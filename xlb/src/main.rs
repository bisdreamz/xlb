mod config;
mod ebpf;
mod r#loop;
mod metrics;
mod provider;
mod status;
mod system;

use crate::config::{BackendSource, XlbConfig};
use crate::r#loop::{MaintenanceLoop, MaintenanceMaps};
use crate::provider::{BackendProvider, FixedProvider, KubernetesProvider};
use crate::status::{PortStatus, ProviderKind, StatusMetadata, StatusState, start_admin_server};
use anyhow::{Context, anyhow};
use aya::maps::{Array, HashMap, PerCpuArray};
use log::{info, warn};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::signal::unix::{SignalKind, signal};
use xlb_common::types::{Backend, Flow, FlowKeyV4};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config = XlbConfig::load("xlb.yaml".into())?;
    let iface = system::get_listen_iface(&config.listen)?;
    config.validate_listen_ip(iface.ip)?;
    system::check_ip_forwarding()?;

    info!("Config {:?}", config);

    if !config.admin.address.is_loopback() {
        warn!(
            "Admin API is unauthenticated and configured on non-loopback address {}",
            config.admin.address
        );
    }

    let service_name = config.name.clone().unwrap_or_else(|| "xlb".to_string());

    if let Some(otel_config) = &config.otel
        && otel_config.enabled
    {
        metrics::init(otel_config, service_name.clone())?;
    }

    let (provider, provider_kind): (Arc<dyn BackendProvider>, ProviderKind) = match &config.provider
    {
        BackendSource::Static { backends } => (
            Arc::new(FixedProvider::new(backends.clone())),
            ProviderKind::Static,
        ),
        BackendSource::Kubernetes { namespace, service } => (
            Arc::new(KubernetesProvider::new(namespace.clone(), service.clone())),
            ProviderKind::Kubernetes,
        ),
    };

    provider
        .start()
        .await
        .context("Failed to start backend provider")?;

    let ebpf::LoadedEbpf {
        mut ebpf,
        attachments,
    } = ebpf::load_ebpf_program(&config, &iface).context("Failed to load eBPF program")?;
    let attached_interfaces = attachments
        .iter()
        .map(|attachment| attachment.interface.clone())
        .collect::<Vec<_>>();

    let ebpf_backends: Array<_, Backend> = ebpf
        .take_map("BACKENDS")
        .ok_or_else(|| anyhow!("Failed to load BACKENDS map"))?
        .try_into()?;
    let ebpf_flows: HashMap<_, FlowKeyV4, Flow> = ebpf
        .take_map("FLOW_MAP")
        .ok_or_else(|| anyhow!("Failed to load FLOW_MAP map"))?
        .try_into()?;
    let flow_pair_invariants: PerCpuArray<_, u64> = ebpf
        .take_map("FLOW_PAIR_INVARIANTS")
        .ok_or_else(|| anyhow!("Failed to load FLOW_PAIR_INVARIANTS map"))?
        .try_into()?;

    let status = Arc::new(StatusState::new(StatusMetadata {
        service: service_name.clone(),
        provider: provider_kind,
        listen_address: iface.ip,
        listen_interface: iface.name.clone(),
        xdp_attachments: attachments,
        protocol: config.proto,
        routing_mode: config.mode,
        ports: config
            .ports
            .iter()
            .map(|port| PortStatus {
                listen: port.local_port,
                backend: port.remote_port,
            })
            .collect(),
    }));
    let mut admin_server = start_admin_server(config.admin.socket_addr(), status.clone()).await?;

    let maint_loop = MaintenanceLoop::new(
        provider.clone(),
        MaintenanceMaps {
            backends: ebpf_backends,
            flows: ebpf_flows,
            flow_pair_invariants,
        },
        Duration::from_secs(config.orphan_ttl_secs as u64),
        Duration::from_mins(1),
        attached_interfaces,
        config.resources.network_capacity_mbps,
        status.clone(),
    );

    let mut loop_handle = maint_loop.start(Duration::from_secs(1));
    status.mark_running();
    info!(
        "Started XLB service ({}) on {} ({:?})",
        service_name, iface.name, iface.ip
    );

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    info!("Waiting for shutdown signal...");

    let shutdown_result = tokio::select! {
        _ = sigterm.recv() => {
            info!("Received SIGTERM");
            Ok(())
        }
        _ = sigint.recv() => {
            info!("Received SIGINT");
            Ok(())
        }
        result = admin_server.wait_for_unexpected_exit() => result,
        result = loop_handle.wait_for_unexpected_exit() => result,
    };

    if let Err(error) = &shutdown_result {
        warn!("{error:#}; stopping XLB");
    }

    info!("Beginning graceful shutdown...");
    status.begin_shutdown();
    let shutdown_started = Instant::now();

    let mut shutdown_flag: Array<_, u8> = ebpf
        .map_mut("SHUTDOWN")
        .ok_or_else(|| anyhow!("Failed to load SHUTDOWN map"))?
        .try_into()?;
    shutdown_flag.set(0, 1, 0)?;
    loop_handle.request_stop();

    provider
        .shutdown()
        .await
        .context("Failed to shutdown backend provider")?;
    info!("Backend provider shutdown");

    info!("Waiting for graceful shutdown timeout, will reset any active conns...");
    let shutdown_timeout = Duration::from_secs(config.shutdown_timeout as u64);
    tokio::time::sleep(shutdown_timeout.saturating_sub(shutdown_started.elapsed())).await;

    info!("Graceful shutdown complete");
    let maintenance_result = loop_handle
        .shutdown(Duration::from_secs(1))
        .await
        .context("Failed to stop maintenance loop");
    let admin_result = admin_server
        .shutdown(Duration::from_secs(1))
        .await
        .context("Failed to shutdown admin HTTP server");

    if let Err(error) = &maintenance_result {
        warn!("{error:#}");
    } else {
        info!("Maintenance loop stopped");
    }
    if let Err(error) = &admin_result {
        warn!("{error:#}");
    }

    shutdown_result?;
    maintenance_result?;
    admin_result
}
