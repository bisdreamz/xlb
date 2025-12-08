mod config;
mod ebpf;
mod r#loop;
mod provider;
mod system;

use crate::config::{BackendSource, XlbConfig};
use crate::provider::{BackendProvider, FixedProvider};
use crate::r#loop::MaintenanceLoop;
use anyhow::{anyhow, Context};
use aya::maps::{Array, HashMap};
use log::info;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use xlb_common::types::{Backend, Flow};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    system::check_ip_forwarding()?;

    let config = XlbConfig::load("xlb.yaml".into())?;
    let iface = system::get_listen_iface(&config.listen)?;

    info!("Config {:?}", config);

    let provider = match &config.provider {
        BackendSource::Static { backends } => FixedProvider::new(backends.clone()),
        _ => panic!("Backend source not impl yet"),
    };

    provider
        .start()
        .await
        .context("Failed to start backend provider")?;

    let mut ebpf = ebpf::load_ebpf_program(&config, &iface).context("Failed to load eBPF program")?;

    info!(
        "Started XLB service ({}) on {} ({:?})",
        config.name.as_ref().unwrap_or(&"xlb".into()),
        iface.name,
        iface.ip
    );

    let ebpf_backends: Array<_, Backend> = ebpf
        .take_map("BACKENDS")
        .ok_or_else(|| anyhow!("Failed to load BACKENDS map"))?
        .try_into()?;
    let ebpf_flows: HashMap<_, u64, Flow> = ebpf
        .take_map("FLOW_MAP")
        .ok_or_else(|| anyhow!("Failed to load FLOW_MAP map"))?
        .try_into()?;

    let arc_provider = Arc::new(provider);
    let maint_loop = MaintenanceLoop::new(
        arc_provider.clone(),
        ebpf_backends,
        ebpf_flows,
        Duration::from_secs(config.orphan_ttl_secs as u64)
    );

    let loop_handle = maint_loop.start(Duration::from_secs(1));

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    info!("Waiting for shutdown signal...");

    tokio::select! {
        _ = sigterm.recv() => info!("Received SIGTERM"),
        _ = sigint.recv() => info!("Received SIGINT"),
    }

    info!("Beginning graceful shutdown...");

    loop_handle.stop();
    info!("Maintenance loop stopped");
    arc_provider.shutdown().await
        .context("Failed to shutdown backend provider")?;
    info!("Backend provider shutdown");

    info!("Waiting for graceful shutdown timeout to rst conns...");
    tokio::time::sleep(Duration::from_secs(config.shutdown_timeout as u64)).await;

    info!("Graceful shutdown complete");

    Ok(())
}
