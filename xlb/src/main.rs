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
use std::time::Duration;
#[rustfmt::skip]
use tokio::signal;
use xlb_common::types::{Backend, Flow, FlowKey};

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
    let ebpf_flows: HashMap<_, FlowKey, Flow> = ebpf
        .take_map("FLOW_MAP")
        .ok_or_else(|| anyhow!("Failed to load FLOW_MAP map"))?
        .try_into()?;

    let maint_loop = MaintenanceLoop::new(
        Box::new(provider),
        ebpf_backends,
        ebpf_flows,
        Duration::from_mins(5)
    );

    let loop_handle = maint_loop.start(Duration::from_secs(1));

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");

    ctrl_c.await?;
    println!("Exiting...");

    loop_handle.stop();

    Ok(())
}
