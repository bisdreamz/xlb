mod ebpf;
mod listen;
mod xlb_config;

use crate::xlb_config::XlbConfig;
use anyhow::Context as _;
use aya::EbpfLoader;
use aya::programs::{Xdp, XdpFlags};
use log::info;
#[rustfmt::skip]
use log::warn;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config = XlbConfig::load("xlb.yaml".into())?;
    let iface = listen::get_listen_iface(&config.listen)?;

    info!(
        "Starting XLB service ({}) on {} ({:?})",
        config.name.as_ref().unwrap_or(&"xlb".into()),
        iface.name,
        iface.ip
    );

    let ebpf_config = ebpf::to_ebpf_config(&config, &iface);

    let mut ebpf = EbpfLoader::new()
        .override_global("CONFIG", &ebpf_config, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/xlb"
        )))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let program: &mut Xdp = ebpf.program_mut("xlb").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface.name, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
