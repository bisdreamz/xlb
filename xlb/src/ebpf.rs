use crate::config::XlbConfig;
use crate::system::ListenIface;
use anyhow::{Result, anyhow};
use aya::maps::Array;
use aya::programs::{Xdp, XdpMode};
use aya::{Ebpf, EbpfLoader};
use log::{info, warn};
use std::net::IpAddr;
use xlb_common::config::ebpf::{EbpfConfig, Strategy};
use xlb_common::types::PortMapping;

pub fn to_ebpf_config(cfg: &XlbConfig, iface: &ListenIface) -> EbpfConfig {
    let ip_bits = match iface.ip {
        IpAddr::V4(ip) => ip.to_bits() as u128,
        IpAddr::V6(ip) => ip.to_bits(),
    };

    let mut port_mappings = [PortMapping {
        local_port: 0,
        remote_port: 0,
    }; 8];
    port_mappings[..cfg.ports.len()].copy_from_slice(&cfg.ports);

    EbpfConfig {
        strategy: Strategy::RoundRobin,
        mode: cfg.mode,
        ip_addr: ip_bits,
        ip_ver: iface.ver,
        proto: cfg.proto,
        shutdown: false,
        port_mappings,
    }
}

pub fn load_ebpf_program(config: &XlbConfig, iface: &ListenIface) -> Result<Ebpf> {
    let ebpf_config = to_ebpf_config(config, iface);

    let mut ebpf = EbpfLoader::new().load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xlb-bpf"
    )))?;

    {
        let mut config_map: Array<_, EbpfConfig> = ebpf
            .map_mut("CONFIG")
            .ok_or_else(|| anyhow!("Failed to load CONFIG map"))?
            .try_into()?;
        config_map.set(0, ebpf_config, 0)?;
    }

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

    // Attach XDP to all interfaces (except loopback and bridges)
    // Skip bridges because we can't attach to both a bridge and its veth members
    // We want the veth pairs to catch return traffic from containers
    let interfaces = default_net::get_interfaces();
    let skip_prefixes = ["lo", "cilium", "lxc", "anchor", "cpbridge"];
    let skip_bridges = ["docker0", "virbr"];

    for interface in interfaces {
        // Skip loopback and bridge interfaces
        if skip_prefixes
            .iter()
            .any(|prefix| interface.name.starts_with(prefix))
            || skip_bridges
                .iter()
                .any(|prefix| interface.name.starts_with(prefix))
        {
            info!(
                "Skipping interface {} (loopback, bridge, or veth)",
                interface.name
            );
            continue;
        }

        // Try native XDP first, then generic SKB mode.
        let attach_result =
            program
                .attach(&interface.name, XdpMode::Driver)
                .or_else(|driver_error| {
                    warn!(
                        "Native XDP attach failed for {}: {}; retrying in SKB mode",
                        interface.name, driver_error
                    );
                    program.attach(&interface.name, XdpMode::Skb)
                });

        match attach_result {
            Ok(_) => {
                info!("XDP ATTACHED successfully to interface: {}", interface.name);
            }
            Err(e) => {
                warn!(
                    "XDP ATTACH FAILED for {}: {} (continuing)",
                    interface.name, e
                );
            }
        }
    }

    Ok(ebpf)
}
