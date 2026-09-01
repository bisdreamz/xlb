use crate::config::{XdpAttachMode, XlbConfig};
use crate::status::{XdpAttachment, XdpAttachmentMode};
use crate::system::ListenIface;
use anyhow::{Result, anyhow};
use aya::maps::Array;
use aya::programs::{Xdp, XdpMode};
use aya::{Ebpf, EbpfLoader};
use log::{info, warn};
use std::net::IpAddr;
use xlb_common::config::ebpf::{EbpfConfig, Strategy};
use xlb_common::types::PortMapping;

pub struct LoadedEbpf {
    pub ebpf: Ebpf,
    pub attachments: Vec<XdpAttachment>,
}

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

pub fn load_ebpf_program(config: &XlbConfig, iface: &ListenIface) -> Result<LoadedEbpf> {
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

    // Validate an explicit list up front. Attaching to nothing, or to
    // everything except the interface carrying the VIP, would leave the
    // dataplane silently inert, so both are startup failures.
    if !config.xdp_interfaces.is_empty() {
        for name in &config.xdp_interfaces {
            if !interfaces.iter().any(|i| &i.name == name) {
                return Err(anyhow!(
                    "xdp_interfaces lists {name}, which does not exist on this host"
                ));
            }
        }
        if !config.xdp_interfaces.iter().any(|n| n == &iface.name) {
            return Err(anyhow!(
                "xdp_interfaces must include the listen interface {}",
                iface.name
            ));
        }
    }

    let mut attachments = Vec::new();
    for interface in interfaces {
        // An explicit list replaces the name heuristics entirely.
        if !config.xdp_interfaces.is_empty() {
            if !config.xdp_interfaces.contains(&interface.name) {
                info!(
                    "Skipping interface {} (not listed in xdp_interfaces)",
                    interface.name
                );
                continue;
            }
        } else if skip_prefixes
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

        let attach_result = match config.xdp_attach_mode {
            // Native only, so a missing fast path surfaces instead of being
            // silently downgraded.
            XdpAttachMode::Native => program
                .attach(&interface.name, XdpMode::Driver)
                .map(|link_id| (link_id, XdpAttachmentMode::Native)),
            // Generic only. Lets native and generic be A/B tested on the same
            // build rather than depending on native attach happening to fail.
            XdpAttachMode::Skb => program
                .attach(&interface.name, XdpMode::Skb)
                .map(|link_id| (link_id, XdpAttachmentMode::Generic)),
            // Try native XDP first, then generic SKB mode.
            XdpAttachMode::Auto => program
                .attach(&interface.name, XdpMode::Driver)
                .map(|link_id| (link_id, XdpAttachmentMode::Native))
                .or_else(|driver_error| {
                    warn!(
                        "Native XDP attach failed for {}: {}; retrying in SKB mode",
                        interface.name, driver_error
                    );
                    program
                        .attach(&interface.name, XdpMode::Skb)
                        .map(|link_id| (link_id, XdpAttachmentMode::Generic))
                }),
        };

        match attach_result {
            Ok((_, mode)) => {
                info!(
                    "XDP attached successfully: interface={} mode={:?}",
                    interface.name, mode
                );
                attachments.push(XdpAttachment {
                    interface: interface.name,
                    mode,
                });
            }
            Err(e) => {
                // An explicit `xdp_interfaces` list is a statement that these
                // interfaces matter, so failing to attach to one must surface
                // rather than leave the dataplane silently absent there.
                //
                // Auto-discovery keeps the historical warn-and-continue: it
                // selects interfaces by name heuristic and may well pick one
                // that cannot take XDP at all, which is not a reason to refuse
                // to start.
                if !config.xdp_interfaces.is_empty() {
                    return Err(anyhow!(
                        "XDP attach failed for {}, which is listed in xdp_interfaces (mode {:?}): {}",
                        interface.name,
                        config.xdp_attach_mode,
                        e
                    ));
                }
                warn!(
                    "XDP ATTACH FAILED for {}: {} (continuing)",
                    interface.name, e
                );
            }
        }
    }

    Ok(LoadedEbpf { ebpf, attachments })
}
