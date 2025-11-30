use crate::listen::ListenIface;
use crate::xlb_config::XlbConfig;
use std::net::IpAddr;
use xlb_common::config::ebpf::EbpfConfig;
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
    for i in 0..cfg.ports.len() {
        port_mappings[i] = cfg.ports[i];
    }

    EbpfConfig {
        mode: cfg.mode,
        ip_addr: ip_bits,
        ip_ver: iface.ver,
        proto: cfg.proto,
        shutdown: false,
        port_mappings,
    }
}
