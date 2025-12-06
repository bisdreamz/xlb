use aya_ebpf::helpers::bpf_ktime_get_ns;
use xlb_common::config::ebpf::EbpfConfig;
use xlb_common::types::{Flow, FlowDirection, FlowKey, PortMapping};
use crate::handler::iface::Iface;
use crate::net::packet::Packet;

/// True if packet matches configured IP version and protocol
pub fn matches_ipver_and_proto(packet: &Packet, config: &EbpfConfig) -> bool {
    packet.ip_version() == config.ip_ver && packet.proto() == config.proto
}

#[inline(always)]

pub fn get_direction_port_map(config: &'_ EbpfConfig, packet: &Packet)
    -> Option<(FlowDirection, PortMapping)>{
    let src_port = packet.src_port();
    let dst_port = packet.dst_port();

    for i in 0..config.port_mappings.len() {
        let port_map = config.port_mappings[i];
        
        if dst_port == port_map.local_port {
            return Some((FlowDirection::ToServer, port_map));
        }

        if src_port == port_map.remote_port {
            return Some((FlowDirection::ToClient, port_map));
        }
    }

    None
}

pub fn get_flow_key(packet: &Packet, direction: &FlowDirection) -> FlowKey {
    match direction {
        FlowDirection::ToServer => {
            // request coming from client
            // client ip:client ephemeral port
            FlowKey::new(packet.src_ip(), packet.src_port())
        }
        FlowDirection::ToClient => {
            // response from backend
            // backend ip:lb ephemeral port
            FlowKey::new(packet.src_ip(), packet.dst_port())
        }
    }
}

#[inline(always)]
pub fn monotonic_time_ns() -> u64 {
    unsafe { bpf_ktime_get_ns() as u64 }
}


#[inline(always)]
pub fn flow_to_iface(flow: &Flow) -> Iface {
    Iface {
        idx: flow.src_iface_idx,
        mac: flow.dst_mac,
        src_mac: flow.src_mac,
        src_ip: flow.src_ip,
    }
}
