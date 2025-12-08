use crate::handler::iface::Iface;
use crate::net::packet::Packet;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use xlb_common::config::ebpf::EbpfConfig;
use xlb_common::types::{Flow, FlowDirection, FlowKey, PortMapping};

/// Checks whether a packet is of interest to this XDP instance.
/// We only care about packets that match our IP version, protocol, and port mappings.
/// For incoming traffic (ToServer), we also verify it's actually destined for our configured
/// listen IP - otherwise it's for some other service and we pass it through
pub fn should_process_packet(config: &EbpfConfig, packet: &Packet)
    -> Option<(FlowDirection, PortMapping)> {

    if packet.ip_version() != config.ip_ver || packet.proto() != config.proto {
        return None;
    }

    let (direction, port_map) = get_direction_port_map(config, packet)?;

    if direction == FlowDirection::ToServer && packet.dst_ip() != config.ip_addr {
        return None;
    }

    Some((direction, port_map))
}

#[inline(always)]
fn get_direction_port_map(config: &'_ EbpfConfig, packet: &Packet)
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

/// Builds the unique ['FlowKey'] from a packet for the
/// provided flow direction. This expects the packet
/// is in its original state without any rewriting.
///
/// # Keys
/// ToServer = source_ip:src_port (client ip:client ephemeral port)
/// ToClient = source_ip:dst_port (backend_ip:lb ephemeral port)
#[inline(always)]
pub fn get_flow_key(packet: &Packet, direction: &FlowDirection) -> FlowKey {
    match direction {
        FlowDirection::ToServer => {
            // request coming from client
            // client ip:client ephemeral port
            server_flow_key(packet.src_ip(), packet.src_port())
        }
        FlowDirection::ToClient => {
            // response from backend
            // backend ip:lb ephemeral port
            client_flow_key(packet.src_ip(), packet.dst_port())
        }
    }
}

#[inline(always)]
pub fn server_flow_key(client_ip: u128, packet_src_port: u16) -> FlowKey {
    FlowKey::new(client_ip, packet_src_port)
}

#[inline(always)]
pub fn client_flow_key(backend_ip: u128, ephemeral_port: u16) -> FlowKey {
    FlowKey::new(backend_ip, ephemeral_port)
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
