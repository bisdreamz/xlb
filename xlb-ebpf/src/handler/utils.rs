use crate::handler::iface::Iface;
use crate::net::packet::Packet;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use xlb_common::config::ebpf::EbpfConfig;
use xlb_common::types::{Flow, FlowDirection, FlowKeyV4, PortMapping};

/// Checks whether a packet is of interest to this XDP instance.
/// We only care about packets that match our IP version, protocol, and port mappings.
/// For incoming traffic (ToServer), we also verify it's actually destined for our configured
/// listen IP - otherwise it's for some other service and we pass it through
pub fn should_process_packet(
    config: &EbpfConfig,
    packet: &Packet,
) -> Option<(FlowDirection, PortMapping)> {
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
fn get_direction_port_map(
    config: &'_ EbpfConfig,
    packet: &Packet,
) -> Option<(FlowDirection, PortMapping)> {
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

/// Build the exact IPv4/TCP flow key from an unmodified packet.
#[inline(always)]
pub fn get_flow_key(packet: &Packet, direction: &FlowDirection) -> FlowKeyV4 {
    FlowKeyV4::tcp(
        packet.src_ip() as u32,
        packet.dst_ip() as u32,
        packet.src_port(),
        packet.dst_port(),
        *direction,
    )
}

#[inline(always)]
pub fn server_flow_key(
    client_ip: u32,
    listen_ip: u32,
    client_port: u16,
    listen_port: u16,
) -> FlowKeyV4 {
    FlowKeyV4::tcp(
        client_ip,
        listen_ip,
        client_port,
        listen_port,
        FlowDirection::ToServer,
    )
}

#[inline(always)]
pub fn client_flow_key(
    backend_ip: u32,
    lb_ip: u32,
    backend_port: u16,
    ephemeral_port: u16,
) -> FlowKeyV4 {
    FlowKeyV4::tcp(
        backend_ip,
        lb_ip,
        backend_port,
        ephemeral_port,
        FlowDirection::ToClient,
    )
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

#[cfg(test)]
mod tests {
    use super::{client_flow_key, server_flow_key};
    use xlb_common::types::{FlowDirection, FlowKeyV4};

    #[test]
    fn directional_key_helpers_match_incoming_wire_tuples() {
        assert_eq!(
            server_flow_key(0xc000_0201, 0xcb00_710a, 50_000, 443),
            FlowKeyV4::tcp(
                0xc000_0201,
                0xcb00_710a,
                50_000,
                443,
                FlowDirection::ToServer,
            )
        );

        assert_eq!(
            client_flow_key(0xc633_6402, 0x0a00_0001, 8443, 30_000),
            FlowKeyV4::tcp(
                0xc633_6402,
                0x0a00_0001,
                8443,
                30_000,
                FlowDirection::ToClient,
            )
        );
    }
}
