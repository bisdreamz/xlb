use crate::balancing;
use crate::handler::iface::Iface;
use crate::handler::types::PacketFlow;
use crate::handler::utils;
use crate::net::packet::Packet;
use crate::net::types::ProtoHeader;
use aya_ebpf::helpers::bpf_get_prandom_u32;
use aya_ebpf::maps::{Array, HashMap};
use aya_log_ebpf::{debug, info};
use xlb_common::config::ebpf::Strategy;
use xlb_common::types::FlowDirection::ToServer;
use xlb_common::types::{Backend, Flow, FlowDirection, FlowKey};
use xlb_common::XlbErr;

/// Process load balancing of a TCP packet, which
/// handles all required rewriting and backend
/// selection
///
/// # Arguments
/// * 'packet' - The mutable packet which will
/// be re-written and ready for XDP_TRANSFER
/// * 'direction' - The detected ['FlowDirection'] of
/// this packet.
/// * 'backends' - The currently available ['Backend']
/// options for the backend selection strategy to
/// choose from
/// * 'strategy' - The ['Strategy'] configured for
/// backend selection.
/// * 'dest_map_port' - The re-mapped service
/// port when forwarding to the backend,
/// e.g. lb service port may be 80 to the client but
/// dest map port is 8080 on the backend.
pub fn handle_tcp_packet(packet: &mut Packet,
                         direction: &FlowDirection,
                         backends: &'static Array<Backend>,
                         flow_map: &'static HashMap<u64, Flow>,
                         strategy: &Strategy,
                         port_map_dest: u16) -> Result<PacketFlow, XlbErr> {
    let tcp = match packet.proto_hdr() {
        ProtoHeader::Tcp(tcp) => tcp,
        _ => unsafe { core::hint::unreachable_unchecked() },
    };

    if tcp.is_syn() && *direction == FlowDirection::ToServer {
        info!(packet.xdp_context(), "New TCP SYN");
        let next_backend = balancing::select_backend(strategy, backends)
            .ok_or(XlbErr::ErrNoBackends)?;

        return new_flow(packet, &next_backend, port_map_dest, flow_map);
    }

    existing_flow(packet, direction, flow_map)
}

/// Handles routing of an (expectedly) existing flow as fined
/// by a packet which matches interest criteria and is
/// does not have the syn flag set, thus should be part
/// of an active load balancing connection
fn existing_flow(packet: &mut Packet, direction: &FlowDirection,
                 flow_map: &'static HashMap<u64, Flow>) -> Result<PacketFlow, XlbErr> {
    let flow_key = utils::get_flow_key(packet, direction);
    let key_hash = flow_key.hash_key();

    debug!(packet.xdp_context(), "Look4flow key {:i}:{}", flow_key.ip as u32, flow_key.port);

    let flow_ptr = flow_map.get_ptr_mut(&key_hash).ok_or(XlbErr::ErrOrphanedFlow)?;
    let flow = unsafe { &mut *flow_ptr };

    debug!(packet.xdp_context(), "Recognized flow {:i}:{}", flow_key.ip as u32, flow_key.port);

    flow.bytes_transfer += packet.size();
    flow.packets_transfer += 1;
    flow.last_seen_ns = utils::monotonic_time_ns();

    Ok(PacketFlow {
        iface: utils::flow_to_iface(flow),
        src_mac: flow.src_mac,
        dst_mac: flow.dst_mac,
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.src_port,
        dst_port: flow.dst_port,
    })
}

/// Flow path for when a new connection arrives (syn)
/// Creates flow entries using pre-computed routing information from the backend
fn new_flow(packet: &mut Packet, backend: &Backend, dest_map_port: u16,
            flow_map: &'static HashMap<u64, Flow>) -> Result<PacketFlow, XlbErr> {
    let egress_iface = Iface {
        idx: backend.src_iface_ifindex,
        mac: backend.next_hop_mac,
        src_mac: backend.src_iface_mac,
        src_ip: backend.src_iface_ip,
    };

    let now_ns = utils::monotonic_time_ns();
    let packet_flow;
    {
        let server_flow = new_flow_to_server(packet, backend,
                                             dest_map_port, &egress_iface, now_ns);

        // extract and keep server and client flow off diff stack frames
        packet_flow = PacketFlow {
            iface: egress_iface,
            src_mac: server_flow.src_mac,
            dst_mac: server_flow.dst_mac,
            src_ip: server_flow.src_ip,
            dst_ip: server_flow.dst_ip,
            src_port: server_flow.src_port,
            dst_port: server_flow.dst_port,
        };

        // Insert server_flow into map (moves/drops from stack)
        let server_key = utils::get_flow_key(packet, &ToServer);
        let server_hash = server_key.hash_key();
        flow_map.insert(&server_hash, &server_flow, 0)
            .map_err(|_| XlbErr::ErrMapInsertFailed)?;
    }

    let client_flow = new_flow_to_client(packet, backend, packet.dst_ip(), now_ns)?;
    let client_key = FlowKey::new(backend.ip, packet_flow.src_port);
    let client_hash = client_key.hash_key();

    debug!(packet.xdp_context(), "Insert client {:i}:{}", client_key.ip as u32, client_key.port);

    flow_map.insert(&client_hash, &client_flow, 0)
        .map_err(|_| XlbErr::ErrMapInsertFailed)?;

    Ok(packet_flow)
}

fn new_flow_to_server(packet: &mut Packet, backend: &Backend,
                      dest_map_port:  u16,
                      egress_iface: &Iface,
                now_ns: u64) -> Flow {
    let src_port = (unsafe { bpf_get_prandom_u32() } % 10000) as u16 + 5000;
    // TODO ephemeral port generation and management code

    let to_server = Flow {
        direction: FlowDirection::ToServer,
        client_ip: packet.src_ip(),
        backend_ip: backend.ip,
        src_ip: egress_iface.src_ip,
        src_port,
        dst_port: dest_map_port,
        dst_ip: backend.ip,
        dst_mac: egress_iface.mac,
        src_iface_idx: egress_iface.idx,
        src_mac: egress_iface.src_mac,
        bytes_transfer: packet.size(),
        packets_transfer: 1,
        created_at_ns: now_ns,
        last_seen_ns: now_ns,
        closed_at_ns: 0,
    };

    to_server
}

fn new_flow_to_client(packet: &mut Packet, backend: &Backend,
                      ext_src_ip: u128, now_ns: u64) -> Result<Flow, XlbErr> {
    Ok(Flow {
        direction: FlowDirection::ToClient,
        client_ip: packet.src_ip(),
        backend_ip: backend.ip,
        src_ip: ext_src_ip,
        // tcp resp has original src port s dst port
        src_port: packet.dst_port(),
        // and dst port as clients ephemeral port
        dst_port: packet.src_port(),
        dst_ip: packet.src_ip(),
        dst_mac: packet.eth_hdr().src_mac().as_bytes(),
        src_iface_idx: packet.xdp_context().ingress_ifindex() as u16,
        src_mac: packet.eth_hdr().dst_mac().as_bytes(),
        bytes_transfer: packet.size(),
        packets_transfer: 1,
        created_at_ns: now_ns,
        last_seen_ns: now_ns,
        closed_at_ns: 0,
    })
}
