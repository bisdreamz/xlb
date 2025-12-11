use crate::balancing;
use crate::handler::iface::Iface;
use crate::handler::types::PacketFlow;
use crate::handler::utils;
use crate::net::packet::Packet;
use crate::net::types::ProtoHeader;
use crate::{packet_log_debug, packet_log_trace, packet_log_warn};
use aya_ebpf::helpers::bpf_get_prandom_u32;
use aya_ebpf::maps::{Array, HashMap};
use xlb_common::XlbErr;
use xlb_common::config::ebpf::Strategy;
use xlb_common::types::{Backend, Flow, FlowDirection, FlowKey};

/// Process load balancing of a TCP packet, which
/// handles required rewriting and backend selection
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
pub fn handle_tcp_packet(
    packet: &mut Packet,
    direction: &FlowDirection,
    backends: &'static Array<Backend>,
    flow_map: &'static HashMap<u64, Flow>,
    strategy: &Strategy,
    port_map_dest: u16,
) -> Result<Option<PacketFlow>, XlbErr> {
    let tcp = match packet.proto_hdr() {
        ProtoHeader::Tcp(tcp) => tcp,
        _ => unsafe { core::hint::unreachable_unchecked() },
    };

    if tcp.is_syn() && *direction == FlowDirection::ToServer {
        packet_log_debug!(packet, "New TCP SYN");
        let next_backend =
            balancing::select_backend(strategy, backends).ok_or(XlbErr::ErrNoBackends)?;

        return match new_flow(packet, &next_backend, port_map_dest, flow_map) {
            Ok(flow) => Ok(Some(flow)),
            Err(XlbErr::ErrNoEphemeralPorts) => match packet.rst() {
                Ok(_) => Ok(None),
                Err(err) => Err(err),
            },
            Err(err) => return Err(err),
        };
    }

    let (tcp_fin, tcp_rst) = (tcp.is_fin(), tcp.is_rst());
    if tcp_fin || tcp_rst {
        // record flow state but continue to process
        close_flow(packet, direction, tcp_fin, tcp_rst, flow_map)?;
    }

    existing_flow(packet, direction, flow_map)
}

fn close_flow(
    packet: &Packet,
    direction: &FlowDirection,
    fin: bool,
    rst: bool,
    flow_map: &'static HashMap<u64, Flow>,
) -> Result<(), XlbErr> {
    let flow_key = utils::get_flow_key(packet, direction);
    let key_hash = flow_key.hash_key();

    let Some(flow_ptr) = flow_map.get_ptr_mut(&key_hash) else {
        if *direction == FlowDirection::ToServer {
            packet_log_debug!(packet, "Orphaned flow but FIN/RST anyway");
        }

        return Ok(());
    };

    let flow = unsafe { &mut *flow_ptr };
    let now_ns = utils::monotonic_time_ns();

    if fin {
        packet_log_debug!(packet, "TCP fin initiated");
        flow.fin = true;
    } else if rst {
        packet_log_debug!(packet, "TCP rst initiated");
        flow.rst_ns = now_ns;
        flow.rst_is_src = true;
    }

    let Some(counter_flow_ptr) = flow_map.get_ptr_mut(&flow.counter_flow_key_hash) else {
        packet_log_warn!(
            packet,
            "Flow exists but counter-flow missing during RST or FIN!"
        );

        // should send a RST but flow is already marked as an RST
        // or is FIN will be cleaned up later as an orphan
        return Err(XlbErr::ErrOrphanedFlow);
    };

    let counter_flow = unsafe { &mut *counter_flow_ptr };

    if fin && counter_flow.fin {
        flow.fin_both_ns = now_ns;
        counter_flow.fin_both_ns = now_ns;
        counter_flow.fin_is_src = true;
    } else if rst {
        counter_flow.rst_ns = now_ns;
        counter_flow.rst_is_src = false;
    }

    Ok(())
}

/// Handles routing of an (expectedly) existing flow as fined
/// by a packet which matches interest criteria and is
/// does not have the syn flag set, thus should be part
/// of an active load balancing connection
fn existing_flow(
    packet: &mut Packet,
    direction: &FlowDirection,
    flow_map: &'static HashMap<u64, Flow>,
) -> Result<Option<PacketFlow>, XlbErr> {
    let flow_key = utils::get_flow_key(packet, direction);
    let key_hash = flow_key.hash_key();

    packet_log_trace!(packet, "Look4flow");

    let flow_ptr = match flow_map.get_ptr_mut(&key_hash) {
        Some(ptr) => ptr,
        None => {
            if *direction == FlowDirection::ToClient {
                return Ok(None);
            }
            return Err(XlbErr::ErrOrphanedFlow);
        }
    };
    let flow = unsafe { &mut *flow_ptr };

    packet_log_trace!(packet, "Recognized flow");

    flow.bytes_transfer += packet.size();
    flow.packets_transfer += 1;
    flow.last_seen_ns = utils::monotonic_time_ns();

    Ok(Some(PacketFlow {
        iface: utils::flow_to_iface(flow),
        src_mac: flow.src_mac,
        dst_mac: flow.dst_mac,
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.src_port,
        dst_port: flow.dst_port,
    }))
}

/// Makes 5 attempts to locate a free ephemeral
/// port between us and the associated backend
/// Returns a ['FlowKey'] representing the
/// ['ToClient'] flow and ephemeral port allocated
#[inline(always)]
fn find_ephemeral_port(
    backend: &Backend,
    flow_map: &'static HashMap<u64, Flow>,
) -> Result<FlowKey, XlbErr> {
    for _ in 0..5 {
        let src_port = (unsafe { bpf_get_prandom_u32() } % 50000) as u16 + 5000;
        let client_flow_key = utils::client_flow_key(backend.ip, src_port);
        let client_key_hash = client_flow_key.hash_key();

        if unsafe { flow_map.get(&client_key_hash).is_none() } {
            return Ok(client_flow_key);
        }
    }

    Err(XlbErr::ErrNoEphemeralPorts)
}

/// Flow path for when a new connection arrives (syn)
/// Creates flow entries using pre-computed routing information from the backend
fn new_flow(
    packet: &mut Packet,
    backend: &Backend,
    dest_map_port: u16,
    flow_map: &'static HashMap<u64, Flow>,
) -> Result<PacketFlow, XlbErr> {
    let egress_iface = Iface {
        idx: backend.src_iface_ifindex,
        mac: backend.next_hop_mac,
        src_mac: backend.src_iface_mac,
        src_ip: backend.src_iface_ip,
    };

    let now_ns = utils::monotonic_time_ns();
    let packet_flow;
    let server_key_hash;
    let client_key_hash;

    {
        let client_key = find_ephemeral_port(backend, flow_map)?;
        client_key_hash = client_key.hash_key();

        let server_flow = new_flow_to_server(
            packet,
            backend,
            dest_map_port,
            &egress_iface,
            &client_key,
            now_ns,
        );
        server_key_hash = utils::server_flow_key(packet.src_ip(), packet.src_port()).hash_key();

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

        packet_log_debug!(packet, "Insert client flow");

        flow_map
            .insert(&server_key_hash, &server_flow, 0)
            .map_err(|_| XlbErr::ErrMapInsertFailed)?;
    }

    let client_flow =
        new_flow_to_client(packet, backend, server_key_hash, packet.dst_ip(), now_ns)?;

    flow_map
        .insert(&client_key_hash, &client_flow, 0)
        .map_err(|_| XlbErr::ErrMapInsertFailed)?;

    Ok(packet_flow)
}

fn new_flow_to_server(
    packet: &mut Packet,
    backend: &Backend,
    dest_map_port: u16,
    egress_iface: &Iface,
    client_flow_key: &FlowKey,
    now_ns: u64,
) -> Flow {
    let to_server = Flow {
        direction: FlowDirection::ToServer,
        client_ip: packet.src_ip(),
        backend_ip: backend.ip,
        src_ip: egress_iface.src_ip,
        src_port: client_flow_key.port,
        dst_port: dest_map_port,
        dst_ip: backend.ip,
        dst_mac: egress_iface.mac,
        src_iface_idx: egress_iface.idx,
        src_mac: egress_iface.src_mac,
        bytes_transfer: packet.size(),
        packets_transfer: 1,
        created_at_ns: now_ns,
        last_seen_ns: now_ns,
        fin: false,
        fin_is_src: false,
        fin_both_ns: 0,
        rst_ns: 0,
        rst_is_src: false,
        counter_flow_key_hash: client_flow_key.hash_key(),
    };

    to_server
}

fn new_flow_to_client(
    packet: &mut Packet,
    backend: &Backend,
    counter_flow_key_hash: u64,
    ext_src_ip: u128,
    now_ns: u64,
) -> Result<Flow, XlbErr> {
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
        fin: false,
        fin_both_ns: 0,
        fin_is_src: false,
        rst_ns: 0,
        rst_is_src: false,
        counter_flow_key_hash,
    })
}
