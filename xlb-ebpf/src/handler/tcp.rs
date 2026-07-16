use crate::balancing;
use crate::handler::iface::Iface;
use crate::handler::types::{PacketFlow, TcpOutcome};
use crate::handler::utils;
use crate::net::packet::Packet;
use crate::net::types::ProtoHeader;
use crate::{packet_log_debug, packet_log_trace};
use aya_ebpf::helpers::bpf_get_prandom_u32;
use aya_ebpf::maps::{Array, HashMap};
use xlb_common::XlbErr;
use xlb_common::config::ebpf::Strategy;
use xlb_common::types::{Backend, Flow, FlowDirection, FlowKeyV4};

#[derive(Clone, Copy)]
enum CloseKind {
    Fin,
    Reset,
}

/// Process TCP flow state, backend selection, and packet disposition.
///
/// # Arguments
/// - `packet`: Packet being classified or rewritten.
/// - `direction`: Detected [`FlowDirection`] for this packet.
/// - `backends`: Backends available to the selection strategy.
/// - `strategy`: Configured backend selection strategy.
/// - `port_map_dest`: Backend destination port; for example, client-facing
///   port 80 may map to backend port 8080.
pub fn handle_tcp_packet(
    packet: &mut Packet,
    direction: &FlowDirection,
    backends: &'static Array<Backend>,
    flow_map: &'static HashMap<FlowKeyV4, Flow>,
    strategy: &Strategy,
    port_map_dest: u16,
) -> Result<TcpOutcome, XlbErr> {
    let tcp = match packet.proto_hdr() {
        ProtoHeader::Tcp(tcp) => tcp,
        _ => return Err(XlbErr::ErrInvalidOp),
    };

    let (tcp_syn, tcp_fin, tcp_rst) = (tcp.is_syn(), tcp.is_fin(), tcp.is_rst());

    // RST takes precedence over every other control flag. In particular, a
    // malformed SYN|RST must not create a flow, and FIN|RST is an immediate
    // reset rather than an orderly close.
    if tcp_rst {
        close_flow(packet, direction, CloseKind::Reset, flow_map)?;
        return existing_flow(packet, direction, flow_map);
    }

    if tcp_syn && *direction == FlowDirection::ToServer {
        packet_log_debug!(packet, "New TCP SYN");
        let next_backend =
            balancing::select_backend(strategy, backends).ok_or(XlbErr::ErrNoBackends)?;

        return match new_flow(packet, &next_backend, port_map_dest, flow_map) {
            Ok(flow) => Ok(TcpOutcome::Forward(flow)),
            Err(XlbErr::ErrNoEphemeralPorts) => {
                packet.rst()?;
                Ok(TcpOutcome::Reply)
            }
            Err(err) => Err(err),
        };
    }

    if tcp_fin {
        // record flow state but continue to process
        close_flow(packet, direction, CloseKind::Fin, flow_map)?;
    }

    existing_flow(packet, direction, flow_map)
}

fn close_flow(
    packet: &Packet,
    direction: &FlowDirection,
    kind: CloseKind,
    flow_map: &'static HashMap<FlowKeyV4, Flow>,
) -> Result<(), XlbErr> {
    let flow_key = utils::get_flow_key(packet, direction);

    let Some(flow_ptr) = flow_map.get_ptr_mut(&flow_key) else {
        if *direction == FlowDirection::ToServer {
            packet_log_debug!(packet, "Orphaned flow but FIN/RST anyway");
        }

        return Ok(());
    };

    let flow = unsafe { &mut *flow_ptr };
    let now_ns = utils::monotonic_time_ns();

    match kind {
        CloseKind::Fin => {
            packet_log_debug!(packet, "TCP fin initiated");
            flow.fin = true;
        }
        CloseKind::Reset => {
            packet_log_debug!(packet, "TCP rst initiated");
            flow.rst_ns = now_ns;
            flow.rst_is_src = true;
        }
    }

    let Some(counter_flow_ptr) = flow_map.get_ptr_mut(&flow.counter_flow_key) else {
        packet_log_debug!(
            packet,
            "Flow exists but counter-flow missing during RST or FIN!"
        );

        flow.pair_invalid = true;

        // The surviving rewrite recipe is still valid for this packet. Forward
        // it rather than turning a map-pair invariant violation into a drop;
        // userspace cleanup will remove the survivor and record the violation.
        return Ok(());
    };

    let counter_flow = unsafe { &mut *counter_flow_ptr };
    if counter_flow.pair_tag != flow.pair_tag {
        packet_log_debug!(packet, "Flow counterpart generation mismatch during close!");
        flow.pair_invalid = true;
        return Ok(());
    }

    match kind {
        CloseKind::Fin if counter_flow.fin => {
            flow.fin_both_ns = now_ns;
            counter_flow.fin_both_ns = now_ns;
            counter_flow.fin_is_src = true;
        }
        CloseKind::Reset => {
            counter_flow.rst_ns = now_ns;
            counter_flow.rst_is_src = false;
        }
        CloseKind::Fin => {}
    }

    Ok(())
}

/// Update and route a packet belonging to an existing flow.
///
/// A missing client-facing flow is passed to the local stack; a missing
/// server-facing flow is reported as an expired/orphaned connection.
fn existing_flow(
    packet: &mut Packet,
    direction: &FlowDirection,
    flow_map: &'static HashMap<FlowKeyV4, Flow>,
) -> Result<TcpOutcome, XlbErr> {
    let flow_key = utils::get_flow_key(packet, direction);

    packet_log_trace!(packet, "Look4flow");

    let flow_ptr = match flow_map.get_ptr_mut(&flow_key) {
        Some(ptr) => ptr,
        None => {
            if *direction == FlowDirection::ToClient {
                return Ok(TcpOutcome::Pass);
            }
            return Err(XlbErr::ErrOrphanedFlow);
        }
    };
    let flow = unsafe { &mut *flow_ptr };

    packet_log_trace!(packet, "Recognized flow");

    flow.bytes_transfer += packet.size();
    flow.packets_transfer += 1;
    flow.last_seen_ns = utils::monotonic_time_ns();

    Ok(TcpOutcome::Forward(PacketFlow {
        iface: utils::flow_to_iface(flow),
        src_mac: flow.src_mac,
        dst_mac: flow.dst_mac,
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.src_port,
        dst_port: flow.dst_port,
    }))
}

/// Try up to five random translation ports for the backend.
///
/// The returned [`FlowKeyV4`] is the exact tuple expected on the
/// [`FlowDirection::ToClient`] response path.
#[inline(always)]
fn find_ephemeral_port(
    backend: &Backend,
    backend_port: u16,
    flow_map: &'static HashMap<FlowKeyV4, Flow>,
) -> Result<(FlowKeyV4, u32), XlbErr> {
    for _ in 0..5 {
        let pair_tag = unsafe { bpf_get_prandom_u32() };
        let ephemeral_port = (pair_tag % 50000) as u16 + 5000;
        let client_flow_key = utils::client_flow_key(
            backend.ip as u32,
            backend.src_iface_ip as u32,
            backend_port,
            ephemeral_port,
        );

        if unsafe { flow_map.get(&client_flow_key).is_none() } {
            return Ok((client_flow_key, pair_tag));
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
    flow_map: &'static HashMap<FlowKeyV4, Flow>,
) -> Result<PacketFlow, XlbErr> {
    let egress_iface = Iface {
        idx: backend.src_iface_ifindex,
        mac: backend.next_hop_mac,
        src_mac: backend.src_iface_mac,
        src_ip: backend.src_iface_ip,
    };

    let now_ns = utils::monotonic_time_ns();
    let packet_flow;
    let server_key;
    let client_key;
    let pair_tag;

    {
        (client_key, pair_tag) = find_ephemeral_port(backend, dest_map_port, flow_map)?;

        let server_flow = new_flow_to_server(
            packet,
            backend,
            dest_map_port,
            &egress_iface,
            &client_key,
            now_ns,
            pair_tag,
        );
        server_key = utils::server_flow_key(
            packet.src_ip() as u32,
            packet.dst_ip() as u32,
            packet.src_port(),
            packet.dst_port(),
        );

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
            .insert(&server_key, &server_flow, 0)
            .map_err(|_| XlbErr::ErrMapInsertFailed)?;
    }

    let client_flow = new_flow_to_client(
        packet,
        backend,
        server_key,
        packet.dst_ip(),
        now_ns,
        pair_tag,
    )?;

    flow_map
        .insert(&client_key, &client_flow, 0)
        .map_err(|_| XlbErr::ErrMapInsertFailed)?;

    Ok(packet_flow)
}

fn new_flow_to_server(
    packet: &mut Packet,
    backend: &Backend,
    dest_map_port: u16,
    egress_iface: &Iface,
    client_flow_key: &FlowKeyV4,
    now_ns: u64,
    pair_tag: u32,
) -> Flow {
    let to_server = Flow {
        direction: FlowDirection::ToServer,
        client_ip: packet.src_ip(),
        backend_ip: backend.ip,
        src_ip: egress_iface.src_ip,
        src_port: client_flow_key.dst_port(),
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
        pair_invalid: false,
        pair_tag,
        counter_flow_key: *client_flow_key,
        _reserved: [0; 2],
    };

    to_server
}

fn new_flow_to_client(
    packet: &mut Packet,
    backend: &Backend,
    counter_flow_key: FlowKeyV4,
    ext_src_ip: u128,
    now_ns: u64,
    pair_tag: u32,
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
        pair_invalid: false,
        pair_tag,
        counter_flow_key,
        _reserved: [0; 2],
    })
}
