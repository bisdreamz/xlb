use crate::handler::types::{PacketFlow, TcpOutcome};
use crate::handler::utils;
use crate::net::packet::Packet;
use crate::net::types::ProtoHeader;
use crate::{packet_log_debug, packet_log_trace};
use aya_ebpf::maps::{Array, HashMap};
use xlb_common::XlbErr;
use xlb_common::config::ebpf::Strategy;
use xlb_common::types::{Backend, Flow, FlowDirection, FlowKeyV4};

mod syn;

#[derive(Clone, Copy)]
enum CloseKind {
    Fin,
    Reset,
}

#[inline(always)]
const fn is_new_client_syn(syn: bool, ack: bool, direction: FlowDirection) -> bool {
    syn && !ack && matches!(direction, FlowDirection::ToServer)
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

    let (tcp_syn, tcp_ack, tcp_fin, tcp_rst) =
        (tcp.is_syn(), tcp.is_ack(), tcp.is_fin(), tcp.is_rst());

    // RST takes precedence over every other control flag. In particular, a
    // malformed SYN|RST must not create a flow, and FIN|RST is an immediate
    // reset rather than an orderly close.
    if tcp_rst {
        close_flow(packet, direction, CloseKind::Reset, flow_map)?;
        return existing_flow(packet, direction, flow_map);
    }

    if is_new_client_syn(tcp_syn, tcp_ack, *direction) {
        return syn::handle_syn(packet, backends, flow_map, strategy, port_map_dest);
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

    // A FIN/RST racing pair installation must abort that transaction rather
    // than publish a partially closed flow as a reusable connection.
    if !flow.pair_ready || !counter_flow.pair_ready {
        flow.pair_invalid = true;
        counter_flow.pair_invalid = true;
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
pub(super) fn existing_flow(
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

#[cfg(test)]
mod tests {
    use super::is_new_client_syn;
    use xlb_common::types::FlowDirection;

    #[test]
    fn only_unacknowledged_client_syn_starts_a_flow() {
        assert!(is_new_client_syn(true, false, FlowDirection::ToServer));
        assert!(!is_new_client_syn(true, true, FlowDirection::ToServer));
        assert!(!is_new_client_syn(true, false, FlowDirection::ToClient));
        assert!(!is_new_client_syn(false, false, FlowDirection::ToServer));
    }
}
