use super::existing_flow;
use crate::balancing;
use crate::handler::iface::Iface;
use crate::handler::types::{PacketFlow, TcpOutcome};
use crate::handler::utils;
use crate::net::packet::Packet;
use crate::packet_log_debug;
use aya_ebpf::bindings::BPF_NOEXIST;
use aya_ebpf::helpers::bpf_get_prandom_u32;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, PerCpuArray};
use xlb_common::XlbErr;
use xlb_common::config::ebpf::Strategy;
use xlb_common::types::{Backend, Flow, FlowDirection, FlowKeyV4};

const MAX_PORT_ATTEMPTS: usize = 5;

#[map(name = "FLOW_PAIR_INVARIANTS")]
static FLOW_PAIR_INVARIANTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SynPairAction {
    Reuse,
    DropInitializing,
    Replace { invariant: bool },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExistingSyn {
    Create,
    Reuse,
    Drop,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InstallError {
    ForwardConflict,
    NoEphemeralPorts,
    MapInsertFailed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Removal {
    Removed,
    GoneOrReplaced,
    Failed,
}

/// Reuse an established SYN mapping or install one new directional pair.
///
/// The forward entry is installed with `pair_ready = false`; the reverse entry
/// is then inserted, and only then is the forward entry published as ready.
/// A concurrent identical SYN drops while that short transaction is in flight
/// and relies on normal client retransmission.
pub fn handle_syn(
    packet: &mut Packet,
    backends: &'static Array<Backend>,
    flow_map: &'static HashMap<FlowKeyV4, Flow>,
    strategy: &Strategy,
    port_map_dest: u16,
) -> Result<TcpOutcome, XlbErr> {
    match prepare_existing_syn(packet, flow_map) {
        ExistingSyn::Reuse => {
            return existing_flow(packet, &FlowDirection::ToServer, flow_map);
        }
        ExistingSyn::Drop => return Ok(TcpOutcome::Drop),
        ExistingSyn::Create => {}
    }

    packet_log_debug!(packet, "New TCP SYN");
    let backend = balancing::select_backend(strategy, backends).ok_or(XlbErr::ErrNoBackends)?;

    match install_flow_pair(packet, backend, port_map_dest, flow_map) {
        Ok(flow) => Ok(TcpOutcome::Forward(flow)),
        Err(InstallError::ForwardConflict) => match prepare_existing_syn(packet, flow_map) {
            ExistingSyn::Reuse => existing_flow(packet, &FlowDirection::ToServer, flow_map),
            ExistingSyn::Create | ExistingSyn::Drop => Ok(TcpOutcome::Drop),
        },
        Err(InstallError::NoEphemeralPorts) => {
            packet.rst()?;
            Ok(TcpOutcome::Reply)
        }
        Err(InstallError::MapInsertFailed) => Err(XlbErr::ErrMapInsertFailed),
    }
}

#[inline(always)]
fn prepare_existing_syn(
    packet: &Packet,
    flow_map: &'static HashMap<FlowKeyV4, Flow>,
) -> ExistingSyn {
    let server_key = utils::server_flow_key(
        packet.src_ip() as u32,
        packet.dst_ip() as u32,
        packet.src_port(),
        packet.dst_port(),
    );

    let Some(server_ptr) = flow_map.get_ptr(server_key) else {
        return ExistingSyn::Create;
    };

    let (action, counter_key, pair_tag, counter_is_reciprocal) = {
        let server = unsafe { &*server_ptr };

        // An initializing entry deliberately has no observable counterpart yet.
        if !server.pair_ready
            && !server.pair_invalid
            && server.rst_ns == 0
            && server.fin_both_ns == 0
            && server.direction == FlowDirection::ToServer
        {
            return ExistingSyn::Drop;
        }

        let counter = unsafe { flow_map.get(server.counter_flow_key) };
        (
            syn_pair_action(&server_key, server, counter),
            server.counter_flow_key,
            server.pair_tag,
            counter.is_some_and(|flow| reciprocal_pair(&server_key, server, flow)),
        )
    };

    match action {
        SynPairAction::Reuse => ExistingSyn::Reuse,
        SynPairAction::DropInitializing => ExistingSyn::Drop,
        SynPairAction::Replace { invariant } => {
            if invariant {
                mark_invalid_generation(flow_map, &server_key, pair_tag);
                record_pair_invariant();
            }

            // Remove the forward entry first so another CPU cannot continue to
            // classify the terminal/incomplete recipe as the current pair.
            if remove_generation(flow_map, &server_key, pair_tag) != Removal::Removed {
                return ExistingSyn::Drop;
            }

            if counter_is_reciprocal
                && remove_generation(flow_map, &counter_key, pair_tag) == Removal::Failed
            {
                mark_invalid_generation(flow_map, &counter_key, pair_tag);
                record_pair_invariant();
                return ExistingSyn::Drop;
            }

            ExistingSyn::Create
        }
    }
}

#[inline(always)]
fn syn_pair_action(server_key: &FlowKeyV4, server: &Flow, counter: Option<&Flow>) -> SynPairAction {
    let server_terminal = flow_is_terminal(server);
    let server_invalid = server.pair_invalid || server.direction != FlowDirection::ToServer;

    if !server.pair_ready && !server_invalid && !server_terminal {
        return SynPairAction::DropInitializing;
    }

    let complete = counter.is_some_and(|flow| {
        reciprocal_pair(server_key, server, flow)
            && flow.pair_ready
            && !flow.pair_invalid
            && flow.direction == FlowDirection::ToClient
    });
    let counter_terminal = counter.is_some_and(flow_is_terminal);
    let invariant = server_invalid || !server.pair_ready || !complete;

    if server_terminal || counter_terminal || invariant {
        SynPairAction::Replace { invariant }
    } else {
        SynPairAction::Reuse
    }
}

#[inline(always)]
fn reciprocal_pair(server_key: &FlowKeyV4, server: &Flow, counter: &Flow) -> bool {
    server.counter_flow_key != *server_key
        && counter.counter_flow_key == *server_key
        && counter.pair_tag == server.pair_tag
}

#[inline(always)]
fn flow_is_terminal(flow: &Flow) -> bool {
    flow.rst_ns > 0 || flow.fin_both_ns > 0
}

#[inline(always)]
fn flow_can_publish(flow: &Flow) -> bool {
    !flow.pair_invalid && !flow.fin && flow.rst_ns == 0 && flow.fin_both_ns == 0
}

#[inline(always)]
fn record_pair_invariant() {
    if let Some(count_ptr) = FLOW_PAIR_INVARIANTS.get_ptr_mut(0) {
        let count = unsafe { &mut *count_ptr };
        *count = count.wrapping_add(1);
    }
}

#[inline(always)]
fn mark_invalid_generation(
    flow_map: &'static HashMap<FlowKeyV4, Flow>,
    key: &FlowKeyV4,
    pair_tag: u32,
) {
    if let Some(flow_ptr) = flow_map.get_ptr_mut(key)
        && unsafe { (*flow_ptr).pair_tag } == pair_tag
    {
        unsafe { (*flow_ptr).pair_invalid = true };
    }
}

#[inline(always)]
fn rollback_generation(
    flow_map: &'static HashMap<FlowKeyV4, Flow>,
    key: &FlowKeyV4,
    pair_tag: u32,
) -> bool {
    if remove_generation(flow_map, key, pair_tag) != Removal::Failed {
        return true;
    }

    mark_invalid_generation(flow_map, key, pair_tag);
    record_pair_invariant();
    false
}

#[inline(always)]
fn remove_generation(
    flow_map: &'static HashMap<FlowKeyV4, Flow>,
    key: &FlowKeyV4,
    pair_tag: u32,
) -> Removal {
    let Some(flow_ptr) = flow_map.get_ptr(key) else {
        return Removal::GoneOrReplaced;
    };
    if unsafe { (*flow_ptr).pair_tag } != pair_tag {
        return Removal::GoneOrReplaced;
    }

    if flow_map.remove(key).is_ok() {
        return Removal::Removed;
    }

    match flow_map.get_ptr(key) {
        Some(flow_ptr) if unsafe { (*flow_ptr).pair_tag } == pair_tag => Removal::Failed,
        _ => Removal::GoneOrReplaced,
    }
}

/// Install both directional entries without overwriting a concurrent winner.
fn install_flow_pair(
    packet: &mut Packet,
    backend: &Backend,
    dest_map_port: u16,
    flow_map: &'static HashMap<FlowKeyV4, Flow>,
) -> Result<PacketFlow, InstallError> {
    let egress_iface = Iface {
        idx: backend.src_iface_ifindex,
        mac: backend.next_hop_mac,
        src_mac: backend.src_iface_mac,
        src_ip: backend.src_iface_ip,
    };
    let server_key = utils::server_flow_key(
        packet.src_ip() as u32,
        packet.dst_ip() as u32,
        packet.src_port(),
        packet.dst_port(),
    );
    let now_ns = utils::monotonic_time_ns();

    for _ in 0..MAX_PORT_ATTEMPTS {
        let pair_tag = unsafe { bpf_get_prandom_u32() };
        let ephemeral_port = (pair_tag % 50000) as u16 + 5000;
        let client_key = utils::client_flow_key(
            backend.ip as u32,
            backend.src_iface_ip as u32,
            dest_map_port,
            ephemeral_port,
        );

        if flow_map.get_ptr(client_key).is_some() {
            continue;
        }

        let packet_flow;
        {
            let server_flow = new_flow_to_server(
                packet,
                backend,
                dest_map_port,
                &egress_iface,
                &client_key,
                now_ns,
                pair_tag,
            );
            packet_flow = PacketFlow {
                iface: egress_iface,
                src_mac: server_flow.src_mac,
                dst_mac: server_flow.dst_mac,
                src_ip: server_flow.src_ip,
                dst_ip: server_flow.dst_ip,
                src_port: server_flow.src_port,
                dst_port: server_flow.dst_port,
            };

            if flow_map
                .insert(server_key, server_flow, BPF_NOEXIST as u64)
                .is_err()
            {
                return if flow_map.get_ptr(server_key).is_some() {
                    Err(InstallError::ForwardConflict)
                } else {
                    Err(InstallError::MapInsertFailed)
                };
            }
        }

        let client_flow = new_flow_to_client(
            packet,
            backend,
            server_key,
            packet.dst_ip(),
            now_ns,
            pair_tag,
        );
        if flow_map
            .insert(client_key, client_flow, BPF_NOEXIST as u64)
            .is_err()
        {
            if !rollback_generation(flow_map, &server_key, pair_tag) {
                return Err(InstallError::MapInsertFailed);
            }

            if flow_map.get_ptr(client_key).is_some() {
                continue;
            }
            return Err(InstallError::MapInsertFailed);
        }

        let Some(server_ptr) = flow_map.get_ptr_mut(server_key) else {
            rollback_generation(flow_map, &client_key, pair_tag);
            return Err(InstallError::ForwardConflict);
        };
        if unsafe { (*server_ptr).pair_tag } != pair_tag {
            rollback_generation(flow_map, &client_key, pair_tag);
            return Err(InstallError::ForwardConflict);
        }

        // A concurrent FIN/RST can touch the initializing pair before this
        // publication store. Do not expose any close marker as a healthy pair.
        if !flow_can_publish(unsafe { &*server_ptr }) {
            if unsafe { (*server_ptr).pair_invalid } {
                record_pair_invariant();
            }
            rollback_generation(flow_map, &server_key, pair_tag);
            rollback_generation(flow_map, &client_key, pair_tag);
            return Err(InstallError::ForwardConflict);
        }
        unsafe { (*server_ptr).pair_ready = true };

        return Ok(packet_flow);
    }

    Err(InstallError::NoEphemeralPorts)
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
    Flow {
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
        pair_ready: false,
        pair_tag,
        counter_flow_key: *client_flow_key,
        _reserved: [0; 1],
    }
}

fn new_flow_to_client(
    packet: &mut Packet,
    backend: &Backend,
    counter_flow_key: FlowKeyV4,
    ext_src_ip: u128,
    now_ns: u64,
    pair_tag: u32,
) -> Flow {
    Flow {
        direction: FlowDirection::ToClient,
        client_ip: packet.src_ip(),
        backend_ip: backend.ip,
        src_ip: ext_src_ip,
        src_port: packet.dst_port(),
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
        pair_ready: true,
        pair_tag,
        counter_flow_key,
        _reserved: [0; 1],
    }
}

#[cfg(test)]
mod tests {
    use super::{SynPairAction, flow_can_publish, syn_pair_action};
    use xlb_common::types::{Flow, FlowDirection, FlowKeyV4};

    fn keys() -> (FlowKeyV4, FlowKeyV4) {
        (
            FlowKeyV4::tcp(
                0xc000_0201,
                0xcb00_710a,
                50_000,
                80,
                FlowDirection::ToServer,
            ),
            FlowKeyV4::tcp(
                0xc633_6402,
                0x0a00_0001,
                8080,
                30_000,
                FlowDirection::ToClient,
            ),
        )
    }

    fn flow(direction: FlowDirection, counter_flow_key: FlowKeyV4) -> Flow {
        Flow {
            client_ip: 0,
            backend_ip: 0,
            src_ip: 0,
            dst_ip: 0,
            bytes_transfer: 0,
            packets_transfer: 0,
            created_at_ns: 0,
            last_seen_ns: 0,
            fin_both_ns: 0,
            rst_ns: 0,
            counter_flow_key,
            direction,
            src_port: 0,
            dst_port: 0,
            src_iface_idx: 0,
            dst_mac: [0; 6],
            src_mac: [0; 6],
            fin: false,
            fin_is_src: false,
            rst_is_src: false,
            pair_invalid: false,
            pair_ready: true,
            _reserved: [0; 1],
            pair_tag: 7,
        }
    }

    #[test]
    fn complete_nonterminal_pair_reuses_the_winning_recipe() {
        let (server_key, client_key) = keys();
        let server = flow(FlowDirection::ToServer, client_key);
        let client = flow(FlowDirection::ToClient, server_key);

        assert_eq!(
            syn_pair_action(&server_key, &server, Some(&client)),
            SynPairAction::Reuse
        );
    }

    #[test]
    fn initializing_forward_entry_drops_the_racing_syn() {
        let (server_key, client_key) = keys();
        let mut server = flow(FlowDirection::ToServer, client_key);
        server.pair_ready = false;

        assert_eq!(
            syn_pair_action(&server_key, &server, None),
            SynPairAction::DropInitializing
        );
    }

    #[test]
    fn terminal_pair_is_replaced_even_during_time_wait() {
        let (server_key, client_key) = keys();
        let mut server = flow(FlowDirection::ToServer, client_key);
        let client = flow(FlowDirection::ToClient, server_key);
        server.fin_both_ns = 1;

        assert_eq!(
            syn_pair_action(&server_key, &server, Some(&client)),
            SynPairAction::Replace { invariant: false }
        );
    }

    #[test]
    fn terminal_counterpart_also_replaces_the_pair() {
        let (server_key, client_key) = keys();
        let server = flow(FlowDirection::ToServer, client_key);
        let mut client = flow(FlowDirection::ToClient, server_key);
        client.rst_ns = 1;

        assert_eq!(
            syn_pair_action(&server_key, &server, Some(&client)),
            SynPairAction::Replace { invariant: false }
        );
    }

    #[test]
    fn one_sided_fin_remains_a_retransmittable_nonterminal_pair() {
        let (server_key, client_key) = keys();
        let mut server = flow(FlowDirection::ToServer, client_key);
        let client = flow(FlowDirection::ToClient, server_key);
        server.fin = true;

        assert_eq!(
            syn_pair_action(&server_key, &server, Some(&client)),
            SynPairAction::Reuse
        );
    }

    #[test]
    fn missing_or_mismatched_counterpart_is_repaired_as_an_invariant() {
        let (server_key, client_key) = keys();
        let server = flow(FlowDirection::ToServer, client_key);
        assert_eq!(
            syn_pair_action(&server_key, &server, None),
            SynPairAction::Replace { invariant: true }
        );

        let mut client = flow(FlowDirection::ToClient, server_key);
        client.pair_tag += 1;
        assert_eq!(
            syn_pair_action(&server_key, &server, Some(&client)),
            SynPairAction::Replace { invariant: true }
        );
    }

    #[test]
    fn pair_invalid_marker_forces_repair() {
        let (server_key, client_key) = keys();
        let mut server = flow(FlowDirection::ToServer, client_key);
        let client = flow(FlowDirection::ToClient, server_key);
        server.pair_invalid = true;

        assert_eq!(
            syn_pair_action(&server_key, &server, Some(&client)),
            SynPairAction::Replace { invariant: true }
        );
    }

    #[test]
    fn publication_rejects_every_close_or_invariant_marker() {
        let (_, client_key) = keys();
        let clean = flow(FlowDirection::ToServer, client_key);
        assert!(flow_can_publish(&clean));

        let mut invalid = clean;
        invalid.pair_invalid = true;
        assert!(!flow_can_publish(&invalid));

        let mut fin = clean;
        fin.fin = true;
        assert!(!flow_can_publish(&fin));

        let mut reset = clean;
        reset.rst_ns = 1;
        assert!(!flow_can_publish(&reset));

        let mut fin_both = clean;
        fin_both.fin_both_ns = 1;
        assert!(!flow_can_publish(&fin_both));
    }
}
