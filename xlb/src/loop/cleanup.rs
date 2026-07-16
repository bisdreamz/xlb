use super::utils;
use aya::maps::{HashMap, MapData, MapError};
use log::trace;
use std::collections::HashSet;
use std::time::Duration;
use xlb_common::types::{Flow, FlowKeyV4};

// Declaration order defines which reason wins when the two halves qualify for
// different reasons: Reset > Fin > Invalid > Orphan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CleanupReason {
    Orphan,
    Invalid,
    Fin,
    Reset,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct CleanupSummary {
    connections: u64,
    fins: u64,
    resets: u64,
    pub(super) orphans: u64,
    pub(super) invariant_violations: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CleanupPlan {
    key: FlowKeyV4,
    counter_key: Option<FlowKeyV4>,
    pair_tag: u32,
    reason: CleanupReason,
    invariant_violation: bool,
}

fn cleanup_reason(
    flow: &Flow,
    now_ns: u64,
    last_run_ns: u64,
    orphan_ttl: &Duration,
    tcp_time_wait_ttl: &Duration,
) -> Option<CleanupReason> {
    if utils::rst_ready_for_cleanup(flow.rst_ns, last_run_ns) {
        Some(CleanupReason::Reset)
    } else if utils::fin_ready_for_cleanup(flow.fin_both_ns, now_ns, tcp_time_wait_ttl) {
        Some(CleanupReason::Fin)
    } else if utils::is_orphan(flow.last_seen_ns, now_ns, orphan_ttl) {
        Some(CleanupReason::Orphan)
    } else {
        None
    }
}

fn terminal_marker_reason(flow: &Flow) -> Option<CleanupReason> {
    if flow.rst_ns > 0 {
        Some(CleanupReason::Reset)
    } else if flow.fin || flow.fin_both_ns > 0 {
        Some(CleanupReason::Fin)
    } else {
        None
    }
}

fn plan_pair_cleanup(
    key: FlowKeyV4,
    flow: &Flow,
    counter_flow: Option<&Flow>,
    now_ns: u64,
    last_run_ns: u64,
    orphan_ttl: &Duration,
    tcp_time_wait_ttl: &Duration,
) -> Option<CleanupPlan> {
    let current_reason = cleanup_reason(flow, now_ns, last_run_ns, orphan_ttl, tcp_time_wait_ttl)
        .or_else(|| {
            flow.pair_invalid
                .then(|| terminal_marker_reason(flow).unwrap_or(CleanupReason::Invalid))
        });

    let reciprocal_counter = counter_flow.filter(|counter| {
        flow.counter_flow_key != key
            && counter.counter_flow_key == key
            && counter.pair_tag == flow.pair_tag
    });
    let pair_reason = match reciprocal_counter {
        Some(counter) => {
            let reason = current_reason?;
            cleanup_reason(counter, now_ns, last_run_ns, orphan_ttl, tcp_time_wait_ttl)
                .map_or(reason, |counter_reason| reason.max(counter_reason))
        }
        None => current_reason.or_else(|| terminal_marker_reason(flow))?,
    };

    Some(CleanupPlan {
        key,
        counter_key: reciprocal_counter.map(|_| flow.counter_flow_key),
        pair_tag: flow.pair_tag,
        reason: pair_reason,
        invariant_violation: flow.pair_invalid || reciprocal_counter.is_none(),
    })
}

pub(super) fn prune_orphaned_or_closed(
    flow_map: &mut HashMap<MapData, FlowKeyV4, Flow>,
    now_ns: u64,
    last_run_ns: u64,
    orphan_ttl: &Duration,
    tcp_time_wait_ttl: &Duration,
) -> CleanupSummary {
    let mut scheduled = HashSet::new();
    let mut plans = Vec::new();
    let mut lookup_failures = 0;

    for (key, flow) in flow_map.iter().flatten() {
        if scheduled.contains(&key)
            || (cleanup_reason(&flow, now_ns, last_run_ns, orphan_ttl, tcp_time_wait_ttl).is_none()
                && !flow.pair_invalid)
        {
            continue;
        }

        let counter_flow = match flow_map.get(&flow.counter_flow_key, 0) {
            Ok(counter) => Some(counter),
            Err(MapError::KeyNotFound) => None,
            Err(_) => {
                lookup_failures += 1;
                continue;
            }
        };
        let Some(plan) = plan_pair_cleanup(
            key,
            &flow,
            counter_flow.as_ref(),
            now_ns,
            last_run_ns,
            orphan_ttl,
            tcp_time_wait_ttl,
        ) else {
            continue;
        };

        scheduled.insert(plan.key);
        if let Some(counter_key) = plan.counter_key {
            scheduled.insert(counter_key);
        }
        plans.push(plan);
    }

    let mut summary = CleanupSummary {
        invariant_violations: lookup_failures,
        ..CleanupSummary::default()
    };
    for plan in plans {
        summary.invariant_violations += u64::from(plan.invariant_violation);

        // Recheck the pair generation after planning. A same-key flow can still
        // be recreated, or a same-generation flow can refresh last_seen_ns, in
        // the narrow window between this lookup and deletion; the map API cannot
        // make that final state-check-and-delete atomic.
        if remove_pair_generation(flow_map, &plan.key, plan.pair_tag) {
            summary.connections += 1;
            match plan.reason {
                CleanupReason::Fin => summary.fins += 1,
                CleanupReason::Reset => summary.resets += 1,
                CleanupReason::Orphan => summary.orphans += 1,
                CleanupReason::Invalid => {}
            }
        } else {
            summary.invariant_violations += 1;
        }
        if let Some(counter_key) = plan.counter_key
            && !remove_pair_generation(flow_map, &counter_key, plan.pair_tag)
        {
            summary.invariant_violations += 1;
        }
    }

    trace!(
        "Cleaned up {} connections (fin={} rst={} orphans={} invariants={})",
        summary.connections,
        summary.fins,
        summary.resets,
        summary.orphans,
        summary.invariant_violations
    );

    summary
}

fn remove_pair_generation(
    flow_map: &mut HashMap<MapData, FlowKeyV4, Flow>,
    key: &FlowKeyV4,
    pair_tag: u32,
) -> bool {
    match flow_map.get(key, 0) {
        Ok(flow) if flow.pair_tag == pair_tag => flow_map.remove(key).is_ok(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{CleanupReason, plan_pair_cleanup};
    use std::time::Duration;
    use xlb_common::types::{Flow, FlowDirection, FlowKeyV4};

    const NOW_NS: u64 = 400_000_000_000;
    const LAST_RUN_NS: u64 = 399_000_000_000;

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
            last_seen_ns: NOW_NS,
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
            pair_tag: 1,
        }
    }

    fn plan(key: FlowKeyV4, flow: &Flow, counter: Option<&Flow>) -> Option<super::CleanupPlan> {
        plan_pair_cleanup(
            key,
            flow,
            counter,
            NOW_NS,
            LAST_RUN_NS,
            &Duration::from_secs(300),
            &Duration::from_secs(60),
        )
    }

    #[test]
    fn one_stale_direction_schedules_the_reciprocal_pair() {
        let (server_key, client_key) = keys();
        let mut server = flow(FlowDirection::ToServer, client_key);
        let client = flow(FlowDirection::ToClient, server_key);
        server.last_seen_ns = 0;

        let cleanup = plan(server_key, &server, Some(&client)).expect("stale pair should clean");

        assert_eq!(cleanup.reason, CleanupReason::Orphan);
        assert_eq!(cleanup.counter_key, Some(client_key));
        assert!(!cleanup.invariant_violation);
    }

    #[test]
    fn valid_half_close_is_retained() {
        let (server_key, client_key) = keys();
        let mut server = flow(FlowDirection::ToServer, client_key);
        let client = flow(FlowDirection::ToClient, server_key);
        server.fin = true;

        assert_eq!(plan(server_key, &server, Some(&client)), None);
    }

    #[test]
    fn terminal_survivor_without_counterpart_is_cleaned_as_invariant() {
        let (server_key, client_key) = keys();
        let mut server = flow(FlowDirection::ToServer, client_key);
        server.fin = true;
        server.pair_invalid = true;

        let cleanup = plan(server_key, &server, None).expect("terminal survivor should clean");

        assert_eq!(cleanup.reason, CleanupReason::Fin);
        assert_eq!(cleanup.counter_key, None);
        assert!(cleanup.invariant_violation);
    }

    #[test]
    fn mismatched_counterpart_is_not_deleted() {
        let (server_key, client_key) = keys();
        let unrelated_key = FlowKeyV4::tcp(
            0xc000_0202,
            0xcb00_710a,
            50_001,
            80,
            FlowDirection::ToServer,
        );
        let mut server = flow(FlowDirection::ToServer, client_key);
        let client = flow(FlowDirection::ToClient, unrelated_key);
        server.last_seen_ns = 0;

        let cleanup = plan(server_key, &server, Some(&client)).expect("survivor should clean");

        assert_eq!(cleanup.counter_key, None);
        assert!(cleanup.invariant_violation);
    }

    #[test]
    fn reused_counter_key_from_another_generation_is_not_deleted() {
        let (server_key, client_key) = keys();
        let mut server = flow(FlowDirection::ToServer, client_key);
        let mut client = flow(FlowDirection::ToClient, server_key);
        server.last_seen_ns = 0;
        client.pair_tag = 2;

        let cleanup = plan(server_key, &server, Some(&client)).expect("survivor should clean");

        assert_eq!(cleanup.counter_key, None);
        assert!(cleanup.invariant_violation);
    }

    #[test]
    fn ebpf_pair_invalid_marker_is_always_counted() {
        let (server_key, client_key) = keys();
        let mut server = flow(FlowDirection::ToServer, client_key);
        let client = flow(FlowDirection::ToClient, server_key);
        server.fin = true;
        server.pair_invalid = true;

        let cleanup = plan(server_key, &server, Some(&client)).expect("marked pair should clean");

        assert_eq!(cleanup.counter_key, Some(client_key));
        assert!(cleanup.invariant_violation);
    }

    #[test]
    fn pair_invalid_without_tcp_close_is_not_counted_as_an_orphan() {
        let (server_key, client_key) = keys();
        let mut server = flow(FlowDirection::ToServer, client_key);
        server.pair_invalid = true;

        let cleanup = plan(server_key, &server, None).expect("marked survivor should clean");

        assert_eq!(cleanup.reason, CleanupReason::Invalid);
        assert!(cleanup.invariant_violation);
    }

    #[test]
    fn reset_reason_wins_over_orphan_reason() {
        let (server_key, client_key) = keys();
        let mut server = flow(FlowDirection::ToServer, client_key);
        let mut client = flow(FlowDirection::ToClient, server_key);
        server.last_seen_ns = 0;
        client.rst_ns = 1;

        let cleanup = plan(server_key, &server, Some(&client)).expect("pair should clean");

        assert_eq!(cleanup.reason, CleanupReason::Reset);
        assert_eq!(cleanup.counter_key, Some(client_key));
    }
}
