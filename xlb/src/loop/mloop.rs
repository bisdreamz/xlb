use crate::r#loop::metrics::Metrics;
use crate::r#loop::utils;
use crate::r#loop::utils::LbFlowStats;
use crate::metrics;
use crate::provider::{BackendProvider, hosts_to_backends_with_routes};
use aya::maps::{Array, HashMap, MapData, MapError};
use log::{debug, trace, warn};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::time::interval;
use xlb_common::consts;
use xlb_common::types::{Backend, Flow, FlowKeyV4};

pub struct MaintenanceLoopHandle {
    shutdown: Arc<AtomicBool>,
}

impl MaintenanceLoopHandle {
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

pub struct MaintenanceLoop {
    shutdown: OnceLock<Arc<AtomicBool>>,
    /// Provider of backends
    provider: Arc<dyn BackendProvider>,
    /// Ebpf land backend destination
    ebpf_backends: Array<MapData, Backend>,
    /// Live map of connection flows, see ['Flow']
    ebpf_flows: HashMap<MapData, FlowKeyV4, Flow>,
    /// If a flow is active longer than this TTL it is considered
    /// to be an orpaned connection (closed w/o fin or rst)
    orphan_ttl: Duration,
    /// Duration we await post a TCP flow side's FIN
    /// event for time_wait to allow grace period for
    /// full closure
    tcp_time_wait_ttl: Duration,
    /// Timestamp (monotonic ns) of the last run,
    /// used as a filter for identifying recent events
    /// such as new conns or closures
    last_run_ns: u64,
    /// Per-flow tracking for delta calculations: flow_key -> (bytes, packets)
    /// Prevents underflow when flows are deleted and avoids improper
    /// reported bandwidth dips during connection closures
    prev_flow_stats: std::collections::HashMap<FlowKeyV4, (u64, u64)>,
}

impl MaintenanceLoop {
    pub fn new(
        provider: Arc<dyn BackendProvider>,
        ebpf_backends: Array<MapData, Backend>,
        ebpf_flows: HashMap<MapData, FlowKeyV4, Flow>,
        orphan_ttl: Duration,
        tcp_time_wait_ttl: Duration,
    ) -> Self {
        Self {
            shutdown: OnceLock::new(),
            provider,
            ebpf_backends,
            ebpf_flows,
            orphan_ttl,
            tcp_time_wait_ttl,
            last_run_ns: 0,
            prev_flow_stats: std::collections::HashMap::new(),
        }
    }

    async fn run(&mut self) {
        let now_ns = utils::monotonic_now_ns();
        let new_hosts = self.provider.get_backends();
        let new_backends = hosts_to_backends_with_routes(&new_hosts).await;

        if new_backends.is_empty() {
            log::warn!("No backends available - all new connections will be dropped");
        }

        let (mut stats, new_prev_flow_stats) = utils::aggregate_flow_stats(
            self.last_run_ns,
            self.ebpf_flows.iter().flatten(),
            &self.prev_flow_stats,
            &self.orphan_ttl,
            now_ns,
        );

        stats.available_backends = new_backends.len() as u32;

        log_pretty_stats(&stats);
        metrics::log_metrics(&stats, &new_hosts);

        self.prev_flow_stats = new_prev_flow_stats;

        for (i, backend) in new_backends.iter().enumerate() {
            self.ebpf_backends
                .set(i as u32, backend, 0)
                .expect("Failed to set backend entry");
        }

        if new_backends.len() > consts::MAX_BACKENDS as usize {
            warn!(
                "More backends than allowed ({}) - dropping extra backends",
                consts::MAX_BACKENDS
            );
        }

        let empty_backend = Backend::default();
        for i in new_backends.len() as u32..consts::MAX_BACKENDS {
            self.ebpf_backends
                .set(i, &empty_backend.clone(), 0)
                .expect("Failed to set empty sentinel backend!");
        }
        trace!("Updated {} backends", new_backends.len());

        let cleanup = prune_orphaned_or_closed(
            &mut self.ebpf_flows,
            now_ns,
            self.last_run_ns,
            &self.orphan_ttl,
            &self.tcp_time_wait_ttl,
        );

        metrics::record_connections_orphaned(cleanup.orphans);
        if cleanup.invariant_violations > 0 {
            warn!(
                "Detected {} flow-pair invariant violation(s) during cleanup",
                cleanup.invariant_violations
            );
            metrics::record_flow_pair_invariant_violations(cleanup.invariant_violations);
        }

        self.last_run_ns = now_ns;
    }

    pub fn start(mut self, tick: Duration) -> MaintenanceLoopHandle {
        // build new index of ip -> Backend entry with updated
        // stats sourced from the flowmap. Then diff against
        // the prior snapshot to calculate stats deltas. Finally,
        // update the ebpf backends map with the new values
        let shutdown = Arc::new(AtomicBool::new(false));
        self.shutdown
            .set(shutdown.clone())
            .expect("Failed to set shutdown flag, already started?");

        let mut ticker = interval(Duration::from_secs(tick.as_secs()));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        tokio::spawn(async move {
            loop {
                ticker.tick().await;
                self.run().await;

                if self
                    .shutdown
                    .get()
                    .expect("Failed to get shutdown flag")
                    .load(Ordering::Relaxed)
                {
                    break;
                }
            }
        });

        MaintenanceLoopHandle { shutdown }
    }
}

// Declaration order defines which terminal reason wins when the two halves
// qualify for different reasons: Reset > Fin > Orphan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CleanupReason {
    Orphan,
    Fin,
    Reset,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct CleanupSummary {
    connections: u64,
    fins: u64,
    resets: u64,
    orphans: u64,
    invariant_violations: u64,
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
                .then(|| terminal_marker_reason(flow).unwrap_or(CleanupReason::Orphan))
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

fn prune_orphaned_or_closed(
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
            _reserved: [0; 2],
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

fn format_pretty_metrics(metrics: &Metrics) -> String {
    let total_closed = metrics.closed_fin_by_client
        + metrics.closed_fin_by_server
        + metrics.closed_rsts_by_client
        + metrics.closed_rsts_by_server;
    let total_fin = metrics.closed_fin_by_client + metrics.closed_fin_by_server;
    let total_rst_by_side = metrics.closed_rsts_by_client + metrics.closed_rsts_by_server;

    format!(
        "pps={:.0} mbps={:.2} active={} new={} closed={} (fin={} rst={} orphans={})",
        metrics.packets_per_second,
        metrics.bandwidth_mbps,
        metrics.active_conns,
        metrics.new_conns,
        total_closed,
        total_fin,
        total_rst_by_side,
        metrics.orphaned_conns
    )
}

fn log_pretty_stats(stats: &LbFlowStats) {
    debug!("Load Balancer Stats:");
    debug!(
        "\tInbound  (ToServer): {}",
        format_pretty_metrics(&stats.totals.to_server)
    );
    debug!(
        "\tOutbound (ToClient): {}",
        format_pretty_metrics(&stats.totals.to_client)
    );
    debug!(
        "\tActive Clients: {} | Available Backends: {}",
        stats.totals.client_set.len(),
        stats.available_backends
    );

    if !stats.backends.is_empty() {
        debug!("\tPer-Backend:");

        for (backend_ip, backend_stats) in stats.backends.iter() {
            let ip_str = utils::format_ip(*backend_ip);
            debug!("\t\t{} clients={}", ip_str, backend_stats.client_set.len());
            debug!(
                "\t\t\tRX (Inbound):  {}",
                format_pretty_metrics(&backend_stats.to_server)
            );
            debug!(
                "\t\t\tTX (Outbound): {}",
                format_pretty_metrics(&backend_stats.to_client)
            );
        }
    }
}
