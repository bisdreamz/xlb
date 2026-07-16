use crate::r#loop::cleanup::prune_orphaned_or_closed;
use crate::r#loop::metrics::Metrics;
use crate::r#loop::utils;
use crate::r#loop::utils::LbFlowStats;
use crate::metrics;
use crate::provider::{BackendProvider, hosts_to_backends_with_routes};
use aya::maps::{Array, HashMap, MapData, PerCpuArray};
use log::{debug, trace, warn};
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
    /// Per-CPU count of flow-pair invariant repairs performed in eBPF.
    flow_pair_invariants: PerCpuArray<MapData, u64>,
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
    /// Last cumulative dataplane invariant count used to emit metric deltas.
    last_flow_pair_invariants: u64,
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
        flow_pair_invariants: PerCpuArray<MapData, u64>,
        orphan_ttl: Duration,
        tcp_time_wait_ttl: Duration,
    ) -> Self {
        Self {
            shutdown: OnceLock::new(),
            provider,
            ebpf_backends,
            ebpf_flows,
            flow_pair_invariants,
            orphan_ttl,
            tcp_time_wait_ttl,
            last_run_ns: 0,
            last_flow_pair_invariants: 0,
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
                .set(i, empty_backend, 0)
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
        let dataplane_invariants = match self.flow_pair_invariants.get(&0, 0) {
            Ok(values) => {
                let total = values
                    .iter()
                    .fold(0u64, |sum, count| sum.saturating_add(*count));
                let delta = total.saturating_sub(self.last_flow_pair_invariants);
                self.last_flow_pair_invariants = total;
                delta
            }
            Err(err) => {
                warn!("Failed to read dataplane flow-pair invariant counter: {err}");
                0
            }
        };
        let invariant_violations = cleanup
            .invariant_violations
            .saturating_add(dataplane_invariants);
        if invariant_violations > 0 {
            warn!(
                "Detected {} flow-pair invariant violation observation(s) this interval",
                invariant_violations
            );
            metrics::record_flow_pair_invariant_violations(invariant_violations);
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
