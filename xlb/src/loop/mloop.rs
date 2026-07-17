use crate::r#loop::cleanup::{CleanupSummary, prune_orphaned_or_closed};
use crate::r#loop::metrics::Metrics;
use crate::r#loop::utils;
use crate::r#loop::utils::LbFlowStats;
use crate::metrics;
use crate::provider::{BackendProvider, hosts_to_backends_with_routes};
use crate::status::StatusState;
use crate::system::ResourceSampler;
use anyhow::{Context, Result, anyhow};
use aya::maps::{Array, HashMap, MapData, PerCpuArray};
use log::{debug, trace, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::interval;
use xlb_common::consts;
use xlb_common::types::{Backend, Flow, FlowKeyV4};

pub struct MaintenanceLoopHandle {
    shutdown: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
}

/// eBPF maps owned and periodically reconciled by the maintenance loop.
pub struct MaintenanceMaps {
    pub backends: Array<MapData, Backend>,
    pub flows: HashMap<MapData, FlowKeyV4, Flow>,
    pub flow_pair_invariants: PerCpuArray<MapData, u64>,
}

impl MaintenanceLoopHandle {
    pub async fn wait_for_unexpected_exit(&mut self) -> Result<()> {
        let result = self
            .task
            .as_mut()
            .ok_or_else(|| anyhow!("Maintenance loop task has already been joined"))?
            .await;
        self.task.take();

        match result {
            Ok(()) => Err(anyhow!("Maintenance loop stopped unexpectedly")),
            Err(error) => Err(error).context("Maintenance loop task failed"),
        }
    }

    pub fn request_stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    pub async fn shutdown(mut self, timeout: Duration) -> Result<()> {
        self.request_stop();
        if let Some(mut task) = self.task.take() {
            match tokio::time::timeout(timeout, &mut task).await {
                Ok(result) => result.context("Maintenance loop task failed")?,
                Err(_) => {
                    task.abort();
                    match task.await {
                        Ok(()) => {}
                        Err(error) if error.is_cancelled() => {}
                        Err(error) => return Err(error).context("Maintenance loop task failed"),
                    }
                }
            }
        }
        Ok(())
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
    /// Samples the bounded resources used by this XLB instance.
    resource_sampler: ResourceSampler,
    /// Suppresses repeated warnings while flow-map iteration remains incomplete.
    flow_iteration_error_reported: bool,
    /// Latest operational snapshot exposed by the admin API.
    status: Arc<StatusState>,
}

impl MaintenanceLoop {
    pub fn new(
        provider: Arc<dyn BackendProvider>,
        maps: MaintenanceMaps,
        orphan_ttl: Duration,
        tcp_time_wait_ttl: Duration,
        attached_interfaces: Vec<String>,
        status: Arc<StatusState>,
    ) -> Self {
        let MaintenanceMaps {
            backends,
            flows,
            flow_pair_invariants,
        } = maps;
        Self {
            shutdown: OnceLock::new(),
            provider,
            ebpf_backends: backends,
            ebpf_flows: flows,
            flow_pair_invariants,
            orphan_ttl,
            tcp_time_wait_ttl,
            last_run_ns: 0,
            last_flow_pair_invariants: 0,
            prev_flow_stats: std::collections::HashMap::new(),
            resource_sampler: ResourceSampler::new(attached_interfaces),
            flow_iteration_error_reported: false,
            status,
        }
    }

    fn shutdown_requested(&self) -> bool {
        self.shutdown
            .get()
            .expect("Failed to get shutdown flag")
            .load(Ordering::Relaxed)
    }

    async fn run(&mut self) {
        let now_ns = utils::monotonic_now_ns();
        let new_hosts = self.provider.get_backends();
        let mut new_backends = hosts_to_backends_with_routes(&new_hosts).await;

        if new_backends.len() > consts::MAX_BACKENDS as usize {
            warn!(
                "More backends than allowed ({}); ignoring {} excess backend(s)",
                consts::MAX_BACKENDS,
                new_backends.len() - consts::MAX_BACKENDS as usize
            );
            new_backends.truncate(consts::MAX_BACKENDS as usize);
        }

        if new_backends.is_empty() {
            log::warn!("No backends available - all new connections will be dropped");
        }

        let mut flow_iteration_errors = 0u64;
        let mut first_flow_iteration_error = None;
        let flows = self.ebpf_flows.iter().filter_map(|entry| match entry {
            Ok(entry) => Some(entry),
            Err(error) => {
                flow_iteration_errors = flow_iteration_errors.saturating_add(1);
                if first_flow_iteration_error.is_none() {
                    first_flow_iteration_error = Some(error.to_string());
                }
                None
            }
        });
        let (mut stats, new_prev_flow_stats) = utils::aggregate_flow_stats(
            self.last_run_ns,
            flows,
            &self.prev_flow_stats,
            &self.orphan_ttl,
            now_ns,
        );

        stats.flow_map_complete = flow_iteration_errors == 0;
        if flow_iteration_errors > 0 && !self.flow_iteration_error_reported {
            warn!(
                "Flow-map iteration was incomplete (errors={}, first={}); suppressing flow-map and combined resource utilization until recovery",
                flow_iteration_errors,
                first_flow_iteration_error.as_deref().unwrap_or("unknown")
            );
            self.flow_iteration_error_reported = true;
        } else if flow_iteration_errors == 0 && self.flow_iteration_error_reported {
            log::info!("Flow-map iteration recovered");
            self.flow_iteration_error_reported = false;
        }

        stats.available_backends = new_backends.len() as u32;
        stats.resource_utilization = self
            .resource_sampler
            .sample(stats.flow_map_entries, stats.flow_map_complete);

        // Preserve the pre-existing best-effort flow-stat baseline even when
        // concurrent map churn makes this iteration incomplete. Completeness
        // is required for capacity reporting, but not for approximate traffic
        // counters.
        self.prev_flow_stats = new_prev_flow_stats;

        for (i, backend) in new_backends.iter().enumerate() {
            self.ebpf_backends
                .set(i as u32, backend, 0)
                .expect("Failed to set backend entry");
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

        apply_orphan_cleanup_stats(&mut stats, &cleanup);

        // Readiness describes the backend set actually committed to the BPF
        // map, never the candidate set observed before reconciliation.
        self.status.publish(
            &stats,
            &new_hosts,
            &new_backends,
            self.provider.is_healthy(),
        );
        log_pretty_stats(&stats);
        metrics::log_metrics(&stats, &new_hosts);

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

        let task = tokio::spawn(async move {
            loop {
                ticker.tick().await;
                if self.shutdown_requested() {
                    break;
                }

                self.run().await;

                if self.shutdown_requested() {
                    break;
                }
            }
        });

        MaintenanceLoopHandle {
            shutdown,
            task: Some(task),
        }
    }
}

fn apply_orphan_cleanup_stats(stats: &mut LbFlowStats, cleanup: &CleanupSummary) {
    stats.totals.to_server.orphaned_conns = 0;
    stats.totals.to_client.orphaned_conns = 0;
    for backend in stats.backends.values_mut() {
        backend.to_server.orphaned_conns = 0;
        backend.to_client.orphaned_conns = 0;
    }

    stats.totals.to_server.orphaned_conns = u32::try_from(cleanup.orphans).unwrap_or(u32::MAX);
    for (backend_ip, orphans) in &cleanup.orphans_by_backend {
        stats
            .backends
            .entry(*backend_ip)
            .or_default()
            .to_server
            .orphaned_conns = u32::try_from(*orphans).unwrap_or(u32::MAX);
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

    if let Some(overall) = stats.resource_utilization.overall_percent {
        debug!(
            "\tResource Utilization: overall={:.1}% cpu={:.1}% (host={:.1}% process={:.1}%) network={:.1}% flow_map={:.1}% ({} entries)",
            overall,
            stats.resource_utilization.cpu_percent.unwrap_or_default(),
            stats
                .resource_utilization
                .host_cpu_percent
                .unwrap_or_default(),
            stats
                .resource_utilization
                .process_cpu_percent
                .unwrap_or_default(),
            stats
                .resource_utilization
                .network_percent
                .unwrap_or_default(),
            stats
                .resource_utilization
                .flow_map_percent
                .unwrap_or_default(),
            stats.flow_map_entries
        );
    } else {
        debug!(
            "\tResource Utilization incomplete: host_cpu={:?}% process_cpu={:?}% network={:?}% flow_map={:?}% (complete={})",
            stats.resource_utilization.host_cpu_percent,
            stats.resource_utilization.process_cpu_percent,
            stats.resource_utilization.network_percent,
            stats.resource_utilization.flow_map_percent,
            stats.flow_map_complete
        );
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn maintenance_exit_before_shutdown_is_fatal() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(async {});
        let mut handle = MaintenanceLoopHandle {
            shutdown,
            task: Some(task),
        };

        let error = handle
            .wait_for_unexpected_exit()
            .await
            .expect_err("an unrequested maintenance exit must stop XLB");
        assert!(error.to_string().contains("stopped unexpectedly"));
        handle
            .shutdown(Duration::from_secs(1))
            .await
            .expect("join maintenance task");
    }

    #[test]
    fn cleanup_results_replace_directional_orphan_estimates() {
        let backend_ip = u128::from(0x0a00_0001_u32);
        let mut stats = LbFlowStats::default();
        stats.totals.to_server.orphaned_conns = 7;
        stats.totals.to_client.orphaned_conns = 5;
        stats
            .backends
            .entry(backend_ip)
            .or_default()
            .to_client
            .orphaned_conns = 3;
        let mut cleanup = CleanupSummary::default();
        cleanup.orphans = 2;
        cleanup.orphans_by_backend.insert(backend_ip, 2);

        apply_orphan_cleanup_stats(&mut stats, &cleanup);

        assert_eq!(stats.totals.to_server.orphaned_conns, 2);
        assert_eq!(stats.totals.to_client.orphaned_conns, 0);
        assert_eq!(stats.backends[&backend_ip].to_server.orphaned_conns, 2);
        assert_eq!(stats.backends[&backend_ip].to_client.orphaned_conns, 0);
    }
}
