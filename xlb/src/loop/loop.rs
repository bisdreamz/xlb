use crate::provider::{hosts_to_backends_with_routes, BackendProvider};
use crate::r#loop::utils;
use crate::r#loop::utils::LbFlowStats;
use aya::maps::{Array, HashMap, MapData};
use log::{trace, info};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::time::interval;
use xlb_common::consts;
use xlb_common::types::{Backend, Flow};
use crate::r#loop::metrics::Metrics;

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
    ebpf_flows: HashMap<MapData, u64, Flow>,
    /// Snapshots of prior loop backen states for
    /// stats delta calculations
    prev_stats: LbFlowStats,
    /// If a flow is active longer than this TTL it is considered
    /// to be an orpaned connection (closed w/o fin or rst)
    #[allow(dead_code)]
    orphan_ttl: Duration,
    /// Timestamp (monotonic ns) of the last run,
    /// used as a filter for identifying recent events
    /// such as new conns or closures
    last_run_ns: u64,
}

impl MaintenanceLoop {
    pub fn new(
        provider: Arc<dyn BackendProvider>,
        ebpf_backends: Array<MapData, Backend>,
        ebpf_flows: HashMap<MapData, u64, Flow>,
        orphan_ttl: Duration,
    ) -> Self {
        Self {
            shutdown: OnceLock::new(),
            provider,
            ebpf_backends,
            ebpf_flows,
            prev_stats: LbFlowStats::default(),
            orphan_ttl,
            last_run_ns: 0,
        }
    }

    async fn run(&mut self) {
        let stats = utils::aggregate_flow_stats(
            self.last_run_ns,
            self.ebpf_flows
                .iter()
                .flatten()
        );

        let deltas = utils::calc_aggregate_deltas(&self.prev_stats, &stats);
        self.prev_stats = stats;

        log_pretty_stats(&deltas);

        let new_hosts = self.provider.get_backends();
        let new_backends = hosts_to_backends_with_routes(&new_hosts).await;

        for (i, backend) in new_backends.iter().enumerate() {
            self.ebpf_backends.set(i as u32, backend, 0)
                .expect("Failed to set backend entry");
        }

        let empty_backend = Backend::default();
        for i in new_backends.len() as u32.. consts::MAX_BACKENDS {
            self.ebpf_backends.set(i, &empty_backend.clone(), 0)
                .expect("Failed to set empty sentinel backend!");
        }
        trace!("Updated {} backends", new_backends.len());

        prune_orphaned_or_closed(&mut self.ebpf_flows);

        self.last_run_ns = utils::monotonic_now_ns();
    }

    pub fn start(mut self, tick: Duration) -> MaintenanceLoopHandle {
        // build new index of ip -> Backend entry with updated
        // stats sourced from the flowmap. Then diff against
        // the prior snapshot to calculate stats deltas. Finally,
        // update the ebpf backends map with the new values
        let shutdown = Arc::new(AtomicBool::new(false));
        self.shutdown.set(shutdown.clone())
            .expect("Failed to set shutdown flag, already started?");

        let mut ticker = interval(Duration::from_secs(tick.as_secs()));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        tokio::spawn(async move {
            loop {
                ticker.tick().await;
                self.run().await;

                if self.shutdown.get()
                    .expect("Failed to get shutdown flag")
                    .load(Ordering::Relaxed) {
                    break;
                }
            }
        });

        MaintenanceLoopHandle { shutdown }
    }
}

fn prune_orphaned_or_closed(flow_map: &mut HashMap<MapData, u64, Flow>) {
    let mut fins = 0;
    let mut rsts = 0;

    let keys_to_delete: Vec<u64> = flow_map
        .iter()
        .flatten()
        .filter_map(|(key, flow)| {
            if flow.fin_both_sides_closed || flow.rst {
                if flow.fin_is_src {
                    fins += 1;
                } else if flow.rst_is_src {
                    rsts += 1;
                }

                Some(key)
            } else {
                None
            }
        })
        .collect();

    for key in &keys_to_delete {
        let _ = flow_map.remove(key);
    }

    trace!("Cleaned up {} closed connections (fin={} rst={})",
        keys_to_delete.len() / 2, fins, rsts);
}

fn format_pretty_metrics(metrics: &Metrics) -> String {
    let mbps = (metrics.bytes_transfer as f64 * 8.0) / 1_000_000.0;
    let pps = metrics.packets_transfer;

    let total_closed = metrics.closed_fin_by_client + metrics.closed_fin_by_server
                     + metrics.closed_rsts_by_client + metrics.closed_rsts_by_server;
    let total_fin = metrics.closed_fin_by_client + metrics.closed_fin_by_server;
    let total_rst = metrics.closed_rsts_by_client + metrics.closed_rsts_by_server;

    format!(
        "pps={} mbps={:.2} active={} new={} closed={} (fin={} rst={})",
        pps, mbps, metrics.active_conns, metrics.new_conns,
        total_closed, total_fin, total_rst
    )
}

fn log_pretty_stats(stats: &LbFlowStats) {
    info!("Load Balancer Stats:");
    info!("\tInbound  (ToServer): {}", format_pretty_metrics(&stats.totals.to_server));
    info!("\tOutbound (ToClient): {}", format_pretty_metrics(&stats.totals.to_client));
    info!("\tActive Clients: {}", stats.totals.client_set.len());

    if !stats.backends.is_empty() {
        info!("\tPer-Backend:");

        for (backend_ip, backend_stats) in stats.backends.iter() {
            let ip_str = utils::format_ip(*backend_ip);
            info!("\t\t{} clients={}", ip_str, backend_stats.client_set.len());
            info!("\t\t\tRX (Inbound):  {}", format_pretty_metrics(&backend_stats.to_server));
            info!("\t\t\tTX (Outbound): {}", format_pretty_metrics(&backend_stats.to_client));
        }
    }
}