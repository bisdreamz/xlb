use crate::provider::{BackendProvider, hosts_to_backends_with_routes};
use crate::r#loop::utils;
use crate::r#loop::utils::LbFlowStats;
use aya::maps::{Array, HashMap, MapData};
use log::{debug, info, trace};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::time::interval;
use xlb_common::consts;
use xlb_common::types::{Backend, Flow, FlowKey};

/*
* 1) prune orphaned con entries from ebpf flow map
 * 2) rebuild backends list and aggregate stats for ebpf
 * 3) calculate backend deltas between old and new
        backend maps to determine otel metric values
        to  export in rate form e.g. per second
 */

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
    provider: Box<dyn BackendProvider>,
    /// Ebpf land backend destination
    ebpf_backends: Array<MapData, Backend>,
    /// Live map of connection flows, see ['Flow']
    ebpf_flows: HashMap<MapData, FlowKey, Flow>,
    /// Snapshots of prior loop backen states for
    /// stats delta calculations
    prev_stats: LbFlowStats,
    /// If a flow is active longer than this TTL it is considered
    /// to be an orpaned connection (closed w/o fin or rst)
    orphan_ttl: Duration,
}

impl MaintenanceLoop {
    pub fn new(
        provider: Box<dyn BackendProvider>,
        ebpf_backends: Array<MapData, Backend>,
        ebpf_flows: HashMap<MapData, FlowKey, Flow>,
        orphan_ttl: Duration,
    ) -> Self {
        Self {
            shutdown: OnceLock::new(),
            provider,
            ebpf_backends,
            ebpf_flows,
            prev_stats: LbFlowStats::default(),
            orphan_ttl,
        }
    }

    async fn run(&mut self) {
        let stats = utils::aggregate_flow_stats(
            0,
            self.ebpf_flows
                .iter()
                .flatten()
        );

        let deltas = utils::calc_aggregate_deltas(&self.prev_stats, &stats);
        self.prev_stats = stats;
        trace!("Delta stats: {:?}", deltas);

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

        // TODO how and where to count orhpaned connections?

        // TODO flowmap orhpan and closed conn cleanup here

        trace!("Updated {} backends", new_backends.len());
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
