use crate::config::Host;
use crate::r#loop::utils::LbFlowStats;
use anyhow::Result;
use opentelemetry::metrics::{Counter, Gauge, Meter};
use std::sync::OnceLock;

struct GlobalMetrics {
    backends_available: Gauge<u64>,
    connections_active: Gauge<u64>,
    connections_opened: Counter<u64>,
    connections_closed: Counter<u64>,
    connections_orphaned: Counter<u64>,
    flow_pair_invariant_violations: Counter<u64>,
}

static METRICS: OnceLock<GlobalMetrics> = OnceLock::new();

/// Initialize global metrics instruments
pub fn init(meter: &Meter) -> Result<()> {
    let metrics = GlobalMetrics {
        backends_available: meter
            .u64_gauge("xlb.global.backends.available")
            .with_description("Number of available backends from provider")
            .build(),

        connections_active: meter
            .u64_gauge("xlb.global.connections.active")
            .with_description("Total active connections")
            .build(),

        connections_opened: meter
            .u64_counter("xlb.global.connections.opened")
            .with_description("New connections opened since last export")
            .build(),

        connections_closed: meter
            .u64_counter("xlb.global.connections.closed")
            .with_description("Total connections closed")
            .build(),

        connections_orphaned: meter
            .u64_counter("xlb.global.connections.orphaned")
            .with_description("Orphaned connections cleaned up")
            .build(),

        flow_pair_invariant_violations: meter
            .u64_counter("xlb.global.flow_pair.invariant_violations")
            .with_description("Missing, mismatched, or concurrently removed flow-pair entries")
            .build(),
    };

    METRICS
        .set(metrics)
        .map_err(|_| anyhow::anyhow!("Global metrics already initialized"))?;

    Ok(())
}

pub fn record_flow_pair_invariant_violations(count: u64) {
    let Some(metrics) = METRICS.get() else {
        return;
    };

    metrics.flow_pair_invariant_violations.add(count, &[]);
}

pub fn record_connections_orphaned(count: u64) {
    let Some(metrics) = METRICS.get() else {
        return;
    };

    metrics.connections_orphaned.add(count, &[]);
}

/// Record global metrics (no backend-specific labels)
pub fn log_global(stats: &LbFlowStats, backends: &Vec<Host>) {
    let Some(m) = METRICS.get() else { return };

    m.backends_available.record(backends.len() as u64, &[]);

    // total conns should be equal across sides, so summing
    // to_server+to_client would result a double value
    let total_active_conns = stats.totals.to_server.active_conns;
    m.connections_active.record(total_active_conns as u64, &[]);

    m.connections_opened
        .add(stats.totals.to_server.new_conns as u64, &[]);

    // these record side specific so must add them
    let total_closed =
        stats.totals.to_server.closed_total_conns + stats.totals.to_client.closed_total_conns;
    m.connections_closed.add(total_closed as u64, &[]);
}
