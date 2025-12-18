use crate::r#loop::utils::{LbFlowStats, format_ip};
use anyhow::Result;
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Gauge, Meter};
use std::sync::OnceLock;

struct EgressMetrics {
    bandwidth_mbps: Gauge<f64>,
    packets_per_second: Gauge<f64>,
    flows_active: Gauge<u64>,
    closures: Counter<u64>,
    bytes_transferred: Counter<u64>,
}

static METRICS: OnceLock<EgressMetrics> = OnceLock::new();

/// Initialize egress (ToClient) metrics instruments
pub fn init(meter: &Meter) -> Result<()> {
    let metrics = EgressMetrics {
        bandwidth_mbps: meter
            .f64_gauge("xlb.egress.mbps")
            .with_description("Bandwidth in Mbps from backends to clients")
            .with_unit("Mbit/s")
            .build(),

        packets_per_second: meter
            .f64_gauge("xlb.egress.pps")
            .with_description("Packets per second from backends to clients")
            .build(),

        flows_active: meter
            .u64_gauge("xlb.egress.flows.active")
            .with_description("Active egress flows per backend")
            .build(),

        closures: meter
            .u64_counter("xlb.egress.flows.closed")
            .with_description("Connection closures initiated from server side")
            .build(),

        bytes_transferred: meter
            .u64_counter("xlb.egress.bytes")
            .with_description("Total bytes transferred from backends to clients")
            .with_unit("By")
            .build(),
    };

    METRICS
        .set(metrics)
        .map_err(|_| anyhow::anyhow!("Egress metrics already initialized"))?;

    Ok(())
}

/// Record egress metrics per backend
pub fn log_egress(stats: &LbFlowStats) {
    let Some(m) = METRICS.get() else { return };

    for (backend_ip, backend_stats) in &stats.backends {
        let backend_str = format_ip(*backend_ip);

        m.bandwidth_mbps.record(
            backend_stats.to_client.bandwidth_mbps,
            &[KeyValue::new("backend", backend_str.clone())],
        );

        m.packets_per_second.record(
            backend_stats.to_client.packets_per_second,
            &[KeyValue::new("backend", backend_str.clone())],
        );

        m.flows_active.record(
            backend_stats.to_client.active_conns as u64,
            &[KeyValue::new("backend", backend_str.clone())],
        );

        m.closures.add(
            backend_stats.to_client.closed_fin_by_server as u64,
            &[
                KeyValue::new("backend", backend_str.clone()),
                KeyValue::new("type", "fin"),
            ],
        );

        m.closures.add(
            backend_stats.to_client.closed_rsts_by_server as u64,
            &[
                KeyValue::new("backend", backend_str.clone()),
                KeyValue::new("type", "rst"),
            ],
        );

        m.bytes_transferred.add(
            backend_stats.to_client.bytes_transferred,
            &[KeyValue::new("backend", backend_str)],
        );
    }
}
