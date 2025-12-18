use crate::r#loop::utils::{LbFlowStats, format_ip};
use anyhow::Result;
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Gauge, Meter};
use std::sync::OnceLock;

struct IngressMetrics {
    bandwidth_mbps: Gauge<f64>,
    packets_per_second: Gauge<f64>,
    flows_active: Gauge<u64>,
    closures: Counter<u64>,
    bytes_transferred: Counter<u64>,
}

static METRICS: OnceLock<IngressMetrics> = OnceLock::new();

/// Initialize ingress (ToServer) metrics instruments
pub fn init(meter: &Meter) -> Result<()> {
    let metrics = IngressMetrics {
        bandwidth_mbps: meter
            .f64_gauge("xlb.ingress.mbps")
            .with_description("Bandwidth in Mbps from clients to backends")
            .build(),

        packets_per_second: meter
            .f64_gauge("xlb.ingress.pps")
            .with_description("Packets per second from clients to backends")
            .build(),

        flows_active: meter
            .u64_gauge("xlb.ingress.flows.active")
            .with_description("Active ingress flows per backend")
            .build(),

        closures: meter
            .u64_counter("xlb.ingress.flows.closed")
            .with_description("Connection closures initiated from client side")
            .build(),

        bytes_transferred: meter
            .u64_counter("xlb.ingress.bytes")
            .with_description("Total bytes transferred from clients to backends")
            .with_unit("By")
            .build(),
    };

    METRICS
        .set(metrics)
        .map_err(|_| anyhow::anyhow!("Ingress metrics already initialized"))?;

    Ok(())
}

/// Record ingress metrics per backend
pub fn log_ingress(stats: &LbFlowStats) {
    let Some(m) = METRICS.get() else { return };

    for (backend_ip, backend_stats) in &stats.backends {
        let backend_str = format_ip(*backend_ip);

        m.bandwidth_mbps.record(
            backend_stats.to_server.bandwidth_mbps,
            &[KeyValue::new("backend", backend_str.clone())],
        );

        m.packets_per_second.record(
            backend_stats.to_server.packets_per_second,
            &[KeyValue::new("backend", backend_str.clone())],
        );

        m.flows_active.record(
            backend_stats.to_server.active_conns as u64,
            &[KeyValue::new("backend", backend_str.clone())],
        );

        m.closures.add(
            backend_stats.to_server.closed_fin_by_client as u64,
            &[
                KeyValue::new("backend", backend_str.clone()),
                KeyValue::new("type", "fin"),
            ],
        );

        m.closures.add(
            backend_stats.to_server.closed_rsts_by_client as u64,
            &[
                KeyValue::new("backend", backend_str.clone()),
                KeyValue::new("type", "rst"),
            ],
        );

        m.bytes_transferred.add(
            backend_stats.to_server.bytes_transferred,
            &[KeyValue::new("backend", backend_str)],
        );
    }
}
