use crate::system::ResourceUtilization;
use anyhow::Result;
use opentelemetry::metrics::{Gauge, Meter};
use std::sync::OnceLock;

struct ResourceMetrics {
    cpu_utilization: Gauge<f64>,
    host_cpu_utilization: Gauge<f64>,
    process_cpu_utilization: Gauge<f64>,
    network_utilization: Gauge<f64>,
    flow_map_utilization: Gauge<f64>,
    overall_utilization: Gauge<f64>,
}

static METRICS: OnceLock<ResourceMetrics> = OnceLock::new();

pub fn init(meter: &Meter) -> Result<()> {
    let metrics = ResourceMetrics {
        cpu_utilization: meter
            .f64_gauge("xlb.resource.cpu.utilization")
            .with_description("Maximum host or XLB process CPU pressure")
            .with_unit("%")
            .build(),
        host_cpu_utilization: meter
            .f64_gauge("xlb.resource.cpu.host.utilization")
            .with_description("Host CPU usage, including kernel and softirq work")
            .with_unit("%")
            .build(),
        process_cpu_utilization: meter
            .f64_gauge("xlb.resource.cpu.process.utilization")
            .with_description("XLB process CPU usage against its configured CPU capacity")
            .with_unit("%")
            .build(),
        network_utilization: meter
            .f64_gauge("xlb.resource.network.utilization")
            .with_description(
                "Busiest direction across attached XDP interfaces as a percentage of link speed",
            )
            .with_unit("%")
            .build(),
        flow_map_utilization: meter
            .f64_gauge("xlb.resource.flow_map.utilization")
            .with_description("Flow-map entries as a percentage of map capacity")
            .with_unit("%")
            .build(),
        overall_utilization: meter
            .f64_gauge("xlb.resource.utilization")
            .with_description("Maximum XLB CPU, network, or flow-map utilization")
            .with_unit("%")
            .build(),
    };

    METRICS
        .set(metrics)
        .map_err(|_| anyhow::anyhow!("Resource metrics already initialized"))?;

    Ok(())
}

pub fn log(utilization: &ResourceUtilization) {
    let Some(metrics) = METRICS.get() else {
        return;
    };

    if let Some(cpu) = utilization.cpu_percent {
        metrics.cpu_utilization.record(cpu, &[]);
    }
    if let Some(host_cpu) = utilization.host_cpu_percent {
        metrics.host_cpu_utilization.record(host_cpu, &[]);
    }
    if let Some(process_cpu) = utilization.process_cpu_percent {
        metrics.process_cpu_utilization.record(process_cpu, &[]);
    }
    if let Some(network) = utilization.network_percent {
        metrics.network_utilization.record(network, &[]);
    }
    if let Some(flow_map) = utilization.flow_map_percent {
        metrics.flow_map_utilization.record(flow_map, &[]);
    }
    if let Some(overall) = utilization.overall_percent {
        metrics.overall_utilization.record(overall, &[]);
    }
}
