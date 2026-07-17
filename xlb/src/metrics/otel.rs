use super::{egress, global, ingress, resource};
use crate::config::{Host, OtelConfig, OtelProtocol};
use crate::r#loop::utils::LbFlowStats;
use anyhow::Result;
use opentelemetry::KeyValue;
use opentelemetry::metrics::MeterProvider;
use opentelemetry_otlp::{MetricExporter, WithExportConfig, WithHttpConfig, WithTonicConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider, Temporality};
use std::sync::OnceLock;
use std::time::Duration;

static OTEL_PROVIDER: OnceLock<SdkMeterProvider> = OnceLock::new();

/// Initialize the OTEL metrics system
/// Sets up provider, meter, and initializes all metric modules
pub fn init(config: &OtelConfig, service_name: String) -> Result<()> {
    let exporter = match config.protocol {
        OtelProtocol::Grpc => {
            let mut builder = MetricExporter::builder()
                .with_tonic()
                .with_temporality(Temporality::Delta)
                .with_endpoint(&config.endpoint);

            if !config.headers.is_empty() {
                let mut metadata = tonic::metadata::MetadataMap::new();
                for (key, value) in &config.headers {
                    let key_name = tonic::metadata::MetadataKey::from_bytes(key.as_bytes())
                        .map_err(|e| {
                            anyhow::anyhow!("Invalid gRPC metadata key '{}': {}", key, e)
                        })?;
                    let value_str = tonic::metadata::MetadataValue::try_from(value.as_str())
                        .map_err(|e| {
                            anyhow::anyhow!("Invalid gRPC metadata value for '{}': {}", key, e)
                        })?;
                    metadata.insert(key_name, value_str);
                }
                builder = builder.with_metadata(metadata);
            }

            builder.build()?
        }
        OtelProtocol::Http => {
            let mut builder = MetricExporter::builder()
                .with_http()
                .with_temporality(Temporality::Delta)
                .with_endpoint(&config.endpoint);

            if !config.headers.is_empty() {
                let headers = config
                    .headers
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                builder = builder.with_headers(headers);
            }

            builder.build()?
        }
    };

    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(config.export_interval_secs))
        .build();

    let mut resource_attributes = vec![
        KeyValue::new("service.name", service_name.clone()),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
    ];
    let pod_name = std::env::var("POD_NAME").ok();
    let pod_namespace = std::env::var("POD_NAMESPACE").ok();

    if let Some(pod_name) = &pod_name {
        resource_attributes.push(KeyValue::new("k8s.pod.name", pod_name.clone()));
    }
    if let Some(namespace) = &pod_namespace {
        resource_attributes.push(KeyValue::new("k8s.namespace.name", namespace.clone()));
        resource_attributes.push(KeyValue::new("service.namespace", namespace.clone()));
    }
    if let Ok(node_name) = std::env::var("NODE_NAME") {
        resource_attributes.push(KeyValue::new("k8s.node.name", node_name));
    }
    if let Ok(pod_uid) = std::env::var("POD_UID") {
        resource_attributes.push(KeyValue::new("service.instance.id", pod_uid.clone()));
        resource_attributes.push(KeyValue::new("k8s.pod.uid", pod_uid));
    } else if let Some(pod_name) = pod_name {
        let instance_id = pod_namespace.map_or(pod_name.clone(), |namespace| {
            format!("{namespace}/{pod_name}")
        });
        resource_attributes.push(KeyValue::new("service.instance.id", instance_id));
    } else if let Ok(hostname) = std::env::var("HOSTNAME") {
        resource_attributes.push(KeyValue::new("service.instance.id", hostname));
    }

    let resource = Resource::builder()
        .with_attributes(resource_attributes)
        .build();

    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();

    let meter = provider.meter("xlb");

    global::init(&meter)?;
    ingress::init(&meter)?;
    egress::init(&meter)?;
    resource::init(&meter)?;

    OTEL_PROVIDER
        .set(provider)
        .map_err(|_| anyhow::anyhow!("OTEL provider already initialized"))?;

    log::info!(
        "OTEL metrics provider initialized: endpoint={} protocol={:?} temporality=Delta",
        config.endpoint,
        config.protocol
    );

    Ok(())
}

/// Export otel for global, ingress, and egress metrics
pub fn log_metrics(stats: &LbFlowStats, backends: &[Host]) {
    global::log_global(stats, backends);
    ingress::log_ingress(stats);
    egress::log_egress(stats);
    resource::log(&stats.resource_utilization);
}

/// Record violations of the two-entry flow-map invariant.
pub fn record_flow_pair_invariant_violations(count: u64) {
    global::record_flow_pair_invariant_violations(count);
}

/// Record orphan cleanup once per connection rather than per directional entry.
pub fn record_connections_orphaned(count: u64) {
    global::record_connections_orphaned(count);
}
