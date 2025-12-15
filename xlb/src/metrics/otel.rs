use crate::config::{OtelConfig, OtelProtocol};
use crate::provider::Host;
use crate::r#loop::utils::LbFlowStats;
use anyhow::Result;
use opentelemetry::KeyValue;
use opentelemetry::metrics::MeterProvider;
use opentelemetry_otlp::{MetricExporter, WithExportConfig, WithHttpConfig, WithTonicConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider, Temporality};
use opentelemetry_sdk::Resource;
use std::sync::OnceLock;
use std::time::Duration;
use super::{global, ingress, egress};

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
                        .map_err(|e| anyhow::anyhow!("Invalid gRPC metadata key '{}': {}", key, e))?;
                    let value_str = tonic::metadata::MetadataValue::try_from(value.as_str())
                        .map_err(|e| anyhow::anyhow!("Invalid gRPC metadata value for '{}': {}", key, e))?;
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
                let headers = config.headers.iter()
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

    let resource = Resource::builder()
        .with_attributes(vec![
            KeyValue::new("service.name", service_name.clone()),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        ])
        .build();

    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();

    let meter = provider.meter("xlb");

    global::init(&meter)?;
    ingress::init(&meter)?;
    egress::init(&meter)?;

    OTEL_PROVIDER.set(provider)
        .map_err(|_| anyhow::anyhow!("OTEL provider already initialized"))?;

    log::info!("OTEL metrics provider initialized: endpoint={} protocol={:?} temporality=Delta",
        config.endpoint, config.protocol);

    Ok(())
}

/// Export otel for global, ingress, and egress metrics
pub fn log_metrics(stats: &LbFlowStats, backends: &Vec<Host>) {
    global::log_global(stats, backends);
    ingress::log_ingress(stats);
    egress::log_egress(stats);
}
