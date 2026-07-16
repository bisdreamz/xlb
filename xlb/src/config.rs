use crate::provider::Host;
use anyhow::{Result, bail};
use config::Config;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use xlb_common::config::routing::RoutingMode;
use xlb_common::net::Proto;
use xlb_common::types::PortMapping;

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum BackendSource {
    Static {
        backends: Vec<Host>,
    },
    #[allow(dead_code)]
    Kubernetes {
        namespace: String,
        service: String,
    },
}

#[repr(C)]
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ListenAddr {
    /// Will attach to the interface and primary ip of
    /// associated with the default network route
    #[default]
    Auto,
    /// Specify an ipv4 listen addr, also used to determine
    /// the target interface
    Ip(String),
}

#[derive(Debug, Clone, Deserialize, Default, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum OtelProtocol {
    #[default]
    Grpc,
    Http,
}

/// OpenTelemetry configuration for metrics export
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct OtelConfig {
    /// Enable/disable OTEL metrics export
    #[serde(default)]
    pub enabled: bool,
    /// OTLP endpoint (e.g., "http://otel-collector:4317" for gRPC)
    pub endpoint: String,
    /// Export interval in seconds
    #[serde(default = "default_otel_export_interval")]
    pub export_interval_secs: u64,
    /// Optional headers for authentication (e.g., API keys)
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Protocol: grpc or http/protobuf
    #[serde(default)]
    pub protocol: OtelProtocol,
}

const fn default_otel_export_interval() -> u64 {
    10
}

/// The user facing application config
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub struct XlbConfig {
    /// Optional name to attach to future otel metrics,
    /// if not provided defaults to kube service name
    /// or static-lb for static deployments
    pub name: Option<String>,
    /// The IP address to "listen" on which is the expected
    /// dest IP value for inbound packets of interest.
    /// Default to auto which will pick the primary address
    /// of the interface associated with the default route.
    #[serde(default)]
    pub listen: ListenAddr,
    /// The target protocol to proxy to the backends e.g.
    /// tcp or udp
    #[serde(default)]
    pub proto: Proto,
    /// The port mappings of inbound to backend dest
    /// ports. E.g. [80 -> 8080], [443 -> 443]
    pub ports: Vec<PortMapping>,
    /// The source of backend hosts to load balance to
    pub provider: BackendSource,
    /// Routing mode of either nat or dsr, presently
    /// only nat is supported
    #[serde(default)]
    pub mode: RoutingMode,
    /// The duration by which an inactive flow,
    /// which has not seen any closure, is considered
    /// orphaned. Must be at least five minutes.
    #[serde(default = "default_orphan_ttl_secs")]
    #[schemars(range(min = "MIN_ORPHAN_TTL_SECS"))]
    pub orphan_ttl_secs: u32,
    /// Grace period after a shutdown which is
    /// used to 'politely' send RSTs to any
    /// active flows, particularly to allow graceful
    /// drain after a potential lb A record removal
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout: u32,
    /// Optional OpenTelemetry metrics configuration
    #[serde(default)]
    pub otel: Option<OtelConfig>,
}

pub const MIN_ORPHAN_TTL_SECS: u32 = 5 * 60;

const fn default_orphan_ttl_secs() -> u32 {
    MIN_ORPHAN_TTL_SECS
}
const fn default_shutdown_timeout() -> u32 {
    15
}

impl XlbConfig {
    pub fn load(path: PathBuf) -> Result<XlbConfig> {
        let config = Config::builder()
            .add_source(config::File::from(path.to_path_buf()))
            .build()?
            .try_deserialize::<XlbConfig>()?;

        if config.ports.is_empty() || config.ports.len() > 8 {
            bail!("Number of port mappings must be between 1 and 8");
        }

        validate_orphan_ttl_secs(config.orphan_ttl_secs)?;

        Ok(config)
    }
}

fn validate_orphan_ttl_secs(orphan_ttl_secs: u32) -> Result<()> {
    if orphan_ttl_secs < MIN_ORPHAN_TTL_SECS {
        bail!("orphan_ttl_secs must be at least {MIN_ORPHAN_TTL_SECS} seconds (5 minutes)");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::schema_for;

    #[test]
    fn schema_advertises_orphan_ttl_minimum() {
        let schema = schema_for!(XlbConfig);
        let properties = schema
            .schema
            .object
            .expect("config schema is an object")
            .properties;
        let orphan_ttl = properties
            .get("orphan_ttl_secs")
            .expect("orphan TTL is in the schema")
            .clone()
            .into_object();

        assert_eq!(
            orphan_ttl
                .number
                .expect("orphan TTL has numeric validation")
                .minimum,
            Some(f64::from(MIN_ORPHAN_TTL_SECS))
        );
    }

    #[test]
    fn rejects_orphan_ttl_below_five_minutes() {
        let error = validate_orphan_ttl_secs(MIN_ORPHAN_TTL_SECS - 1)
            .expect_err("short orphan TTL must be rejected");

        assert_eq!(
            error.to_string(),
            "orphan_ttl_secs must be at least 300 seconds (5 minutes)"
        );
    }

    #[test]
    fn accepts_five_minute_orphan_ttl() {
        validate_orphan_ttl_secs(MIN_ORPHAN_TTL_SECS)
            .expect("five-minute orphan TTL must be accepted");
    }
}
