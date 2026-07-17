use anyhow::{Result, bail};
use config::Config;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use xlb_common::config::routing::RoutingMode;
use xlb_common::net::Proto;
use xlb_common::types::PortMapping;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, JsonSchema)]
pub struct Host {
    pub name: String,
    pub ip: IpAddr,
}

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

/// Local listener for health, readiness, and administrative status.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AdminConfig {
    /// Address on which the unauthenticated admin API listens.
    #[serde(default = "default_admin_address")]
    pub address: IpAddr,
    /// TCP port on which the admin API listens.
    #[serde(default = "default_admin_port")]
    pub port: u16,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            address: default_admin_address(),
            port: default_admin_port(),
        }
    }
}

impl AdminConfig {
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

const fn default_admin_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

const fn default_admin_port() -> u16 {
    9090
}

/// The user facing application config
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub struct XlbConfig {
    /// Optional service name attached to OTEL metrics.
    /// Defaults to "xlb" when omitted.
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
    /// orphaned. Values below five minutes are raised
    /// to five minutes at startup.
    #[serde(default = "default_orphan_ttl_secs")]
    pub orphan_ttl_secs: u32,
    /// Reactive grace period after a shutdown signal.
    /// Matching TCP packets that arrive during this
    /// window receive a reset before XLB exits.
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout: u32,
    /// Optional OpenTelemetry metrics configuration
    #[serde(default)]
    pub otel: Option<OtelConfig>,
    /// Local health, readiness, and administrative status API.
    #[serde(default)]
    pub admin: AdminConfig,
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
        let mut config = Config::builder()
            .add_source(config::File::from(path.to_path_buf()))
            .build()?
            .try_deserialize::<XlbConfig>()?;

        if config.ports.is_empty() || config.ports.len() > 8 {
            bail!("Number of port mappings must be between 1 and 8");
        }

        config.validate_supported()?;
        config.orphan_ttl_secs = normalize_orphan_ttl_secs(config.orphan_ttl_secs);

        Ok(config)
    }

    fn validate_supported(&self) -> Result<()> {
        if self.admin.port == 0 {
            bail!("Admin API port must be between 1 and 65535");
        }

        if self.proto != Proto::Tcp {
            bail!("Unsupported protocol 'udp': XLB currently supports only IPv4/TCP");
        }
        if self.mode != RoutingMode::Nat {
            bail!("Unsupported routing mode 'dsr': XLB currently supports only NAT");
        }

        if let ListenAddr::Ip(value) = &self.listen {
            let listen_ip = value.parse::<IpAddr>()?;
            self.validate_listen_ip(listen_ip)?;
        }

        if let BackendSource::Static { backends } = &self.provider
            && let Some(backend) = backends.iter().find(|backend| backend.ip.is_ipv6())
        {
            bail!(
                "Unsupported IPv6 backend '{}' ({}): XLB currently supports only IPv4 backends",
                backend.name,
                backend.ip
            );
        }

        Ok(())
    }

    /// Validate an explicitly configured or auto-detected listen address.
    pub(crate) fn validate_listen_ip(&self, listen_ip: IpAddr) -> Result<()> {
        if listen_ip.is_ipv6() {
            bail!(
                "Unsupported IPv6 listen address '{}': XLB currently supports only IPv4/TCP",
                listen_ip
            );
        }
        Ok(())
    }
}

fn normalize_orphan_ttl_secs(orphan_ttl_secs: u32) -> u32 {
    if orphan_ttl_secs < MIN_ORPHAN_TTL_SECS {
        log::warn!(
            "orphan_ttl_secs={} is below the safe minimum; enforcing {} seconds (5 minutes)",
            orphan_ttl_secs,
            MIN_ORPHAN_TTL_SECS
        );
        MIN_ORPHAN_TTL_SECS
    } else {
        orphan_ttl_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::schema_for;
    use std::fs;

    const MINIMAL_CONFIG: &str = r#"
name: config-test
listen: auto
proto: tcp
ports:
  - local_port: 80
    remote_port: 8080
provider:
  static:
    backends:
      - name: backend-1
        ip: 127.0.0.1
mode: nat
shutdown_timeout: 15
"#;

    fn load_test_config(name: &str, yaml: &str) -> Result<XlbConfig> {
        let path = std::env::temp_dir().join(format!(
            "xlb-{name}-{}-{}.yaml",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        fs::write(&path, yaml).expect("write test config");
        let result = XlbConfig::load(path.clone());
        fs::remove_file(path).expect("remove test config");
        result
    }

    #[test]
    fn schema_allows_values_below_effective_orphan_ttl_minimum() {
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
            Some(0.0)
        );
    }

    #[test]
    fn raises_orphan_ttl_below_five_minutes() {
        assert_eq!(
            normalize_orphan_ttl_secs(MIN_ORPHAN_TTL_SECS - 1),
            MIN_ORPHAN_TTL_SECS
        );
    }

    #[test]
    fn preserves_orphan_ttl_at_or_above_five_minutes() {
        assert_eq!(
            normalize_orphan_ttl_secs(MIN_ORPHAN_TTL_SECS),
            MIN_ORPHAN_TTL_SECS
        );
        assert_eq!(normalize_orphan_ttl_secs(900), 900);
    }

    #[test]
    fn load_raises_orphan_ttl_below_five_minutes() {
        let yaml = format!("{MINIMAL_CONFIG}\norphan_ttl_secs: 299\n");
        let config = load_test_config("short-orphan-ttl", &yaml)
            .expect("short orphan TTL must be normalized during config loading");

        assert_eq!(config.orphan_ttl_secs, MIN_ORPHAN_TTL_SECS);
    }

    #[test]
    fn load_defaults_orphan_ttl_to_five_minutes() {
        let config = load_test_config("default-orphan-ttl", MINIMAL_CONFIG)
            .expect("config without orphan TTL must load");

        assert_eq!(config.orphan_ttl_secs, MIN_ORPHAN_TTL_SECS);
    }

    #[test]
    fn load_defaults_admin_api_to_localhost() {
        let config =
            load_test_config("default-admin", MINIMAL_CONFIG).expect("minimal config must load");

        assert_eq!(config.admin.address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(config.admin.port, 9090);
        assert_eq!(
            config.admin.socket_addr(),
            "127.0.0.1:9090".parse().expect("valid socket address")
        );
    }

    #[test]
    fn load_rejects_zero_admin_port() {
        let yaml = format!("{MINIMAL_CONFIG}\nadmin:\n  port: 0\n");
        let error = load_test_config("zero-admin-port", &yaml)
            .expect_err("port zero would make the advertised endpoint unstable");

        assert!(error.to_string().contains("Admin API port"));
    }

    #[test]
    fn load_rejects_unsupported_protocol_and_routing_mode() {
        let udp = MINIMAL_CONFIG.replace("proto: tcp", "proto: udp");
        let udp_error = load_test_config("udp", &udp).expect_err("UDP must fail fast");
        assert!(udp_error.to_string().contains("Unsupported protocol 'udp'"));

        let dsr = MINIMAL_CONFIG.replace("mode: nat", "mode: dsr");
        let dsr_error = load_test_config("dsr", &dsr).expect_err("DSR must fail fast");
        assert!(
            dsr_error
                .to_string()
                .contains("Unsupported routing mode 'dsr'")
        );
    }

    #[test]
    fn load_rejects_explicit_ipv6_listen_and_static_backend() {
        let ipv6_listen = MINIMAL_CONFIG.replace("listen: auto", "listen:\n  ip: \"2001:db8::10\"");
        let listen_error = load_test_config("ipv6-listen", &ipv6_listen)
            .expect_err("IPv6 listener must fail fast");
        assert!(
            listen_error
                .to_string()
                .contains("Unsupported IPv6 listen address")
        );

        let ipv6_backend = MINIMAL_CONFIG.replace("127.0.0.1", "2001:db8::20");
        let backend_error = load_test_config("ipv6-backend", &ipv6_backend)
            .expect_err("IPv6 backend must fail fast");
        assert!(
            backend_error
                .to_string()
                .contains("Unsupported IPv6 backend 'backend-1'")
        );
    }

    #[test]
    fn runtime_listen_validation_catches_ipv6_auto_detection() {
        let config =
            load_test_config("runtime-listen", MINIMAL_CONFIG).expect("minimal config should load");

        assert!(
            config
                .validate_listen_ip("192.0.2.10".parse().expect("valid IPv4 test address"))
                .is_ok()
        );
        assert!(
            config
                .validate_listen_ip("2001:db8::10".parse().expect("valid IPv6 test address"))
                .is_err()
        );
    }
}
