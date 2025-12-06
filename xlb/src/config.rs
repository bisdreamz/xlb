use crate::provider::Host;
use anyhow::{Result, bail};
use config::Config;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use xlb_common::config::routing::RoutingMode;
use xlb_common::net::Proto;
use xlb_common::types::PortMapping;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendSource {
    Static { backends: Vec<Host> },
    #[allow(dead_code)]
    Kubernetes { namespace: String, service: String },
}

#[repr(C)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListenAddr {
    /// Will attach to the interface and primary ip of
    /// associated with the default network route
    #[default]
    Auto,
    /// Specify an ipv4 listen addr, also used to determine
    /// the target interface
    Ip(String),
    /// Specific interface, IP combo
    Exact {
        iface: String,
        ip: String
    }
}

/// The user facing application config
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct XlbConfig {
    /// Optional name to attach to future otel metrics,
    /// if not provided defaults to kube service name
    /// or static-lb for static deployments
    pub name: Option<String>,
    #[serde(default)]
    pub listen: ListenAddr,
    #[serde(default)]
    pub proto: Proto,
    pub ports: Vec<PortMapping>,
    pub provider: BackendSource,
    #[serde(default)]
    pub mode: RoutingMode,
    #[serde(default = "default_orphan_ttl_secs")]
    pub orphan_ttl_secs: u32,
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout: u32
}

const fn default_orphan_ttl_secs() -> u32 { 5 * 60 }
const fn default_shutdown_timeout() -> u32 { 15 }

impl XlbConfig {
    pub fn load(path: PathBuf) -> Result<XlbConfig> {
        let config = Config::builder()
            .add_source(config::File::from(path.to_path_buf()))
            .build()?
            .try_deserialize::<XlbConfig>()?;

        if config.ports.is_empty() || config.ports.len() > 8 {
            bail!("Number of port mappings must be between 1 and 8");
        }

        Ok(config)
    }
}
