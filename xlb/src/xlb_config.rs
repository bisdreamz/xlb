use anyhow::{Result, bail};
use config::Config;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use xlb_common::config::routing::RoutingMode;
use xlb_common::net::Proto;
use xlb_common::types::PortMapping;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendProvider {
    Static { backends: Vec<String> },
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
    pub provider: BackendProvider,
    #[serde(default)]
    pub mode: RoutingMode,
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

        match &config.provider {
            BackendProvider::Static { backends } => {
                if backends.is_empty() {
                    bail!("At least one backend must be specified for static deployments");
                }

                for backend in backends {
                    let _addr = backend
                        .parse::<std::net::IpAddr>()
                        .map_err(|_| anyhow::anyhow!("Invalid backend address: {}", backend))?;
                }
            }
            _ => (),
        }

        Ok(config)
    }
}
