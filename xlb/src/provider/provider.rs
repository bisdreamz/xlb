use crate::system;
use anyhow::Result;
use async_trait::async_trait;
use log::trace;
use serde::Deserialize;
use std::net::IpAddr;
use xlb_common::net::IpVersion;
use xlb_common::types::Backend;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
pub struct Host {
    pub name: String,
    pub ip: IpAddr,
}

/// Responsible for maintaining a live list of
/// backend nodes traffic should be routed to.
#[async_trait]
pub trait BackendProvider: Send + Sync {
    /// Start the provider monitoring for changes
    async fn start(&self) -> Result<()>;

    /// Get the current list of backends
    fn get_backends(&self) -> Vec<Host>;

    /// Shutdown the provider
    async fn shutdown(&self) -> Result<()>;
}

impl From<&Host> for Backend {
    fn from(value: &Host) -> Self {
        let (ip, ver) = match value.ip {
            IpAddr::V4(ip) => (ip.to_bits() as u128, IpVersion::Ipv4),
            IpAddr::V6(ip) => (ip.to_bits(), IpVersion::Ipv6),
        };

        Backend {
            ip,
            ip_ver: ver,
            src_iface_ip: 0,
            src_iface_mac: [0; 6],
            next_hop_mac: [0; 6],
            src_iface_ifindex: 0,
            conns: 0,
            bytes_transfer: 0,
        }
    }
}

/// Converts hosts to backends with routing information populated by
/// performing kernel route and neighbor lookups for each backend.
/// Skips backends that cannot be reached and logs warnings.
pub async fn hosts_to_backends_with_routes(hosts: &[Host]) -> Vec<Backend> {
    let mut backends = Vec::new();

    for host in hosts {
        let mut backend = Backend::from(host);

        match system::populate_backend_route(&mut backend).await {
            Ok(()) => {
                trace!("Backend {} ({}) ready: ifindex={}", host.name, host.ip, backend.src_iface_ifindex);
                backends.push(backend);
            }
            Err(e) => {
                log::warn!("Skipping unreachable backend {} ({}): {}", host.name, host.ip, e);
            }
        }
    }

    backends
}
