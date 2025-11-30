use xlb_common::config::ebpf::{ListenProto, PortMapping};
use xlb_common::config::net::ListenAddr;

#[derive(Debug, Clone)]
pub enum BackendProvider {
    Static { backends: Vec<String> },
    Kubernetes { namespace: String, service: String },
}

/// The user facing application config
#[derive(Debug, Clone)]
pub struct XlbConfig {
    /// Optional name to attach to future otel metrics,
    /// if not provided defaults to kube service name
    /// or static-lb for static deployments
    name: Option<String>,
    listen: ListenAddr,
    proto: ListenProto,
    ports: PortMapping,
    provider: BackendProvider,
}
