use crate::system::ResourceUtilization;
use serde::Serialize;
use std::net::IpAddr;
use xlb_common::config::routing::RoutingMode;
use xlb_common::net::Proto;

pub const STATUS_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone)]
pub struct StatusMetadata {
    pub service: String,
    pub provider: ProviderKind,
    pub listen_address: IpAddr,
    pub listen_interface: String,
    pub xdp_attachments: Vec<XdpAttachment>,
    pub protocol: Proto,
    pub routing_mode: RoutingMode,
    pub ports: Vec<PortStatus>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum XdpAttachmentMode {
    Native,
    Generic,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct XdpAttachment {
    pub interface: String,
    pub mode: XdpAttachmentMode,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Static,
    Kubernetes,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Starting,
    Running,
    ShuttingDown,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessReason {
    Ready,
    Starting,
    ShuttingDown,
    AwaitingDataplaneSample,
    DataplaneSampleStale,
    BackendProviderUnhealthy,
    NoRoutableBackends,
}

impl ReadinessReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Starting => "starting",
            Self::ShuttingDown => "shutting_down",
            Self::AwaitingDataplaneSample => "awaiting_dataplane_sample",
            Self::DataplaneSampleStale => "dataplane_sample_stale",
            Self::BackendProviderUnhealthy => "backend_provider_unhealthy",
            Self::NoRoutableBackends => "no_routable_backends",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthReason {
    Healthy,
    Starting,
    ShuttingDown,
    DataplaneSampleStale,
    BackendProviderUnhealthy,
}

impl HealthReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Starting => "starting",
            Self::ShuttingDown => "shutting_down",
            Self::DataplaneSampleStale => "dataplane_sample_stale",
            Self::BackendProviderUnhealthy => "backend_provider_unhealthy",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HealthStatus {
    pub healthy: bool,
    pub reason: HealthReason,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReadinessStatus {
    pub ready: bool,
    pub reason: ReadinessReason,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PortStatus {
    pub listen: u16,
    pub backend: u16,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct TrafficStatus {
    pub packets_per_second: f64,
    pub megabits_per_second: f64,
    pub bytes_per_second: f64,
    pub bytes_total: u64,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct ConnectionStatus {
    pub active: u32,
    pub active_clients: u32,
    pub opened_per_second: f64,
    pub opened_total: u64,
    pub closed_per_second: f64,
    pub closed_total: u64,
    pub orphaned_per_second: f64,
    pub orphaned_total: u64,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct ResourceStatus {
    pub cpu_percent: Option<f64>,
    pub host_cpu_percent: Option<f64>,
    pub process_cpu_percent: Option<f64>,
    pub network_percent: Option<f64>,
    pub flow_map_percent: Option<f64>,
    pub overall_percent: Option<f64>,
}

impl From<ResourceUtilization> for ResourceStatus {
    fn from(value: ResourceUtilization) -> Self {
        Self {
            cpu_percent: finite(value.cpu_percent),
            host_cpu_percent: finite(value.host_cpu_percent),
            process_cpu_percent: finite(value.process_cpu_percent),
            network_percent: finite(value.network_percent),
            flow_map_percent: finite(value.flow_map_percent),
            overall_percent: finite(value.overall_percent),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BackendStatus {
    pub name: String,
    pub address: IpAddr,
    pub discovered: bool,
    pub available_for_new_connections: bool,
    pub time_in_pool_seconds: u64,
    pub connections: ConnectionStatus,
    pub ingress: TrafficStatus,
    pub egress: TrafficStatus,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProviderStatus {
    pub kind: ProviderKind,
    pub healthy: bool,
    pub discovered_backends: usize,
    pub routable_backends: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DataplaneStatus {
    pub listen_address: IpAddr,
    pub listen_interface: String,
    pub attached_interfaces: Vec<String>,
    pub xdp_attachments: Vec<XdpAttachment>,
    pub protocol: Proto,
    pub routing_mode: RoutingMode,
    pub ports: Vec<PortStatus>,
    pub directional_flow_entries: u64,
    pub flow_map_complete: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StatusSnapshot {
    pub schema_version: u16,
    pub service: String,
    pub version: String,
    pub lifecycle: Lifecycle,
    pub uptime_seconds: u64,
    pub health: HealthStatus,
    pub readiness: ReadinessStatus,
    pub sampled_at_unix_ms: Option<u64>,
    pub sample_age_ms: Option<u64>,
    pub provider: ProviderStatus,
    pub dataplane: DataplaneStatus,
    pub connections: ConnectionStatus,
    pub ingress: TrafficStatus,
    pub egress: TrafficStatus,
    pub resources: ResourceStatus,
    pub backends: Vec<BackendStatus>,
}

fn finite(value: Option<f64>) -> Option<f64> {
    value.filter(|value| value.is_finite())
}
