use super::model::*;
use crate::config::Host;
use crate::r#loop::metrics::Metrics;
use crate::r#loop::utils::{AggregateFlowStats, LbFlowStats};
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use xlb_common::types::Backend;

pub const DEFAULT_MAX_SAMPLE_AGE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Default)]
struct CumulativeTotals {
    opened: u64,
    closed: u64,
    orphaned: u64,
    ingress_bytes: u64,
    egress_bytes: u64,
}

#[derive(Debug, Clone)]
struct Sample {
    sampled_at_unix_ms: u64,
    provider: ProviderStatus,
    directional_flow_entries: u64,
    flow_map_complete: bool,
    connections: ConnectionStatus,
    ingress: TrafficStatus,
    egress: TrafficStatus,
    resources: ResourceStatus,
    backends: Vec<BackendStatus>,
}

#[derive(Debug)]
struct StatusInner {
    lifecycle: Lifecycle,
    sample: Option<Sample>,
    sampled_at: Option<Instant>,
    totals: CumulativeTotals,
    backend_totals: BTreeMap<IpAddr, CumulativeTotals>,
}

/// Shared, read-mostly operational state consumed by health checks and the
/// future administrative UI.
#[derive(Debug)]
pub struct StatusState {
    metadata: StatusMetadata,
    started_at: Instant,
    max_sample_age: Duration,
    inner: RwLock<StatusInner>,
}

impl StatusState {
    pub fn new(metadata: StatusMetadata) -> Self {
        Self::with_max_sample_age(metadata, DEFAULT_MAX_SAMPLE_AGE)
    }

    fn with_max_sample_age(metadata: StatusMetadata, max_sample_age: Duration) -> Self {
        Self {
            metadata,
            started_at: Instant::now(),
            max_sample_age,
            inner: RwLock::new(StatusInner {
                lifecycle: Lifecycle::Starting,
                sample: None,
                sampled_at: None,
                totals: CumulativeTotals::default(),
                backend_totals: BTreeMap::new(),
            }),
        }
    }

    pub fn mark_running(&self) {
        self.inner.write().expect("status lock poisoned").lifecycle = Lifecycle::Running;
    }

    pub fn begin_shutdown(&self) {
        self.inner.write().expect("status lock poisoned").lifecycle = Lifecycle::ShuttingDown;
    }

    pub fn publish(
        &self,
        stats: &LbFlowStats,
        discovered_hosts: &[Host],
        routable_backends: &[Backend],
        provider_healthy: bool,
    ) {
        self.publish_at(
            stats,
            discovered_hosts,
            routable_backends,
            provider_healthy,
            Instant::now(),
            unix_time_ms(),
        );
    }

    fn publish_at(
        &self,
        stats: &LbFlowStats,
        discovered_hosts: &[Host],
        routable_backends: &[Backend],
        provider_healthy: bool,
        sampled_at: Instant,
        sampled_at_unix_ms: u64,
    ) {
        let mut inner = self.inner.write().expect("status lock poisoned");
        let sample_seconds = positive_finite(stats.sample_duration_seconds);

        add_to_totals(&mut inner.totals, &stats.totals);

        let present_backend_ips: HashSet<IpAddr> = discovered_hosts
            .iter()
            .map(|host| host.ip)
            .chain(stats.backends.keys().copied().map(packed_ip))
            .collect();
        inner
            .backend_totals
            .retain(|address, _| present_backend_ips.contains(address));
        for (backend_ip, aggregate) in &stats.backends {
            add_to_totals(
                inner
                    .backend_totals
                    .entry(packed_ip(*backend_ip))
                    .or_default(),
                aggregate,
            );
        }

        let connections = connection_status(&stats.totals, sample_seconds, &inner.totals);
        let ingress = traffic_status(
            &stats.totals.to_server,
            sample_seconds,
            inner.totals.ingress_bytes,
        );
        let egress = traffic_status(
            &stats.totals.to_client,
            sample_seconds,
            inner.totals.egress_bytes,
        );
        let backends = backend_statuses(
            stats,
            discovered_hosts,
            routable_backends,
            sample_seconds,
            &inner.backend_totals,
        );
        let discovered_backends = backends.iter().filter(|backend| backend.discovered).count();
        let routable_backends = backends
            .iter()
            .filter(|backend| backend.available_for_new_connections)
            .count();

        inner.sample = Some(Sample {
            sampled_at_unix_ms,
            provider: ProviderStatus {
                kind: self.metadata.provider,
                healthy: provider_healthy,
                discovered_backends,
                routable_backends,
            },
            directional_flow_entries: stats.flow_map_entries,
            flow_map_complete: stats.flow_map_complete,
            connections,
            ingress,
            egress,
            resources: stats.resource_utilization.into(),
            backends,
        });
        inner.sampled_at = Some(sampled_at);
    }

    pub fn readiness(&self) -> ReadinessStatus {
        let now = Instant::now();
        let inner = self.inner.read().expect("status lock poisoned");
        readiness(
            inner.lifecycle,
            inner.sample.as_ref(),
            sample_age(&inner, now),
            self.max_sample_age,
        )
    }

    pub fn health(&self) -> HealthStatus {
        let now = Instant::now();
        let inner = self.inner.read().expect("status lock poisoned");
        health(
            inner.lifecycle,
            inner.sample.as_ref(),
            sample_age(&inner, now),
            now.saturating_duration_since(self.started_at),
            self.max_sample_age,
        )
    }

    pub fn snapshot(&self) -> StatusSnapshot {
        self.snapshot_at(Instant::now())
    }

    fn snapshot_at(&self, now: Instant) -> StatusSnapshot {
        let inner = self.inner.read().expect("status lock poisoned");
        let sample_age = sample_age(&inner, now);
        let readiness = readiness(
            inner.lifecycle,
            inner.sample.as_ref(),
            sample_age,
            self.max_sample_age,
        );
        let health = health(
            inner.lifecycle,
            inner.sample.as_ref(),
            sample_age,
            now.saturating_duration_since(self.started_at),
            self.max_sample_age,
        );
        let sample = inner.sample.clone();
        let provider = sample
            .as_ref()
            .map(|sample| sample.provider.clone())
            .unwrap_or(ProviderStatus {
                kind: self.metadata.provider,
                healthy: false,
                discovered_backends: 0,
                routable_backends: 0,
            });

        StatusSnapshot {
            schema_version: STATUS_SCHEMA_VERSION,
            service: self.metadata.service.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            lifecycle: inner.lifecycle,
            uptime_seconds: now.saturating_duration_since(self.started_at).as_secs(),
            health,
            readiness,
            sampled_at_unix_ms: sample.as_ref().map(|sample| sample.sampled_at_unix_ms),
            sample_age_ms: sample_age.map(|age| age.as_millis().min(u128::from(u64::MAX)) as u64),
            provider,
            dataplane: DataplaneStatus {
                listen_address: self.metadata.listen_address,
                listen_interface: self.metadata.listen_interface.clone(),
                attached_interfaces: self.metadata.attached_interfaces.clone(),
                protocol: self.metadata.protocol,
                routing_mode: self.metadata.routing_mode,
                ports: self.metadata.ports.clone(),
                directional_flow_entries: sample
                    .as_ref()
                    .map_or(0, |sample| sample.directional_flow_entries),
                flow_map_complete: sample
                    .as_ref()
                    .is_some_and(|sample| sample.flow_map_complete),
            },
            connections: sample
                .as_ref()
                .map(|sample| sample.connections.clone())
                .unwrap_or_default(),
            ingress: sample
                .as_ref()
                .map(|sample| sample.ingress.clone())
                .unwrap_or_default(),
            egress: sample
                .as_ref()
                .map(|sample| sample.egress.clone())
                .unwrap_or_default(),
            resources: sample
                .as_ref()
                .map(|sample| sample.resources.clone())
                .unwrap_or_default(),
            backends: sample.map_or_else(Vec::new, |sample| sample.backends),
        }
    }
}

fn sample_age(inner: &StatusInner, now: Instant) -> Option<Duration> {
    inner
        .sampled_at
        .map(|sampled_at| now.saturating_duration_since(sampled_at))
}

fn health(
    lifecycle: Lifecycle,
    sample: Option<&Sample>,
    sample_age: Option<Duration>,
    uptime: Duration,
    max_sample_age: Duration,
) -> HealthStatus {
    let reason = match lifecycle {
        Lifecycle::Starting => HealthReason::Starting,
        Lifecycle::ShuttingDown => HealthReason::ShuttingDown,
        Lifecycle::Running => match (sample, sample_age) {
            (None, _) | (_, None) if uptime > max_sample_age => HealthReason::DataplaneSampleStale,
            (None, _) | (_, None) => HealthReason::Starting,
            (_, Some(age)) if age > max_sample_age => HealthReason::DataplaneSampleStale,
            (Some(sample), _) if !sample.provider.healthy => HealthReason::BackendProviderUnhealthy,
            (Some(_), _) => HealthReason::Healthy,
        },
    };

    HealthStatus {
        healthy: matches!(
            reason,
            HealthReason::Healthy | HealthReason::Starting | HealthReason::ShuttingDown
        ),
        reason,
    }
}

fn readiness(
    lifecycle: Lifecycle,
    sample: Option<&Sample>,
    sample_age: Option<Duration>,
    max_sample_age: Duration,
) -> ReadinessStatus {
    let reason = match lifecycle {
        Lifecycle::Starting => ReadinessReason::Starting,
        Lifecycle::ShuttingDown => ReadinessReason::ShuttingDown,
        Lifecycle::Running => match (sample, sample_age) {
            (None, _) | (_, None) => ReadinessReason::AwaitingDataplaneSample,
            (_, Some(age)) if age > max_sample_age => ReadinessReason::DataplaneSampleStale,
            (Some(sample), _) if !sample.provider.healthy => {
                ReadinessReason::BackendProviderUnhealthy
            }
            (Some(sample), _) if sample.provider.routable_backends == 0 => {
                ReadinessReason::NoRoutableBackends
            }
            (Some(_), _) => ReadinessReason::Ready,
        },
    };

    ReadinessStatus {
        ready: reason == ReadinessReason::Ready,
        reason,
    }
}

fn backend_statuses(
    stats: &LbFlowStats,
    discovered_hosts: &[Host],
    routable_backends: &[Backend],
    sample_seconds: f64,
    backend_totals: &BTreeMap<IpAddr, CumulativeTotals>,
) -> Vec<BackendStatus> {
    let routable: HashSet<IpAddr> = routable_backends
        .iter()
        .map(|backend| packed_ip(backend.ip))
        .collect();
    let mut backends = BTreeMap::new();

    for host in discovered_hosts {
        backends.entry(host.ip).or_insert_with(|| BackendStatus {
            name: host.name.clone(),
            address: host.ip,
            discovered: true,
            available_for_new_connections: routable.contains(&host.ip),
            connections: ConnectionStatus::default(),
            ingress: TrafficStatus::default(),
            egress: TrafficStatus::default(),
        });
    }

    for (backend_ip, aggregate) in &stats.backends {
        let address = packed_ip(*backend_ip);
        let backend = backends.entry(address).or_insert_with(|| BackendStatus {
            name: address.to_string(),
            address,
            discovered: false,
            available_for_new_connections: false,
            connections: ConnectionStatus::default(),
            ingress: TrafficStatus::default(),
            egress: TrafficStatus::default(),
        });
        let totals = backend_totals.get(&address).cloned().unwrap_or_default();
        backend.connections = connection_status(aggregate, sample_seconds, &totals);
        backend.ingress =
            traffic_status(&aggregate.to_server, sample_seconds, totals.ingress_bytes);
        backend.egress = traffic_status(&aggregate.to_client, sample_seconds, totals.egress_bytes);
    }

    backends.into_values().collect()
}

fn add_to_totals(totals: &mut CumulativeTotals, aggregate: &AggregateFlowStats) {
    totals.opened = totals
        .opened
        .saturating_add(u64::from(aggregate.to_server.new_conns));
    totals.closed = totals
        .closed
        .saturating_add(u64::from(aggregate.to_server.closed_total_conns))
        .saturating_add(u64::from(aggregate.to_client.closed_total_conns));
    totals.orphaned = totals
        .orphaned
        .saturating_add(u64::from(aggregate.to_server.orphaned_conns));
    totals.ingress_bytes = totals
        .ingress_bytes
        .saturating_add(aggregate.to_server.bytes_transferred);
    totals.egress_bytes = totals
        .egress_bytes
        .saturating_add(aggregate.to_client.bytes_transferred);
}

fn connection_status(
    aggregate: &AggregateFlowStats,
    sample_seconds: f64,
    totals: &CumulativeTotals,
) -> ConnectionStatus {
    let closed = u64::from(aggregate.to_server.closed_total_conns)
        .saturating_add(u64::from(aggregate.to_client.closed_total_conns));
    ConnectionStatus {
        active: aggregate.to_server.active_conns,
        active_clients: aggregate.to_server.active_clients,
        opened_per_second: rate(aggregate.to_server.new_conns.into(), sample_seconds),
        opened_total: totals.opened,
        closed_per_second: rate(closed, sample_seconds),
        closed_total: totals.closed,
        orphaned_per_second: rate(aggregate.to_server.orphaned_conns.into(), sample_seconds),
        orphaned_total: totals.orphaned,
    }
}

fn traffic_status(metrics: &Metrics, sample_seconds: f64, bytes_total: u64) -> TrafficStatus {
    TrafficStatus {
        packets_per_second: finite_or_zero(metrics.packets_per_second),
        megabits_per_second: finite_or_zero(metrics.bandwidth_mbps),
        bytes_per_second: rate(metrics.bytes_transferred, sample_seconds),
        bytes_total,
    }
}

fn rate(value: u64, seconds: f64) -> f64 {
    finite_or_zero(value as f64 / positive_finite(seconds))
}

fn positive_finite(value: f64) -> f64 {
    if value.is_finite() && value > 0.0 {
        value
    } else {
        1.0
    }
}

fn finite_or_zero(value: f64) -> f64 {
    if value.is_finite() { value } else { 0.0 }
}

fn packed_ip(ip: u128) -> IpAddr {
    if ip <= u128::from(u32::MAX) {
        IpAddr::V4(Ipv4Addr::from(ip as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(ip))
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests;
