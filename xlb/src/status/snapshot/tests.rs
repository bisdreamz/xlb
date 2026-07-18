use super::*;
use crate::r#loop::utils::LbFlowStats;
use xlb_common::net::IpVersion;

fn metadata() -> StatusMetadata {
    StatusMetadata {
        service: "test-lb".into(),
        provider: ProviderKind::Kubernetes,
        listen_address: "192.0.2.10".parse().expect("valid IP"),
        listen_interface: "eth0".into(),
        xdp_attachments: vec![XdpAttachment {
            interface: "eth0".into(),
            mode: XdpAttachmentMode::Native,
        }],
        protocol: xlb_common::net::Proto::Tcp,
        routing_mode: xlb_common::config::routing::RoutingMode::Nat,
        ports: vec![PortStatus {
            listen: 80,
            backend: 8080,
        }],
    }
}

fn host(name: &str, ip: &str) -> Host {
    Host {
        name: name.into(),
        ip: ip.parse().expect("valid IP"),
    }
}

fn backend(ip: &str) -> Backend {
    let ip = match ip.parse::<IpAddr>().expect("valid IP") {
        IpAddr::V4(ip) => u128::from(u32::from(ip)),
        IpAddr::V6(ip) => u128::from(ip),
    };
    Backend {
        ip,
        ip_ver: IpVersion::Ipv4,
        ..Default::default()
    }
}

fn stats() -> LbFlowStats {
    let mut stats = LbFlowStats {
        sample_duration_seconds: 2.0,
        flow_map_complete: true,
        ..Default::default()
    };
    stats.totals.to_server.active_clients = 3;
    stats.totals.to_server.active_conns = 4;
    stats.totals.to_server.new_conns = 6;
    stats.totals.to_server.closed_total_conns = 2;
    stats.totals.to_server.orphaned_conns = 2;
    stats.totals.to_server.packets_per_second = 100.0;
    stats.totals.to_server.bandwidth_mbps = 8.0;
    stats.totals.to_server.bytes_transferred = 1_000;
    stats.totals.to_client.closed_total_conns = 2;
    stats.totals.to_client.packets_per_second = 80.0;
    stats.totals.to_client.bandwidth_mbps = 6.0;
    stats.totals.to_client.bytes_transferred = 500;
    stats
}

fn backend_status<'a>(snapshot: &'a StatusSnapshot, ip: &str) -> &'a BackendStatus {
    let address = ip.parse::<IpAddr>().expect("valid IP");
    snapshot
        .backends
        .iter()
        .find(|backend| backend.address == address)
        .expect("backend is present")
}

#[test]
fn readiness_requires_running_fresh_provider_and_routable_backend() {
    let state = StatusState::with_max_sample_age(metadata(), Duration::from_secs(5));
    assert_eq!(state.readiness().reason, ReadinessReason::Starting);

    state.mark_running();
    assert_eq!(
        state.readiness().reason,
        ReadinessReason::AwaitingDataplaneSample
    );

    state.publish(&stats(), &[host("backend-a", "10.0.0.1")], &[], true);
    assert_eq!(
        state.readiness().reason,
        ReadinessReason::NoRoutableBackends
    );
    assert_eq!(state.health().reason, HealthReason::Healthy);

    state.publish(
        &stats(),
        &[host("backend-a", "10.0.0.1")],
        &[backend("10.0.0.1")],
        false,
    );
    assert_eq!(
        state.readiness().reason,
        ReadinessReason::BackendProviderUnhealthy
    );
    assert_eq!(
        state.health().reason,
        HealthReason::BackendProviderUnhealthy
    );

    state.publish(
        &stats(),
        &[host("backend-a", "10.0.0.1")],
        &[backend("10.0.0.1")],
        true,
    );
    assert!(state.readiness().ready);

    state.begin_shutdown();
    assert_eq!(state.readiness().reason, ReadinessReason::ShuttingDown);
    assert_eq!(state.health().reason, HealthReason::ShuttingDown);
    assert!(state.health().healthy);
}

#[test]
fn stale_samples_make_running_instance_unready() {
    let state = StatusState::with_max_sample_age(metadata(), Duration::from_secs(5));
    let now = Instant::now();
    state.mark_running();
    state.publish_at(
        &stats(),
        &[host("backend-a", "10.0.0.1")],
        &[backend("10.0.0.1")],
        true,
        now,
        1,
    );

    let stale = state.snapshot_at(now + Duration::from_secs(6));
    assert_eq!(
        stale.readiness.reason,
        ReadinessReason::DataplaneSampleStale
    );
    assert_eq!(stale.health.reason, HealthReason::DataplaneSampleStale);
    assert!(!stale.health.healthy);
}

#[test]
fn snapshot_reports_rates_totals_and_unavailable_draining_backends() {
    let state = StatusState::new(metadata());
    let mut stats = stats();
    let mut draining = AggregateFlowStats::default();
    draining.to_server.active_conns = 2;
    draining.to_server.active_clients = 1;
    stats.backends.insert(u128::from(0x0a00_0002_u32), draining);

    state.mark_running();
    state.publish(
        &stats,
        &[host("backend-a", "10.0.0.1")],
        &[backend("10.0.0.1")],
        true,
    );
    let snapshot = state.snapshot();

    assert_eq!(snapshot.connections.opened_per_second, 3.0);
    assert_eq!(snapshot.connections.opened_total, 6);
    assert_eq!(snapshot.connections.closed_per_second, 2.0);
    assert_eq!(snapshot.connections.closed_total, 4);
    assert_eq!(snapshot.connections.orphaned_per_second, 1.0);
    assert_eq!(snapshot.ingress.bytes_per_second, 500.0);
    assert_eq!(snapshot.ingress.bytes_total, 1_000);
    assert_eq!(snapshot.provider.discovered_backends, 1);
    assert_eq!(snapshot.provider.routable_backends, 1);
    assert_eq!(snapshot.backends.len(), 2);
    assert!(snapshot.backends[0].available_for_new_connections);
    assert!(!snapshot.backends[1].discovered);
    assert_eq!(snapshot.backends[1].connections.active, 2);
}

#[test]
fn backend_time_in_pool_survives_draining_and_resets_after_removal() {
    let state = StatusState::new(metadata());
    let first_seen = Instant::now();
    let complete = LbFlowStats {
        sample_duration_seconds: 1.0,
        flow_map_complete: true,
        ..Default::default()
    };

    state.publish_at(
        &complete,
        &[host("backend-a", "10.0.0.1")],
        &[backend("10.0.0.1")],
        true,
        first_seen,
        1,
    );
    assert_eq!(
        backend_status(&state.snapshot_at(first_seen), "10.0.0.1").time_in_pool_seconds,
        0
    );

    let mut draining = complete.clone();
    draining
        .backends
        .insert(u128::from(0x0a00_0001_u32), AggregateFlowStats::default());
    let draining_at = first_seen + Duration::from_secs(75);
    state.publish_at(&draining, &[], &[], true, draining_at, 2);
    assert_eq!(
        backend_status(&state.snapshot_at(draining_at), "10.0.0.1").time_in_pool_seconds,
        75
    );

    let incomplete = LbFlowStats {
        sample_duration_seconds: 1.0,
        flow_map_complete: false,
        ..Default::default()
    };
    state.publish_at(
        &incomplete,
        &[],
        &[],
        true,
        first_seen + Duration::from_secs(120),
        3,
    );
    let reappeared_at = first_seen + Duration::from_secs(180);
    state.publish_at(
        &complete,
        &[host("backend-a", "10.0.0.1")],
        &[backend("10.0.0.1")],
        true,
        reappeared_at,
        4,
    );
    assert_eq!(
        backend_status(&state.snapshot_at(reappeared_at), "10.0.0.1").time_in_pool_seconds,
        180
    );

    state.publish_at(
        &complete,
        &[],
        &[],
        true,
        first_seen + Duration::from_secs(240),
        5,
    );
    let rediscovered_at = first_seen + Duration::from_secs(300);
    state.publish_at(
        &complete,
        &[host("backend-a", "10.0.0.1")],
        &[backend("10.0.0.1")],
        true,
        rediscovered_at,
        6,
    );
    assert_eq!(
        backend_status(&state.snapshot_at(rediscovered_at), "10.0.0.1").time_in_pool_seconds,
        0
    );
}

#[test]
fn backend_totals_remain_monotonic_while_a_discovered_backend_is_idle() {
    let state = StatusState::new(metadata());
    let hosts = [host("backend-a", "10.0.0.1")];
    let routable = [backend("10.0.0.1")];
    let backend_ip = u128::from(0x0a00_0001_u32);

    let mut active = LbFlowStats {
        sample_duration_seconds: 2.0,
        flow_map_complete: true,
        ..Default::default()
    };
    let mut active_backend = AggregateFlowStats::default();
    active_backend.to_server.active_conns = 2;
    active_backend.to_server.new_conns = 4;
    active_backend.to_server.closed_total_conns = 1;
    active_backend.to_server.orphaned_conns = 1;
    active_backend.to_server.bytes_transferred = 1_000;
    active_backend.to_client.closed_total_conns = 2;
    active_backend.to_client.bytes_transferred = 500;
    active.backends.insert(backend_ip, active_backend);

    state.publish(&active, &hosts, &routable, true);
    let first = state.snapshot();
    let first_backend = backend_status(&first, "10.0.0.1");
    assert_eq!(first_backend.connections.active, 2);
    assert_eq!(first_backend.connections.opened_total, 4);
    assert_eq!(first_backend.connections.closed_total, 3);
    assert_eq!(first_backend.connections.orphaned_total, 1);
    assert_eq!(first_backend.ingress.bytes_total, 1_000);
    assert_eq!(first_backend.egress.bytes_total, 500);

    let idle = LbFlowStats {
        sample_duration_seconds: 2.0,
        flow_map_complete: true,
        ..Default::default()
    };
    state.publish(&idle, &hosts, &routable, true);
    let idle_snapshot = state.snapshot();
    let idle_backend = backend_status(&idle_snapshot, "10.0.0.1");
    assert_eq!(idle_backend.connections.active, 0);
    assert_eq!(idle_backend.connections.opened_per_second, 0.0);
    assert_eq!(idle_backend.connections.opened_total, 4);
    assert_eq!(idle_backend.connections.closed_total, 3);
    assert_eq!(idle_backend.connections.orphaned_total, 1);
    assert_eq!(idle_backend.ingress.bytes_per_second, 0.0);
    assert_eq!(idle_backend.ingress.bytes_total, 1_000);
    assert_eq!(idle_backend.egress.bytes_total, 500);

    let mut reappeared = idle;
    let mut reappeared_backend = AggregateFlowStats::default();
    reappeared_backend.to_server.new_conns = 2;
    reappeared_backend.to_server.closed_total_conns = 1;
    reappeared_backend.to_server.bytes_transferred = 200;
    reappeared_backend.to_client.closed_total_conns = 1;
    reappeared_backend.to_client.bytes_transferred = 100;
    reappeared.backends.insert(backend_ip, reappeared_backend);

    state.publish(&reappeared, &hosts, &routable, true);
    let reappeared_snapshot = state.snapshot();
    let reappeared_backend = backend_status(&reappeared_snapshot, "10.0.0.1");
    assert_eq!(reappeared_backend.connections.opened_total, 6);
    assert_eq!(reappeared_backend.connections.closed_total, 5);
    assert_eq!(reappeared_backend.connections.orphaned_total, 1);
    assert_eq!(reappeared_backend.ingress.bytes_total, 1_200);
    assert_eq!(reappeared_backend.egress.bytes_total, 600);
}

#[test]
fn removing_a_backend_discards_totals_after_its_draining_flows_end() {
    let state = StatusState::new(metadata());
    let hosts = [host("backend-a", "10.0.0.1")];
    let routable = [backend("10.0.0.1")];
    let mut active = LbFlowStats {
        sample_duration_seconds: 1.0,
        flow_map_complete: true,
        ..Default::default()
    };
    let mut aggregate = AggregateFlowStats::default();
    aggregate.to_server.new_conns = 3;
    active
        .backends
        .insert(u128::from(0x0a00_0001_u32), aggregate);

    state.publish(&active, &hosts, &routable, true);
    assert_eq!(
        backend_status(&state.snapshot(), "10.0.0.1")
            .connections
            .opened_total,
        3
    );

    let mut draining = LbFlowStats {
        sample_duration_seconds: 1.0,
        flow_map_complete: true,
        ..Default::default()
    };
    draining
        .backends
        .insert(u128::from(0x0a00_0001_u32), AggregateFlowStats::default());
    state.publish(&draining, &[], &[], true);
    let draining_snapshot = state.snapshot();
    let draining_backend = backend_status(&draining_snapshot, "10.0.0.1");
    assert!(!draining_backend.discovered);
    assert_eq!(draining_backend.connections.opened_total, 3);

    let incomplete = LbFlowStats {
        sample_duration_seconds: 1.0,
        flow_map_complete: false,
        ..Default::default()
    };
    state.publish(&incomplete, &[], &[], true);
    assert!(state.snapshot().backends.is_empty());

    let mut reappeared = LbFlowStats {
        sample_duration_seconds: 1.0,
        flow_map_complete: true,
        ..Default::default()
    };
    let mut reappeared_aggregate = AggregateFlowStats::default();
    reappeared_aggregate.to_server.new_conns = 2;
    reappeared
        .backends
        .insert(u128::from(0x0a00_0001_u32), reappeared_aggregate);
    state.publish(&reappeared, &[], &[], true);
    assert_eq!(
        backend_status(&state.snapshot(), "10.0.0.1")
            .connections
            .opened_total,
        5
    );

    let idle = LbFlowStats {
        sample_duration_seconds: 1.0,
        flow_map_complete: true,
        ..Default::default()
    };
    state.publish(&idle, &[], &[], true);
    assert!(state.snapshot().backends.is_empty());

    state.publish(&idle, &hosts, &routable, true);
    assert_eq!(
        backend_status(&state.snapshot(), "10.0.0.1")
            .connections
            .opened_total,
        0
    );
}

#[test]
fn non_finite_values_never_reach_status_json() {
    let state = StatusState::new(metadata());
    let mut stats = stats();
    stats.totals.to_server.packets_per_second = f64::NAN;
    stats.resource_utilization.overall_percent = Some(f64::INFINITY);

    state.publish(
        &stats,
        &[host("backend-a", "10.0.0.1")],
        &[backend("10.0.0.1")],
        true,
    );
    let snapshot = state.snapshot();

    assert_eq!(snapshot.ingress.packets_per_second, 0.0);
    assert_eq!(snapshot.resources.overall_percent, None);
    serde_json::to_string(&snapshot).expect("status snapshot is valid JSON");
}
