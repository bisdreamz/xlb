use crate::r#loop::metrics::Metrics;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use xlb_common::types::FlowDirection::ToClient;
use xlb_common::types::{Flow, FlowDirection};

#[derive(Debug, Clone, Default)]
pub struct AggregateFlowStats {
    pub(crate) client_set: HashSet<u128>,
    pub to_server: Metrics,
    pub to_client: Metrics,
}

#[derive(Debug, Clone, Default)]
pub struct LbFlowStats {
    pub totals: AggregateFlowStats,
    pub backends: HashMap<u128, AggregateFlowStats>,
    /// Number of available backends from provider
    pub available_backends: u32,
}

impl AggregateFlowStats {
    fn add_client(&mut self, client_ip: u128) {
        self.client_set.insert(client_ip);
    }

    #[allow(dead_code)]
    fn clients_count(&self) -> u32 {
        self.client_set.len() as u32
    }
}

fn add_flow_stats(
    flow: &Flow,
    metrics: &mut Metrics,
    direction: &FlowDirection,
    conn_is_new: bool,
    conn_is_rst: bool,
    conn_is_fin: bool,
    conn_is_orphan: bool,
    conn_is_active: bool,
) {
    if conn_is_new {
        metrics.new_conns += 1;
    }

    if conn_is_fin && flow.fin_is_src {
        match direction {
            ToClient => metrics.closed_fin_by_server += 1,
            FlowDirection::ToServer => metrics.closed_fin_by_client += 1,
        }

        metrics.closed_total_conns += 1;
    } else if conn_is_rst && flow.rst_is_src {
        match direction {
            ToClient => metrics.closed_rsts_by_server += 1,
            FlowDirection::ToServer => metrics.closed_rsts_by_client += 1,
        }
        metrics.closed_total_conns += 1;
    } else if conn_is_orphan {
        metrics.orphaned_conns += 1;
    }

    if conn_is_active {
        metrics.active_conns += 1;
    }
}

pub fn aggregate_flow_stats<'a>(
    event_ns: u64,
    flows: impl Iterator<Item = (u64, Flow)>,
    prev_flow_stats: &HashMap<u64, (u64, u64)>,
    orphan_ttl: &Duration,
    now_ns: u64,
) -> (LbFlowStats, HashMap<u64, (u64, u64)>) {
    let mut backends_map = HashMap::new();
    let mut totals = AggregateFlowStats::default();
    let mut new_prev_flow_stats = HashMap::new();

    for (key, flow) in flows {
        let (prev_bytes, prev_packets) = prev_flow_stats.get(&key).copied().unwrap_or((0, 0));
        let delta_bytes = flow.bytes_transfer.saturating_sub(prev_bytes);
        let delta_packets = flow.packets_transfer.saturating_sub(prev_packets);

        new_prev_flow_stats.insert(key, (flow.bytes_transfer, flow.packets_transfer));

        let backend = backends_map
            .entry(flow.backend_ip)
            .or_insert_with(|| AggregateFlowStats::default());

        let is_new = flow.created_at_ns > event_ns;
        // record RSTs & FINs as they happen during our tick for metrics,
        // which may differ from when we clean them from the
        // officialy from the conn track e.g. for time wait
        let is_rst = flow.rst_ns >= event_ns && flow.rst_ns <= now_ns;
        let is_fin = flow.fin_both_ns >= event_ns && flow.fin_both_ns <= now_ns;
        let is_orphaned = is_orphan(flow.last_seen_ns, now_ns, orphan_ttl);
        let is_active = is_active(&flow) && !is_orphaned;

        if flow.direction == ToClient {
            add_flow_stats(
                &flow,
                &mut totals.to_client,
                &flow.direction,
                is_new,
                is_rst,
                is_fin,
                is_orphaned,
                is_active,
            );

            add_flow_stats(
                &flow,
                &mut backend.to_client,
                &flow.direction,
                is_new,
                is_rst,
                is_fin,
                is_orphaned,
                is_active,
            );

            totals.to_client.bytes_transfer += delta_bytes;
            totals.to_client.packets_transfer += delta_packets;
            backend.to_client.bytes_transfer += delta_bytes;
            backend.to_client.packets_transfer += delta_packets;

            continue;
        }

        add_flow_stats(
            &flow,
            &mut totals.to_server,
            &flow.direction,
            is_new,
            is_rst,
            is_fin,
            is_orphaned,
            is_active,
        );

        add_flow_stats(
            &flow,
            &mut backend.to_server,
            &flow.direction,
            is_new,
            is_rst,
            is_fin,
            is_orphaned,
            is_active,
        );

        totals.to_server.bytes_transfer += delta_bytes;
        totals.to_server.packets_transfer += delta_packets;
        backend.to_server.bytes_transfer += delta_bytes;
        backend.to_server.packets_transfer += delta_packets;

        if is_active {
            totals.add_client(flow.client_ip);
            backend.add_client(flow.client_ip);
        }
    }

    totals.to_server.active_clients = totals.client_set.len() as u32;
    totals.to_client.active_clients = totals.client_set.len() as u32;

    for backend in backends_map.values_mut() {
        backend.to_server.active_clients = backend.client_set.len() as u32;
        backend.to_client.active_clients = backend.client_set.len() as u32;
    }

    (
        LbFlowStats {
            totals,
            backends: backends_map,
            available_backends: 0,
        },
        new_prev_flow_stats,
    )
}

pub fn is_orphan(last_seen_ns: u64, now_ns: u64, orphan_ttl: &Duration) -> bool {
    Duration::from_nanos(now_ns.saturating_sub(last_seen_ns)).ge(orphan_ttl)
}

pub fn is_active(flow: &Flow) -> bool {
    flow.fin_both_ns == 0 && flow.rst_ns == 0
}

/// Returns true if RST happened at least 1 loop cycle ago (ready to count and delete)
pub fn rst_ready_for_cleanup(rst_ns: u64, last_run_ns: u64) -> bool {
    rst_ns > 0 && rst_ns < last_run_ns
}

/// Returns true if the fin both timestamp was at least time_wait duration ago
/// and both sides of the flow are marked closed
pub fn fin_ready_for_cleanup(fin_both_ns: u64, now_ns: u64, time_wait_ttl: &Duration) -> bool {
    fin_both_ns > 0 && Duration::from_nanos(now_ns.saturating_sub(fin_both_ns)).ge(&time_wait_ttl)
}

/// Gets the current monotonic timestamp in nanoseconds,
/// matching the eBPF bpf_ktime_get_ns() behavior
pub fn monotonic_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64 * 1_000_000_000) + (ts.tv_nsec as u64)
}

/// Formats a u128 IP address (IPv4 or IPv6) as a string
pub fn format_ip(ip: u128) -> String {
    use std::net::{Ipv4Addr, Ipv6Addr};

    if ip <= u32::MAX as u128 {
        Ipv4Addr::from(ip as u32).to_string()
    } else {
        Ipv6Addr::from(ip).to_string()
    }
}
