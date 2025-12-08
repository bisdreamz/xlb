use crate::r#loop::metrics::Metrics;
use std::collections::{HashMap, HashSet};
use xlb_common::types::FlowDirection::ToClient;
use xlb_common::types::{Flow, FlowDirection};


#[derive(Debug, Clone, Default)]
pub struct AggregateFlowStats {
    pub (crate) client_set: HashSet<u128>,
    pub to_server: Metrics,
    pub to_client: Metrics,
}

#[derive(Debug, Clone, Default)]
pub struct LbFlowStats {
    pub totals: AggregateFlowStats,
    pub backends: HashMap<u128, AggregateFlowStats>,
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

fn add_flow_stats(flow: &Flow, metrics: &mut Metrics, direction: &FlowDirection, event_ns: u64) {
    if flow.created_at_ns > event_ns {
        metrics.new_conns += 1;
    } else if flow.fin_ns > event_ns && flow.fin_is_src {
        match direction {
            ToClient => metrics.closed_fin_by_server += 1,
            FlowDirection::ToServer => metrics.closed_fin_by_client += 1,
        }

        if flow.fin_both_sides_closed {
            metrics.closed_total_conns += 1;
        }
    } else if flow.rst {
        match direction {
            ToClient => metrics.closed_rsts_by_server += 1,
            FlowDirection::ToServer => metrics.closed_rsts_by_client += 1,
        }

        metrics.closed_total_conns += 1;
    } else {
        metrics.active_conns += 1;
    }

    metrics.bytes_transfer += flow.bytes_transfer;
    metrics.packets_transfer += flow.packets_transfer;
}

/// Aggregates stats for inbound requests (ToServer)
/// by backend and total
/// Returns (totals, mapped per backend ip) tuple
pub fn aggregate_flow_stats<'a>(
    event_ns: u64,
    flows: impl Iterator<Item = (u64, Flow)>,
) -> LbFlowStats {
    let mut backends_map = HashMap::new();
    let mut totals = AggregateFlowStats::default();

    for (_, flow) in flows {
        let backend = backends_map
            .entry(flow.backend_ip)
            .or_insert_with(|| AggregateFlowStats::default());

        if flow.direction == ToClient {
            add_flow_stats(&flow, &mut totals.to_client, &flow.direction, event_ns);
            add_flow_stats(&flow, &mut backend.to_client, &flow.direction, event_ns);

            continue;
        }

        add_flow_stats(&flow, &mut totals.to_server, &flow.direction, event_ns);
        add_flow_stats(&flow, &mut backend.to_server, &flow.direction, event_ns);

        totals.add_client(flow.client_ip);
        backend.add_client(flow.client_ip);
    }

    LbFlowStats {
        totals,
        backends: backends_map
    }
}

/// Returns a new Metrics object which
/// retains the total metrics (conns) but
/// calculates deltas for curr-prev for the
/// transfer metrics
fn merge_metrics_calc_deltas(prev: &Metrics, curr: &Metrics) -> Metrics {
    let mut deltas = Metrics::default();

    deltas.active_conns = curr.active_clients;
    deltas.new_conns = curr.new_conns;
    deltas.closed_total_conns = curr.closed_total_conns;
    deltas.closed_fin_by_client = curr.closed_fin_by_client;
    deltas.closed_fin_by_server = curr.closed_fin_by_server;
    deltas.closed_rsts_by_client = curr.closed_rsts_by_client;
    deltas.closed_rsts_by_server = curr.closed_rsts_by_server;

    deltas.bytes_transfer = curr.bytes_transfer.saturating_sub(prev.bytes_transfer);
    deltas.packets_transfer = curr.packets_transfer.saturating_sub(prev.packets_transfer);

    deltas
}

pub fn calc_aggregate_deltas(prev: &LbFlowStats, curr: &LbFlowStats) -> LbFlowStats {
    let mut deltas = LbFlowStats::default();

    deltas.totals.client_set = curr.totals.client_set.clone();
    deltas.totals.to_server = merge_metrics_calc_deltas(&prev.totals.to_server, &curr.totals.to_server);
    deltas.totals.to_client = merge_metrics_calc_deltas(&prev.totals.to_client, &curr.totals.to_client);

    let empty_backend = AggregateFlowStats::default();
    for (backend_ip, curr_backend) in curr.backends.iter() {
        let prev_backend = prev.backends.get(backend_ip)
            .unwrap_or(&empty_backend);

        let mut delta_backend = AggregateFlowStats::default();

        delta_backend.client_set = curr_backend.client_set.clone();
        delta_backend.to_server = merge_metrics_calc_deltas(&prev_backend.to_server, &curr_backend.to_server);
        delta_backend.to_client = merge_metrics_calc_deltas(&prev_backend.to_client, &curr_backend.to_client);

        deltas.backends.insert(*backend_ip, delta_backend);
    }

    deltas
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