use crate::r#loop::metrics::Metrics;
use std::collections::{HashMap, HashSet};
use xlb_common::types::FlowDirection::ToClient;
use xlb_common::types::Flow;


#[derive(Debug, Clone, Default)]
pub struct AggregateFlowStats {
    client_set: HashSet<u128>,
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

fn add_flow_stats(flow: &Flow, metrics: &mut Metrics, event_ns: u64) {
    if flow.created_at_ns > event_ns {
        metrics.new_conns += 1;
    } else if flow.closed_at_ns > event_ns {
        metrics.closed_conns += 1;
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
            add_flow_stats(&flow, &mut totals.to_client, event_ns);
            add_flow_stats(&flow, &mut backend.to_client, event_ns);

            continue;
        }

        add_flow_stats(&flow, &mut totals.to_server, event_ns);
        add_flow_stats(&flow, &mut backend.to_server, event_ns);

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
    deltas.closed_conns = curr.closed_conns;

    deltas.bytes_transfer = curr.bytes_transfer - prev.bytes_transfer;
    deltas.packets_transfer = curr.packets_transfer - prev.packets_transfer;

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