/// Generic object for metrics to be exported
/// via otel, which may be aggregated
/// platform wide or by specific backends
#[derive(Debug, Clone, Default)]
pub struct Metrics {
    /// Current active clients (unique client IPs)
    pub active_clients: u32,
    /// Current active connections
    pub active_conns: u32,
    /// New connections since last poll
    pub new_conns: u32,
    /// Total closed connections regardless of source
    pub closed_total_conns: u32,
    /// Gracefully closed connections since last poll (rst or fin received)
    pub closed_fin_by_client: u32,
    pub closed_fin_by_server: u32,
    pub closed_rsts_by_client: u32,
    pub closed_rsts_by_server: u32,
    /// Orphaned connections cleaned up (idle timeout)
    pub orphaned_conns: u32,
    /// Average bandwidth in Mbps between last poll
    pub bandwidth_mbps: f64,
    /// Average packets per second between last poll
    pub packets_per_second: f64,
    /// Total bytes transferred (delta since last poll)
    pub bytes_transferred: u64,
}
