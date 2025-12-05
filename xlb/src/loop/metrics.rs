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
    /// Closed connections since last poll (rst or fin received)
    pub closed_conns: u32,
    /// Total bytes transferred since last poll
    pub bytes_transfer: u64,
    /// Total packets transferred since last poll
    pub packets_transfer: u64,
}
