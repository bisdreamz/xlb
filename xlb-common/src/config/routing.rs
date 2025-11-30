use serde::{Serialize, Deserialize};

#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    /// Packets pass through lb bi-directionally, and is compatible
    /// with all deployment environments
    Nat,
    /// Packets are distributed to backends but the client source
    /// is maintained, so the backend can skip the lb and respond
    /// directly back to the client. This requires vip configuration
    /// and arp to be disabled for the vip on the backends
    Dsr,
}
