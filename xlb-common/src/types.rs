use serde::Deserialize;

/// Generic port mapping struct representing
/// a port on the local machine and a port
/// on some remote host
#[repr(C)]
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct PortMapping {
    /// Port on this local machine e.g.
    /// could be the lb listen port,
    /// the source port we have assigned
    pub local_port: u16,
    /// Port on a remote host e.g.
    /// backend node service port, or a
    /// src port from a client connection
    pub remote_port: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PortMapping {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Backend {
    /// IP address of the backend packed into a u128 which
    /// can be ipv4 or ipv6
    pub ip: u128,
    /// Aggregate count of live connections
    pub conns: u16,
    /// Aggregate count of bytes transferred
    /// across live connections
    pub bytes_transfer: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Backend {}

/// Denotes the directional flow of a packet
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum FlowDirection {
    /// Flow is toward the client and the incoming
    /// data is from a backend
    ToClient,
    /// Flow is toward a backend server and incoming
    /// data is from a client
    ToServer,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowDirection {}

/// A directional connection entry, which defines
/// the verbatim rewrite recipe to properly
/// reroute a packet. This does *not* record
/// the details of a connection
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Flow {
    /// Direction of this flow which denotes
    /// the destination for this packet
    pub direction: FlowDirection,
    /// The source IP value of the out iface
    /// used to reach the dst_ip.
    /// This may not  be the load balancer primary IP in
    /// cases where a different iface is needed
    /// to reach the destination route
    pub src_ip: u128,
    /// The source port value.
    /// When direction is ToClient, this should be the
    /// original dest port of the service e.g. 80, 443.
    /// When direction is ToServer, this should be
    /// our locally assigned ephemeral port
    pub src_port: u16,
    /// The dest port value.
    /// When direction is ToClient, this should be
    /// the client's original src port.
    /// When direction is ToServer, this should be
    /// the primary service destination port e.g. 80, 443
    pub dst_port: u16,
    /// The destination IP value of the packet.
    /// When ToClient this is the original client IP.
    /// When ToServer this is the selected backend IP.
    pub dst_ip: u128,
    /// The destination MAC address of the packet.
    pub dst_mac: [u8; 6],
    /// The interface index which must be used
    /// in the XDP_TRANSFER call to reach the
    /// destination, since this may require
    /// a different interface than the data was
    /// received on
    pub src_iface_idx: u16,
    /// The MAC address of the interface
    /// this packet should be sent out on
    pub src_mac: [u8; 6],
    /// Counter of total bytes transferred across this flow
    /// for its lifetime
    pub bytes_transfer: u64,
    /// Monotonic timestamp of the last packet
    /// seen on this flow
    pub last_seen_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Flow {}
