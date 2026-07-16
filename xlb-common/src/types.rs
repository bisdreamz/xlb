use crate::net::IpVersion;
use serde::Deserialize;
use strum::IntoStaticStr;

#[cfg(feature = "user")]
use schemars::JsonSchema;

/// Generic port mapping struct representing
/// a port on the local machine and a port
/// on some remote host
#[repr(C)]
#[derive(Debug, Clone, Copy, Deserialize)]
#[cfg_attr(feature = "user", derive(JsonSchema))]
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
#[derive(Debug, Clone, Copy, Default)]
pub struct Backend {
    /// IP address of the backend packed into a u128 which
    /// can be ipv4 or ipv6
    pub ip: u128,
    pub src_iface_ip: u128,
    /// Aggregate count of bytes transferred
    /// across live connections
    pub bytes_transfer: u64,
    pub src_iface_mac: [u8; 6],
    pub next_hop_mac: [u8; 6],
    pub src_iface_ifindex: u16,
    /// Aggregate count of live connections
    pub conns: u16,
    /// The ip protovol ver
    pub ip_ver: IpVersion,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Backend {}

/// Denotes the directional flow of a packet
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoStaticStr)]
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
/// the details of a connection.
///
/// Field order is part of the userspace/eBPF map ABI and deliberately avoids
/// implicit padding. Keep the size/offset assertions in sync with any change.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Flow {
    /// The original client IP the external
    /// request associated with this flow
    pub client_ip: u128,
    /// The backend IP of the node associated
    /// with this flow
    pub backend_ip: u128,
    /// The source IP value of the out iface
    /// used to reach the dst_ip.
    /// This may not  be the load balancer primary IP in
    /// cases where a different iface is needed
    /// to reach the destination route
    pub src_ip: u128,
    /// The destination IP value of the packet.
    /// When ToClient this is the original client IP.
    /// When ToServer this is the selected backend IP.
    pub dst_ip: u128,
    /// Counter of total bytes transferred across this flow
    /// for its lifetime
    pub bytes_transfer: u64,
    /// Counter of total packets transferred across this flow
    pub packets_transfer: u64,
    /// Monotonic timestamp for when this
    /// flow was created if value > 0
    pub created_at_ns: u64,
    /// Monotonic timestamp of the last packet
    /// seen on this flow
    pub last_seen_ns: u64,
    /// Monotonic timestamp for when
    /// both sides of the flow finalized
    /// bidirectional fin. Value > 0
    /// indicates this connection has
    /// been gracefully closed
    pub fin_both_ns: u64,
    /// Monotonic timestamp for when this flow received
    /// an RST from either side. If > 0, conn is dead
    pub rst_ns: u64,
    /// Exact key for this flow's counterpart in the flow map,
    /// e.g. if this is a ToServer flow then counter key
    /// identifies the corresponding ToClient flow.
    pub counter_flow_key: FlowKeyV4,
    /// Direction of this flow which denotes
    /// the destination for this packet
    pub direction: FlowDirection,
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
    /// The interface index which must be used
    /// in the XDP_TRANSFER call to reach the
    /// destination, since this may require
    /// a different interface than the data was
    /// received on
    pub src_iface_idx: u16,
    /// The destination MAC address of the packet.
    pub dst_mac: [u8; 6],
    /// The MAC address of the interface
    /// this packet should be sent out on
    pub src_mac: [u8; 6],
    /// Whether a fin has been received from
    /// this side of the flow yet
    pub fin: bool,
    /// True if this side of the flow was the
    /// first fin source, e.g. initiated the close
    pub fin_is_src: bool,
    /// If true and rst_ns > 0, this side of the flow
    /// was the cause of unhappy closure
    pub rst_is_src: bool,
    /// The eBPF path observed a missing counterpart while closing this flow.
    pub pair_invalid: bool,
    /// Both directional entries have been installed and may be reused.
    pub pair_ready: bool,
    /// Explicit bytes keep the following pair tag aligned without implicit,
    /// potentially uninitialized padding.
    #[doc(hidden)]
    pub _reserved: [u8; 1],
    /// Generation shared by both directional entries of this flow pair.
    pub pair_tag: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Flow {}

const _: [(); 160] = [(); core::mem::size_of::<Flow>()];
const _: [(); 16] = [(); core::mem::align_of::<Flow>()];

/// Exact, fixed-layout identity for an IPv4 TCP flow direction.
///
/// Private fields require construction through [`FlowKeyV4::tcp`], which sets
/// the protocol/direction namespace and initializes every reserved byte.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKeyV4 {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    direction: u8,
    reserved: [u8; 2],
}

impl FlowKeyV4 {
    const TCP_PROTOCOL: u8 = 6;

    pub const fn tcp(
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        direction: FlowDirection,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: Self::TCP_PROTOCOL,
            direction: match direction {
                FlowDirection::ToClient => 0,
                FlowDirection::ToServer => 1,
            },
            reserved: [0; 2],
        }
    }

    /// Destination port encoded in this directional tuple.
    pub const fn dst_port(&self) -> u16 {
        self.dst_port
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKeyV4 {}

const _: [(); 16] = [(); core::mem::size_of::<FlowKeyV4>()];
const _: [(); 4] = [(); core::mem::align_of::<FlowKeyV4>()];

#[cfg(test)]
mod tests {
    use super::{Flow, FlowDirection, FlowKeyV4};

    #[test]
    fn flow_has_padding_free_stable_layout() {
        assert_eq!(core::mem::size_of::<Flow>(), 160);
        assert_eq!(core::mem::align_of::<Flow>(), 16);
        assert_eq!(core::mem::offset_of!(Flow, client_ip), 0);
        assert_eq!(core::mem::offset_of!(Flow, backend_ip), 16);
        assert_eq!(core::mem::offset_of!(Flow, src_ip), 32);
        assert_eq!(core::mem::offset_of!(Flow, dst_ip), 48);
        assert_eq!(core::mem::offset_of!(Flow, bytes_transfer), 64);
        assert_eq!(core::mem::offset_of!(Flow, packets_transfer), 72);
        assert_eq!(core::mem::offset_of!(Flow, created_at_ns), 80);
        assert_eq!(core::mem::offset_of!(Flow, last_seen_ns), 88);
        assert_eq!(core::mem::offset_of!(Flow, fin_both_ns), 96);
        assert_eq!(core::mem::offset_of!(Flow, rst_ns), 104);
        assert_eq!(core::mem::offset_of!(Flow, counter_flow_key), 112);
        assert_eq!(core::mem::offset_of!(Flow, direction), 128);
        assert_eq!(core::mem::offset_of!(Flow, src_port), 132);
        assert_eq!(core::mem::offset_of!(Flow, dst_port), 134);
        assert_eq!(core::mem::offset_of!(Flow, src_iface_idx), 136);
        assert_eq!(core::mem::offset_of!(Flow, dst_mac), 138);
        assert_eq!(core::mem::offset_of!(Flow, src_mac), 144);
        assert_eq!(core::mem::offset_of!(Flow, fin), 150);
        assert_eq!(core::mem::offset_of!(Flow, fin_is_src), 151);
        assert_eq!(core::mem::offset_of!(Flow, rst_is_src), 152);
        assert_eq!(core::mem::offset_of!(Flow, pair_invalid), 153);
        assert_eq!(core::mem::offset_of!(Flow, pair_ready), 154);
        assert_eq!(core::mem::offset_of!(Flow, _reserved), 155);
        assert_eq!(core::mem::offset_of!(Flow, pair_tag), 156);
    }

    #[test]
    fn flow_key_v4_has_stable_layout() {
        assert_eq!(core::mem::size_of::<FlowKeyV4>(), 16);
        assert_eq!(core::mem::align_of::<FlowKeyV4>(), 4);
        assert_eq!(core::mem::offset_of!(FlowKeyV4, src_ip), 0);
        assert_eq!(core::mem::offset_of!(FlowKeyV4, dst_ip), 4);
        assert_eq!(core::mem::offset_of!(FlowKeyV4, src_port), 8);
        assert_eq!(core::mem::offset_of!(FlowKeyV4, dst_port), 10);
        assert_eq!(core::mem::offset_of!(FlowKeyV4, protocol), 12);
        assert_eq!(core::mem::offset_of!(FlowKeyV4, direction), 13);
        assert_eq!(core::mem::offset_of!(FlowKeyV4, reserved), 14);
    }

    #[test]
    fn flow_key_v4_preserves_complete_tuple_identity() {
        let base = FlowKeyV4::tcp(
            0x0102_0304,
            0x0a00_0001,
            50_000,
            80,
            FlowDirection::ToServer,
        );
        // This tuple collided with `base` under the former
        // `ip * 31 + port` application-level hash.
        let different_client = FlowKeyV4::tcp(
            0x0102_0305,
            0x0a00_0001,
            49_969,
            80,
            FlowDirection::ToServer,
        );
        let different_service = FlowKeyV4::tcp(
            0x0102_0304,
            0x0a00_0001,
            50_000,
            443,
            FlowDirection::ToServer,
        );
        let different_vip = FlowKeyV4::tcp(
            0x0102_0304,
            0x0a00_0002,
            50_000,
            80,
            FlowDirection::ToServer,
        );
        let different_direction = FlowKeyV4::tcp(
            0x0102_0304,
            0x0a00_0001,
            50_000,
            80,
            FlowDirection::ToClient,
        );

        assert_ne!(base, different_client);
        assert_ne!(base, different_service);
        assert_ne!(base, different_vip);
        assert_ne!(base, different_direction);
        assert_eq!(different_direction.direction, 0);
    }

    #[test]
    fn flow_key_v4_constructor_initializes_every_namespace_field() {
        let key = FlowKeyV4::tcp(
            0xc000_0201,
            0xc633_6402,
            50_000,
            443,
            FlowDirection::ToServer,
        );

        assert_eq!(key.src_ip, 0xc000_0201);
        assert_eq!(key.dst_ip, 0xc633_6402);
        assert_eq!(key.src_port, 50_000);
        assert_eq!(key.dst_port, 443);
        assert_eq!(key.protocol, 6);
        assert_eq!(key.direction, 1);
        assert_eq!(key.reserved, [0; 2]);
    }
}
