use crate::handler::iface::Iface;

#[repr(C)]
pub struct PacketFlow {
    pub iface: Iface,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: u128,
    pub dst_ip: u128,
    pub src_port: u16,
    pub dst_port: u16,
}

impl PacketFlow {
    const EMPTY: Self = Self {
        iface: Iface::EMPTY,
        src_mac: [0; 6],
        dst_mac: [0; 6],
        src_ip: 0,
        dst_ip: 0,
        src_port: 0,
        dst_port: 0,
    };
}

/// Packet disposition selected by TCP processing.
pub enum TcpAction {
    /// Leave the packet unchanged for the kernel networking stack.
    Pass,
    /// Silently discard a packet during a transient flow-state race.
    Drop,
    /// Transmit the packet back through its ingress interface.
    Reply,
    /// Rewrite and redirect the packet using the stored flow recipe.
    Forward,
}

/// Result of TCP processing before conversion to an XDP packet event.
///
/// The flow field is initialized for every action because LLVM may copy an
/// inactive Rust enum payload before branching on its discriminant. eBPF
/// verifiers before the ~6.4 relaxation that lets privileged programs read
/// uninitialized stack slots as scalars reject that read, so a unit variant
/// fails to load on kernels such as Linux 5.15 (OVH MKS). A fixed, fully
/// written result removes the uninitialized bytes without changing packet
/// disposition; the copy itself still happens, its source is now always
/// written.
pub struct TcpOutcome {
    pub action: TcpAction,
    pub flow: PacketFlow,
}

impl TcpOutcome {
    pub const PASS: Self = Self {
        action: TcpAction::Pass,
        flow: PacketFlow::EMPTY,
    };

    pub const DROP: Self = Self {
        action: TcpAction::Drop,
        flow: PacketFlow::EMPTY,
    };

    pub const REPLY: Self = Self {
        action: TcpAction::Reply,
        flow: PacketFlow::EMPTY,
    };

    pub const fn forward(flow: PacketFlow) -> Self {
        Self {
            action: TcpAction::Forward,
            flow,
        }
    }
}
