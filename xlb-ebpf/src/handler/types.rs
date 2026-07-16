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

/// Result of TCP processing before conversion to an XDP packet event.
pub enum TcpOutcome {
    /// Leave the packet unchanged for the kernel networking stack.
    Pass,
    /// Transmit the packet back through its ingress interface.
    Reply,
    /// Rewrite and redirect the packet using the stored flow recipe.
    Forward(PacketFlow),
}
