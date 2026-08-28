#[derive(Debug, Clone, Copy)]
pub struct Iface {
    pub idx: u16,
    pub mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub src_ip: u128,
}

impl Iface {
    /// All-zero interface, used to fully initialize results that carry an
    /// `Iface` on paths that do not forward (see `PacketFlow::EMPTY`).
    pub const EMPTY: Self = Self {
        idx: 0,
        mac: [0; 6],
        src_mac: [0; 6],
        src_ip: 0,
    };
}
