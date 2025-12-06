#[derive(Debug, Clone)]
pub struct Iface {
    pub idx: u16,
    pub mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub src_ip: u128,
}
