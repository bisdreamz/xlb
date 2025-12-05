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