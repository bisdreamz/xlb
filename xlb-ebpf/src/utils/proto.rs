use crate::utils::context::ptr_at;
use aya_ebpf::programs::XdpContext;
use network_types::eth::EthHdr;
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

#[inline(always)]
pub fn extract_ipv4_tcp_hdr_ptr(ctx: &XdpContext) -> Result<*mut TcpHdr, ()> {
    ptr_at::<TcpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN)
}

#[inline(always)]
pub fn extract_ipv6_tcp_hdr_ptr(ctx: &XdpContext) -> Result<*mut TcpHdr, ()> {
    ptr_at::<TcpHdr>(ctx, EthHdr::LEN + Ipv6Hdr::LEN)
}

#[inline(always)]
pub fn extract_ipv4_udp_hdr_ptr(ctx: &XdpContext) -> Result<*mut UdpHdr, ()> {
    ptr_at::<UdpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN)
}

#[inline(always)]
pub fn extract_ipv6_udp_hdr_ptr(ctx: &XdpContext) -> Result<*mut UdpHdr, ()> {
    ptr_at::<UdpHdr>(ctx, EthHdr::LEN + Ipv6Hdr::LEN)
}
