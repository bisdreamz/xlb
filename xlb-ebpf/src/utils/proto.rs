use crate::utils::context::ptr_at;
use aya_ebpf::programs::XdpContext;
use network_types::eth::EthHdr;
use network_types::ip::Ipv4Hdr;
use network_types::tcp::TcpHdr;

#[inline(always)]
pub fn extract_ipv4_tcp_hdr_ptr(ctx: &XdpContext) -> Result<*mut TcpHdr, ()> {
    ptr_at::<TcpHdr>(ctx, EthHdr::LEN + Ipv4Hdr::LEN)
}
