use crate::utils::context::ptr_at;
use aya_ebpf::programs::XdpContext;
use network_types::eth::EthHdr;
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};

#[inline(always)]
pub fn get_ipv4_hdr_ptr(ctx: &XdpContext) -> Result<*mut Ipv4Hdr, ()> {
    ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN).map_err(|_| ())
}

#[inline(always)]
pub fn get_ipv6_hdr_ptr(ctx: &XdpContext) -> Result<*mut Ipv6Hdr, ()> {
    ptr_at::<Ipv6Hdr>(ctx, EthHdr::LEN).map_err(|_| ())
}

#[inline(always)]
pub fn extract_ipv4_proto(ip_hdr_ptr: *const Ipv4Hdr) -> IpProto {
    unsafe { *ip_hdr_ptr }.proto
}
