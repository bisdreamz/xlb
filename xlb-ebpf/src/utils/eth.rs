use crate::utils::context::ptr_at;
use aya_ebpf::programs::XdpContext;
use network_types::eth::{EthHdr, EtherType};

#[inline(always)]
pub fn get_eth_hdr_ptr(ctx: &XdpContext) -> Result<*mut EthHdr, ()> {
    ptr_at::<EthHdr>(ctx, 0).map_err(|_| ())
}

#[inline(always)]
pub fn extract_eth_proto(eth_hdr: *const EthHdr) -> Result<EtherType, ()> {
    unsafe { *eth_hdr }.ether_type().map_err(|_| ())
}
