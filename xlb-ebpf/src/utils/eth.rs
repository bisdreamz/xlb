use crate::utils::context::ptr_at;
use aya_ebpf::programs::XdpContext;
use network_types::eth::{EthHdr, EtherType};

#[inline(always)]
pub fn get_eth_hdr_ptr(ctx: &XdpContext) -> Result<*mut EthHdr, ()> {
    ptr_at::<EthHdr>(ctx, 0).map_err(|_| ())
}

#[inline(always)]
pub fn extract_eth_type(eth_hdr: *const EthHdr) -> u16 {
    unsafe { (*eth_hdr).ether_type }
}

#[inline(always)]
pub const fn is_ipv4_eth_type(ether_type: u16) -> bool {
    ether_type == EtherType::Ipv4 as u16
}

#[cfg(test)]
mod tests {
    use super::is_ipv4_eth_type;
    use network_types::eth::EtherType;

    #[test]
    fn only_ipv4_ether_type_enters_network_parsing() {
        assert!(is_ipv4_eth_type(EtherType::Ipv4 as u16));
        assert!(!is_ipv4_eth_type(EtherType::Ipv6 as u16));
        assert!(!is_ipv4_eth_type(0x88cc_u16.to_be())); // LLDP
        assert!(!is_ipv4_eth_type(0x888e_u16.to_be())); // EAPOL
    }
}
