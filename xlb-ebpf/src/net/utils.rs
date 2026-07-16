use crate::net::ip::Ipv4Header;
use crate::net::proto::TcpHeader;
use crate::net::types::{IpHeader, ProtoHeader};
use crate::utils;
use aya_ebpf::programs::XdpContext;
use network_types::eth::EthHdr;

#[inline(always)]
pub fn extract_ip_hdr(
    ctx: &XdpContext,
    eth_hdr: *const EthHdr,
) -> Result<Option<IpHeader<'_>>, ()> {
    let ether_type = utils::eth::extract_eth_type(eth_hdr);
    if !utils::eth::is_ipv4_eth_type(ether_type) {
        // IPv6 and unrelated Ethernet protocols pass before header parsing.
        return Ok(None);
    }

    let hdr = utils::ip::get_ipv4_hdr_ptr(ctx).map_err(|_| ())?;
    let protocol = utils::ip::extract_ipv4_protocol(hdr);
    if !utils::ip::is_tcp_protocol(protocol) {
        return Ok(None);
    }

    Ok(Some(IpHeader::Ipv4(Ipv4Header::new(hdr))))
}

/// Extract ['ProtoHdr'] enum from context and ['IpHdr'] struct.
/// Returns error if any failure in parsing, and None if a valid
/// but unsupported proto is found
#[inline(always)]
pub fn extract_proto_hdr<'a>(
    ctx: &XdpContext,
    ip_hdr: &'_ IpHeader,
) -> Result<Option<ProtoHeader<'a>>, ()> {
    match ip_hdr {
        IpHeader::Ipv4(ipv4_header) => {
            if ipv4_header.supports_tcp_processing() {
                let ptr = utils::proto::extract_ipv4_tcp_hdr_ptr(ctx).map_err(|_| ())?;
                return Ok(Some(ProtoHeader::Tcp(TcpHeader::new(ptr))));
            }

            // Unsupported IPv4 options/fragments pass untouched before
            // fixed-offset transport parsing.
            Ok(None)
        }
        IpHeader::Ipv6(_) => Ok(None),
    }
}
