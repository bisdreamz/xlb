use crate::net::ip::{Ipv4Header, Ipv6Header};
use crate::net::proto::{TcpHeader, UdpHeader};
use crate::net::types::{IpHeader, ProtoHeader};
use crate::utils;
use aya_ebpf::programs::XdpContext;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::IpProto;

#[inline(always)]
pub fn extract_ip_hdr(
    ctx: &XdpContext,
    eth_hdr: *const EthHdr,
) -> Result<Option<IpHeader<'_>>, ()> {
    let eth_type = utils::eth::extract_eth_proto(eth_hdr)?;

    match eth_type {
        EtherType::Ipv4 => {
            let hdr = utils::ip::get_ipv4_hdr_ptr(ctx).map_err(|_| ())?;
            Ok(Some(IpHeader::Ipv4(Ipv4Header::new(hdr))))
        }
        EtherType::Ipv6 => {
            let hdr = utils::ip::get_ipv6_hdr_ptr(ctx).map_err(|_| ())?;
            Ok(Some(IpHeader::Ipv6(Ipv6Header::new(hdr))))
        }
        _ => Ok(None),
    }
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
        IpHeader::Ipv4(ipv4_header) => match utils::ip::extract_ipv4_proto(ipv4_header.as_ptr()) {
            IpProto::Tcp => {
                let ptr = utils::proto::extract_ipv4_tcp_hdr_ptr(ctx).map_err(|_| ())?;

                Ok(Some(ProtoHeader::Tcp(TcpHeader::new(ptr))))
            }
            IpProto::Udp => {
                let ptr = utils::proto::extract_ipv4_udp_hdr_ptr(ctx).map_err(|_| ())?;

                Ok(Some(ProtoHeader::Udp(UdpHeader::new(ptr))))
            }
            _ => Ok(None),
        },
        IpHeader::Ipv6(_ip_ptr) => Err(()), // TODO impl remaining ipv6 support
    }
}
