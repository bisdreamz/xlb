use crate::net::eth::EthHeader;
use crate::net::types::{IpHeader, ProtoHeader};
use crate::{net, utils};
use aya_ebpf::programs::XdpContext;
use xlb_common::XlbStatus;
use xlb_common::config::net::{IpVersion, Proto};

pub struct Packet<'a> {
    // ctx: XdpContext, if we need ownership later?
    eth_hdr: EthHeader<'a>,
    ip_hdr: IpHeader<'a>,
    proto_hdr: ProtoHeader<'a>,
}

impl<'a> Packet<'a> {
    pub fn new(ctx: &'a XdpContext) -> Result<Option<Self>, XlbStatus> {
        let eth_hdr_ptr =
            utils::eth::get_eth_hdr_ptr(ctx).map_err(|_| XlbStatus::ErrParseHdrEth)?;
        let eth_hdr = EthHeader::new(eth_hdr_ptr);

        let ip_hdr = match net::utils::extract_ip_hdr(ctx, eth_hdr.as_ptr()) {
            Ok(Some(ip_hdr)) => ip_hdr,
            Ok(None) => return Ok(None),
            Err(_) => return Err(XlbStatus::ErrParseHdrIp),
        };

        let proto_hdr = match net::utils::extract_proto_hdr(ctx, &ip_hdr) {
            Ok(Some(proto_hdr)) => proto_hdr,
            Ok(None) => return Ok(None),
            Err(_) => return Err(XlbStatus::ErrParseHdrProto),
        };

        Ok(Some(Self {
            eth_hdr,
            ip_hdr,
            proto_hdr,
        }))
    }

    pub fn eth_hdr(&self) -> &EthHeader<'_> {
        &self.eth_hdr
    }

    pub fn ip_hdr(&self) -> &IpHeader<'_> {
        &self.ip_hdr
    }

    pub fn proto_hdr(&self) -> &ProtoHeader<'_> {
        &self.proto_hdr
    }

    pub fn ip_version(&self) -> IpVersion {
        match self.ip_hdr {
            IpHeader::Ipv4(_) => IpVersion::Ipv4,
            IpHeader::Ipv6(_) => IpVersion::Ipv6,
        }
    }

    pub fn proto(&self) -> Proto {
        match self.proto_hdr {
            ProtoHeader::Tcp(_) => Proto::Tcp,
            ProtoHeader::Udp(_) => Proto::Udp,
        }
    }
}
