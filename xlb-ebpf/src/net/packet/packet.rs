use crate::net::eth::{EthHeader, MacAddr};
use crate::net::types::{IpHeader, ProtoHeader};
use crate::{net, utils};
use aya_ebpf::programs::XdpContext;
use xlb_common::XlbErr;
use xlb_common::net::{IpVersion, Proto};

pub struct Packet<'a> {
    ctx: &'a XdpContext,
    eth_hdr: EthHeader<'a>,
    ip_hdr: IpHeader<'a>,
    proto_hdr: ProtoHeader<'a>,
}

impl<'a> Packet<'a> {
    pub fn new(ctx: &'a XdpContext) -> Result<Option<Self>, XlbErr> {
        let eth_hdr_ptr = utils::eth::get_eth_hdr_ptr(ctx).map_err(|_| XlbErr::ErrParseHdrEth)?;
        let eth_hdr = EthHeader::new(eth_hdr_ptr);

        let ip_hdr = match net::utils::extract_ip_hdr(ctx, eth_hdr.as_ptr()) {
            Ok(Some(ip_hdr)) => ip_hdr,
            Ok(None) => return Ok(None),
            Err(_) => return Err(XlbErr::ErrParseHdrIp),
        };

        let proto_hdr = match net::utils::extract_proto_hdr(ctx, &ip_hdr) {
            Ok(Some(proto_hdr)) => proto_hdr,
            Ok(None) => return Ok(None),
            Err(_) => return Err(XlbErr::ErrParseHdrProto),
        };

        Ok(Some(Self {
            ctx,
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

    /// Rewrites packet headers to reroute to a new destination.
    ///
    /// Caller is responsible for determining appropriate source/destination values
    /// based on forwarding mode (DSR vs NAT) and connection tracking state.
    ///
    /// # Arguments
    /// * `dst_mac_addr` - MAC address of next hop (gateway/backend)
    /// * `src_ip_addr` - Source IP (u32 for IPv4, upper 96 bits ignored)
    /// * `dst_ip_addr` - Destination IP (u32 for IPv4, upper 96 bits ignored)
    /// * `src_port` - Source port for TCP/UDP header
    /// * `dst_port` - Destination port for TCP/UDP header
    ///
    /// # DSR vs NAT
    /// - **DSR**: Pass original client src_ip/src_port, backend dst_ip/dst_port
    /// - **NAT**: Pass LB VIP as src_ip with LB port, backend dst_ip/dst_port
    pub fn reroute(
        &mut self,
        src_mac_addr: &MacAddr,
        dst_mac_addr: &MacAddr,
        src_ip_addr: u128,
        dst_ip_addr: u128,
        src_port: u16,
        dst_port: u16,
    ) -> Result<(), XlbErr> {
        self.eth_hdr.set_src_mac(src_mac_addr);
        self.eth_hdr.set_dst_mac(dst_mac_addr);

        match &mut self.ip_hdr {
            IpHeader::Ipv4(ipv4) => {
                if src_ip_addr > u32::MAX as u128 || dst_ip_addr > u32::MAX as u128 {
                    return Err(XlbErr::ErrInvalidIpVal);
                }

                ipv4.set_src_dst_addrs(src_ip_addr as u32, dst_ip_addr as u32)
            }
            IpHeader::Ipv6(_) => return Err(XlbErr::ErrNotYetImpl),
        }

        match &mut self.proto_hdr {
            ProtoHeader::Tcp(tcp) => tcp.set_src_dst_ports(src_port, dst_port),
            ProtoHeader::Udp(_) => return Err(XlbErr::ErrNotYetImpl),
        }

        Ok(())
    }

    /// Transform packet into a RST response by swapping
    /// the src/dst values. Errors if this is not a TCP packet.
    pub fn rst(&mut self) -> Result<(), XlbErr> {
        let src_mac = self.eth_hdr.src_mac();
        let dst_mac = self.eth_hdr.dst_mac();

        self.eth_hdr.set_src_mac(&dst_mac);
        self.eth_hdr.set_dst_mac(&src_mac);

        match &mut self.ip_hdr {
            IpHeader::Ipv4(ip) => {
                let src_ip = ip.src_addr();
                let dst_ip = ip.dst_addr();

                ip.set_src_dst_addrs(dst_ip, src_ip);

                match &mut self.proto_hdr {
                    ProtoHeader::Tcp(tcp) => {
                        let new_total_len = tcp.rst(
                            self.ctx,
                            dst_ip,
                            src_ip,
                            ip.total_len(),
                            ip.header_len_ihl(),
                        )?;
                        ip.set_total_len(new_total_len);
                    }
                    ProtoHeader::Udp(_) => return Err(XlbErr::ErrInvalidOp),
                }
            }
            IpHeader::Ipv6(_) => return Err(XlbErr::ErrNotYetImpl),
        }

        Ok(())
    }
}
