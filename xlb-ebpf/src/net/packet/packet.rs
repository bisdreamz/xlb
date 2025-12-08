use crate::net::eth::{EthHeader, MacAddr};
use crate::net::types::{IpHeader, ProtoHeader};
use crate::{net, utils};
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::info;
use xlb_common::net::{IpVersion, Proto};
use xlb_common::XlbErr;

/// Macros for packet logging with compile-time optimization
/// debug/trace logs are compiled out when 'verbose-logs' feature is disabled (zero overhead)
/// info/warn/error logs are always included

#[macro_export]
macro_rules! packet_log_trace {
    ($packet:expr, $($arg:tt)*) => {
        #[cfg(feature = "verbose-logs")]
        ::aya_log_ebpf::trace!($packet.xdp_context(), $($arg)*);
    };
}

#[macro_export]
macro_rules! packet_log_debug {
    ($packet:expr, $($arg:tt)*) => {
        #[cfg(feature = "verbose-logs")]
        ::aya_log_ebpf::debug!($packet.xdp_context(), $($arg)*);
    };
}

#[macro_export]
macro_rules! packet_log_info {
    ($packet:expr, $($arg:tt)*) => {
        ::aya_log_ebpf::info!($packet.xdp_context(), $($arg)*);
    };
}

#[macro_export]
macro_rules! packet_log_warn {
    ($packet:expr, $($arg:tt)*) => {
        ::aya_log_ebpf::warn!($packet.xdp_context(), $($arg)*);
    };
}

#[macro_export]
macro_rules! packet_log_error {
    ($packet:expr, $($arg:tt)*) => {
        ::aya_log_ebpf::error!($packet.xdp_context(), $($arg)*);
    };
}

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

    pub fn xdp_context(&self) -> &'_ XdpContext {
        self.ctx
    }

    pub fn size(&self) -> u64 {
        (self.ctx.data_end() - self.ctx.data()) as u64
    }

    pub fn eth_hdr(&self) -> &EthHeader<'_> {
        &self.eth_hdr
    }

    #[allow(dead_code)]
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

    pub fn src_ip(&self) -> u128 {
        match &self.ip_hdr {
            IpHeader::Ipv4(ipv4) => ipv4.src_addr() as u128,
            IpHeader::Ipv6(_) => 0,
        }
    }

    pub fn dst_ip(&self) -> u128 {
        match &self.ip_hdr {
            IpHeader::Ipv4(ipv4) => ipv4.dst_addr() as u128,
            IpHeader::Ipv6(_) => 0,
        }
    }

    pub fn src_port(&self) -> u16 {
        match &self.proto_hdr {
            ProtoHeader::Tcp(tcp) => tcp.src_port(),
            ProtoHeader::Udp(_) => 0,
        }
    }

    pub fn dst_port(&self) -> u16 {
        match &self.proto_hdr {
            ProtoHeader::Tcp(tcp) => tcp.dst_port(),
            ProtoHeader::Udp(_) => 0,
        }
    }

    #[allow(dead_code)]
    pub fn ip_total_len(&self) -> u16 {
        match &self.ip_hdr {
            IpHeader::Ipv4(ipv4) => ipv4.total_len(),
            IpHeader::Ipv6(_) => 0, // TODO: IPv6 support
        }
    }

    /// Logs major packet details for debugging
    #[allow(dead_code)]
    pub fn dump(&self, label: &str) {
        let src_mac = self.eth_hdr.src_mac().as_bytes();
        let dst_mac = self.eth_hdr.dst_mac().as_bytes();

        info!(
            self.ctx,
            "{} MAC: {:x}:{:x}:{:x}:{:x}:{:x}:{:x} -> {:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            label,
            src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
            dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]
        );

        match &self.ip_hdr {
            IpHeader::Ipv4(ipv4) => {
                let src_ip = ipv4.src_addr();
                let dst_ip = ipv4.dst_addr();

                info!(
                    self.ctx,
                    "{} IP: {}.{}.{}.{}:{} -> {}.{}.{}.{}:{}",
                    label,
                    (src_ip >> 24) & 0xff, (src_ip >> 16) & 0xff, (src_ip >> 8) & 0xff, src_ip & 0xff,
                    self.src_port(),
                    (dst_ip >> 24) & 0xff, (dst_ip >> 16) & 0xff, (dst_ip >> 8) & 0xff, dst_ip & 0xff,
                    self.dst_port()
                );
            }
            IpHeader::Ipv6(_) => {
                info!(self.ctx, "{}: IPv6", label);
            }
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

                let old_src_ip = ipv4.src_addr();
                let old_dst_ip = ipv4.dst_addr();

                let new_src_ip = src_ip_addr as u32;
                let new_dst_ip = dst_ip_addr as u32;

                // Update IP addresses (also updates IP header checksum)
                ipv4.set_src_dst_addrs(new_src_ip, new_dst_ip);

                // Incremental TCP checksum update using RFC 1624
                match &mut self.proto_hdr {
                    ProtoHeader::Tcp(tcp) => {
                        let old_src_port = tcp.src_port();
                        let old_dst_port = tcp.dst_port();

                        // Update checksum for NAT (IPs + ports) in one operation
                        tcp.update_checksum_for_nat(
                            old_src_ip,
                            old_dst_ip,
                            old_src_port,
                            old_dst_port,
                            new_src_ip,
                            new_dst_ip,
                            src_port,
                            dst_port,
                        );

                        // Update port values after checksum
                        tcp.set_ports_no_checksum(src_port, dst_port);
                    }
                    ProtoHeader::Udp(_) => return Err(XlbErr::ErrNotYetImpl),
                }
            }
            IpHeader::Ipv6(_) => return Err(XlbErr::ErrNotYetImpl),
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
