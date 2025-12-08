use crate::config::ListenAddr;
use anyhow::{Result, anyhow};
use std::net::IpAddr;
use xlb_common::net::IpVersion;

pub struct ListenIface {
    pub name: String,
    pub ip: IpAddr,
    pub ver: IpVersion,
}

/// Detects the default interface and ip address to listen on
/// by retrieving the interface associated with the default
/// route and returning the first address on the same
/// subnet as the default route
fn detect_default() -> Result<ListenIface> {
    let gateway = default_net::get_default_gateway()
        .map_err(|e| anyhow!("Failed to get default gateway: {}", e))?;

    let interface = default_net::get_default_interface()
        .map_err(|e| anyhow!("Failed to get default interface: {}", e))?;

    match gateway.ip_addr {
        IpAddr::V4(gw_ip) => {
            let ip = interface
                .ipv4
                .iter()
                .find(|addr| {
                    let mask = if addr.prefix_len == 0 {
                        0
                    } else {
                        (!0u32) << (32 - addr.prefix_len)
                    };
                    let ip_bits = u32::from(addr.addr);
                    let gw_bits = u32::from(gw_ip);
                    (ip_bits & mask) == (gw_bits & mask)
                })
                .map(|addr| IpAddr::V4(addr.addr))
                .ok_or_else(|| anyhow::anyhow!("No IPv4 address in same subnet as gateway"))?;

            Ok(ListenIface {
                name: interface.name,
                ip,
                ver: IpVersion::Ipv4,
            })
        }
        IpAddr::V6(gw_ip) => {
            let ip = interface
                .ipv6
                .iter()
                .find(|addr| {
                    let mask = if addr.prefix_len == 0 {
                        0
                    } else {
                        (!0u128) << (128 - addr.prefix_len)
                    };
                    let ip_bits = u128::from(addr.addr);
                    let gw_bits = u128::from(gw_ip);
                    (ip_bits & mask) == (gw_bits & mask)
                })
                .map(|addr| IpAddr::V6(addr.addr))
                .ok_or_else(|| anyhow::anyhow!("No IPv6 address in same subnet as gateway"))?;

            Ok(ListenIface {
                name: interface.name,
                ip,
                ver: IpVersion::Ipv6,
            })
        }
    }
}

fn get_iface_for_ip(ip: IpAddr) -> Result<ListenIface> {
    let interfaces = default_net::get_interfaces();

    for interface in interfaces {
        match ip {
            IpAddr::V4(target_ip) => {
                if interface.ipv4.iter().any(|addr| addr.addr == target_ip) {
                    return Ok(ListenIface {
                        name: interface.name,
                        ip,
                        ver: IpVersion::Ipv4,
                    });
                }
            }
            IpAddr::V6(target_ip) => {
                if interface.ipv6.iter().any(|addr| addr.addr == target_ip) {
                    return Ok(ListenIface {
                        name: interface.name,
                        ip,
                        ver: IpVersion::Ipv6,
                    });
                }
            }
        }
    }

    anyhow::bail!("No interface found with IP address {}", ip)
}

/// Retrieves the ['ListenIface'] details to listen on based on the provided listen config
pub fn get_listen_iface(listen: &ListenAddr) -> Result<ListenIface> {
    match listen {
        ListenAddr::Auto => detect_default(),
        ListenAddr::Ip(ip) => get_iface_for_ip(ip.parse()?),
    }
}
