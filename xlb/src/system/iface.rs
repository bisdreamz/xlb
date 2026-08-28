use crate::config::ListenAddr;
use anyhow::{Result, anyhow, bail};
use std::net::{IpAddr, Ipv4Addr};
use xlb_common::net::IpVersion;

pub struct ListenIface {
    pub name: String,
    pub ip: IpAddr,
    pub ver: IpVersion,
}

/// How the listen address was chosen from the default interface's addresses.
#[derive(Debug, PartialEq, Eq)]
enum AddressChoice<'a, T> {
    /// An address sharing the default gateway's subnet.
    InSubnet(&'a T),
    /// The interface's only address, accepted although it is outside the
    /// gateway's subnet.
    SoleAddress(&'a T),
}

/// True when `addr/prefix_len` and `gw` fall in the same subnet. A `/0`
/// matches everything.
fn same_subnet_v4(addr: Ipv4Addr, prefix_len: u8, gw: Ipv4Addr) -> bool {
    let mask = match prefix_len {
        0 => 0,
        len if len >= 32 => u32::MAX,
        len => u32::MAX << (32 - len),
    };

    (u32::from(addr) & mask) == (u32::from(gw) & mask)
}

/// Picks the listen address: the first address in the gateway's subnet,
/// otherwise the interface's sole address.
///
/// Routed host addresses such as OVH's public /32 have an explicitly on-link
/// gateway outside their CIDR. The interface is already the OS-selected
/// default, so its only address is the unambiguous choice. Multiple unmatched
/// addresses remain ambiguous and yield `None`.
fn select_default_address<T>(
    addresses: &[T],
    is_same_subnet: impl Fn(&T) -> bool,
) -> Option<AddressChoice<'_, T>> {
    addresses
        .iter()
        .find(|address| is_same_subnet(address))
        .map(AddressChoice::InSubnet)
        .or(match addresses {
            [only] => Some(AddressChoice::SoleAddress(only)),
            _ => None,
        })
}

/// Detects the default interface and IPv4 address to listen on from the
/// interface that owns the default route.
///
/// Automatic detection is IPv4-only: `default_net`'s Linux gateway discovery
/// reads `/proc/net/route` (IPv4) and XLB rejects IPv6 listen addresses
/// (see `Config::validate_listen_ip`). IPv6 hosts must set `listen.ip`.
fn detect_default() -> Result<ListenIface> {
    let gateway = default_net::get_default_gateway()
        .map_err(|e| anyhow!("Failed to get default gateway: {}", e))?;

    let interface = default_net::get_default_interface()
        .map_err(|e| anyhow!("Failed to get default interface: {}", e))?;

    let IpAddr::V4(gw_ip) = gateway.ip_addr else {
        bail!(
            "Automatic listen address detection supports IPv4 only (default gateway is {}); set listen.ip explicitly",
            gateway.ip_addr
        );
    };

    let choice = select_default_address(&interface.ipv4, |addr| {
        same_subnet_v4(addr.addr, addr.prefix_len, gw_ip)
    });

    let ip = match choice {
        Some(AddressChoice::InSubnet(addr)) => addr.addr,
        Some(AddressChoice::SoleAddress(addr)) => {
            log::warn!(
                "Listen address {}/{} on {} is outside the default gateway's subnet ({}); using it as the interface's only address. Set listen.ip if this is wrong.",
                addr.addr,
                addr.prefix_len,
                interface.name,
                gw_ip
            );
            addr.addr
        }
        None => bail!(
            "Cannot infer listen address on {}: {} IPv4 address(es), none in the default gateway's subnet ({}); set listen.ip explicitly",
            interface.name,
            interface.ipv4.len(),
            gw_ip
        ),
    };

    Ok(ListenIface {
        name: interface.name,
        ip: IpAddr::V4(ip),
        ver: IpVersion::Ipv4,
    })
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

#[cfg(test)]
mod tests {
    use super::{AddressChoice, same_subnet_v4, select_default_address};
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn routed_host_address_is_not_in_the_gateway_subnet() {
        // OVH-style public /32 with an on-link gateway outside the CIDR.
        assert!(!same_subnet_v4(ip("203.0.113.10"), 32, ip("203.0.113.1")));
    }

    #[test]
    fn host_route_matches_only_itself() {
        assert!(same_subnet_v4(ip("203.0.113.10"), 32, ip("203.0.113.10")));
    }

    #[test]
    fn same_subnet_for_a_matching_prefix() {
        assert!(same_subnet_v4(ip("192.0.2.10"), 24, ip("192.0.2.1")));
        assert!(same_subnet_v4(ip("192.0.2.10"), 20, ip("192.0.15.254")));
    }

    #[test]
    fn different_subnet_for_a_non_matching_prefix() {
        assert!(!same_subnet_v4(ip("192.0.2.10"), 24, ip("198.51.100.1")));
        assert!(!same_subnet_v4(ip("192.0.2.10"), 25, ip("192.0.2.200")));
    }

    #[test]
    fn default_route_prefix_matches_everything() {
        assert!(same_subnet_v4(ip("192.0.2.10"), 0, ip("198.51.100.1")));
    }

    #[test]
    fn accepts_the_only_address_for_a_routed_host_address() {
        let addresses = ["203.0.113.10/32"];

        assert_eq!(
            select_default_address(&addresses, |_| false),
            Some(AddressChoice::SoleAddress(&addresses[0]))
        );
    }

    #[test]
    fn refuses_to_guess_between_unmatched_addresses() {
        let addresses = ["192.0.2.10/32", "192.0.2.11/32"];

        assert_eq!(select_default_address(&addresses, |_| false), None);
    }

    #[test]
    fn rejects_an_interface_without_addresses() {
        let addresses: [&str; 0] = [];

        assert_eq!(select_default_address(&addresses, |_| true), None);
    }

    #[test]
    fn prefers_the_address_matching_the_gateway_subnet() {
        let addresses = ["192.0.2.10/24", "198.51.100.10/24"];

        assert_eq!(
            select_default_address(&addresses, |address| address.starts_with("198.51.100.")),
            Some(AddressChoice::InSubnet(&addresses[1]))
        );
    }
}
