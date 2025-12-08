use anyhow::{anyhow, Result};
use log::warn;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use xlb_common::types::Backend;

/// Figures out how to reach a backend by looking up routing info and MAC addresses.
///
/// Given a backend IP, this function determines:
/// - Which interface we'll send packets from (e.g., eth0, eth1)
/// - What source IP and MAC to use
/// - What destination MAC to use (the "next hop")
///
/// The tricky part: for XDP packet rewriting, we need the MAC address of wherever
/// the packet goes NEXT, not necessarily the backend itself. If the backend is on
/// a remote subnet, we need the gateway's MAC, not the backend's MAC.
///
/// Example:
/// - Backend IP: 10.109.0.153 (pod on another node)
/// - Route: "10.109.0.153 via 10.116.0.18 dev eth1 src 10.116.0.17"
/// - Next hop: 10.116.0.18 (the gateway, not the pod!)
/// - We need the MAC for 10.116.0.18, which the kernel will forward to the pod
///
/// This is a simplified implementation using CLI tools (ip, ping).
/// For production, should be replaced with netlink API calls.
/// Supports both IPv4 and IPv6.
pub async fn populate_backend_route(backend: &mut Backend) -> Result<()> {
    let backend_ip = u128_to_ip(backend.ip)?;

    // Ask the kernel how to reach this IP
    let output = Command::new("ip")
        .args(&["route", "get", &backend_ip.to_string()])
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("ip route get failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let route_output = String::from_utf8_lossy(&output.stdout);

    // Parse routing info from output like:
    // "10.109.0.153 via 10.116.0.18 dev eth1 src 10.116.0.17"
    let src_ip = parse_src_ip_from_route(&route_output)?;
    let dev_name = parse_dev_from_route(&route_output)?;
    let ifindex = get_ifindex(&dev_name)?;
    let src_mac = get_interface_mac(&dev_name)?;

    // Here's the key logic: figure out whose MAC we actually need.
    // If there's a "via X.X.X.X" in the route, we're routing through a gateway,
    // so we need the gateway's MAC. If there's no "via", the backend is on the
    // same L2 segment, so we use the backend's MAC directly.
    let next_hop_ip = parse_via_from_route(&route_output).unwrap_or(backend_ip);

    // Try to get the MAC from the neighbor table (ARP/NDP cache)
    let next_hop_mac = match get_arp_entry(&next_hop_ip) {
        Ok(mac) => mac,
        Err(e) => {
            // No neighbor entry yet, so ping to populate it
            warn!("No neighbor entry for {}, attempting ping", next_hop_ip);
            let _ = Command::new("ping")
                .args(&["-c", "1", "-W", "1", &next_hop_ip.to_string()])
                .output();

            // Give the kernel a moment to update the neighbor table
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            // Try again
            get_arp_entry(&next_hop_ip)
                .map_err(|_| anyhow!("Failed to resolve MAC for {}: {}", next_hop_ip, e))?
        }
    };

    // Store everything in the backend struct for XDP to use
    backend.src_iface_ip = ip_to_u128(src_ip);
    backend.src_iface_mac = src_mac;
    backend.next_hop_mac = next_hop_mac;
    backend.src_iface_ifindex = ifindex as u16;

    Ok(())
}

/// Extracts the source IP from "ip route get" output.
/// Looks for "src X.X.X.X" and returns X.X.X.X
///
/// Example: "10.109.0.153 via 10.116.0.18 dev eth1 src 10.116.0.17"
/// Returns: 10.116.0.17
///
/// Works for both IPv4 and IPv6.
fn parse_src_ip_from_route(output: &str) -> Result<IpAddr> {
    if let Some(idx) = output.find("src ") {
        let after_src = &output[idx + 4..];
        if let Some(ip_str) = after_src.split_whitespace().next() {
            return ip_str.parse()
                .map_err(|e| anyhow!("Failed to parse source IP: {}", e));
        }
    }
    Err(anyhow!("No source IP found in route output"))
}

/// Extracts the gateway IP from "ip route get" output, if it exists.
/// Looks for "via X.X.X.X" and returns Some(X.X.X.X), or None if direct L2.
///
/// Examples:
/// - "10.109.0.153 via 10.116.0.18 dev eth1 src 10.116.0.17" → Some(10.116.0.18)
/// - "192.168.1.5 dev wlan0 src 192.168.1.100" → None (same subnet, no gateway)
///
/// Works for both IPv4 and IPv6.
fn parse_via_from_route(output: &str) -> Option<IpAddr> {
    for (i, part) in output.split_whitespace().enumerate() {
        if part == "via" {
            if let Some(gateway_str) = output.split_whitespace().nth(i + 1) {
                if let Ok(gateway_ip) = gateway_str.parse::<IpAddr>() {
                    return Some(gateway_ip);
                }
            }
        }
    }
    None
}

/// Extracts the interface name from "ip route get" output.
/// Looks for "dev IFNAME" and returns IFNAME
///
/// Example: "10.109.0.153 via 10.116.0.18 dev eth1 src 10.116.0.17"
/// Returns: "eth1"
fn parse_dev_from_route(output: &str) -> Result<String> {
    for (i, part) in output.split_whitespace().enumerate() {
        if part == "dev" {
            if let Some(dev_name) = output.split_whitespace().nth(i + 1) {
                return Ok(dev_name.to_string());
            }
        }
    }
    Err(anyhow!("No device found in route output"))
}

/// Gets the interface index for a network device.
/// XDP needs this to know which interface to attach to / redirect from.
///
/// Uses "ip link show IFNAME" and parses the number at the start.
/// Example output: "7: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
/// Returns: 7
fn get_ifindex(dev_name: &str) -> Result<u32> {
    let output = Command::new("ip")
        .args(&["link", "show", dev_name])
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("Failed to get ifindex for {}", dev_name));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);

    if let Some(idx_str) = output_str.split(':').next() {
        return idx_str.trim().parse()
            .map_err(|e| anyhow!("Failed to parse ifindex: {}", e));
    }

    Err(anyhow!("Could not extract ifindex from ip link output"))
}

/// Gets the MAC address for a network interface.
/// This is the source MAC we'll use when rewriting packets in XDP.
fn get_interface_mac(dev_name: &str) -> Result<[u8; 6]> {
    let interfaces = default_net::get_interfaces();

    for iface in interfaces {
        if iface.name == dev_name {
            if let Some(mac) = iface.mac_addr {
                return Ok(mac.octets());
            }
        }
    }

    Err(anyhow!("No MAC address found for interface {}", dev_name))
}

/// Looks up a MAC address in the kernel's neighbor table (ARP for IPv4, NDP for IPv6).
/// Uses "ip neigh show IP" to query.
///
/// Example output: "10.116.0.18 dev eth1 lladdr b6:8e:c2:34:c9:2d REACHABLE"
/// Returns: [0xb6, 0x8e, 0xc2, 0x34, 0xc9, 0x2d]
///
/// Note: If there's no entry, this fails. Caller should ping first to populate.
/// Works for both IPv4 (ARP) and IPv6 (NDP).
fn get_arp_entry(ip: &IpAddr) -> Result<[u8; 6]> {
    let output = Command::new("ip")
        .args(&["neigh", "show", &ip.to_string()])
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("ip neigh show failed"));
    }

    let neigh_output = String::from_utf8_lossy(&output.stdout);

    for (i, part) in neigh_output.split_whitespace().enumerate() {
        if part == "lladdr" {
            if let Some(mac_str) = neigh_output.split_whitespace().nth(i + 1) {
                return parse_mac(mac_str);
            }
        }
    }

    Err(anyhow!("No ARP entry found"))
}

/// Parses a MAC address string like "b6:8e:c2:34:c9:2d" into a 6-byte array.
fn parse_mac(mac_str: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow!("Invalid MAC address format"));
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|e| anyhow!("Failed to parse MAC octet: {}", e))?;
    }

    Ok(mac)
}

/// Converts IpAddr to u128 for storage in Backend struct.
/// IPv4 addresses fit in the lower 32 bits, IPv6 uses the full 128 bits.
fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u32::from(v4) as u128,
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// Converts u128 back to IpAddr.
/// If the value fits in u32, it's IPv4. Otherwise, it's IPv6.
fn u128_to_ip(val: u128) -> Result<IpAddr> {
    if val <= u32::MAX as u128 {
        Ok(IpAddr::V4(Ipv4Addr::from(val as u32)))
    } else {
        Ok(IpAddr::V6(val.into()))
    }
}

