use anyhow::{anyhow, Result};
use log::warn;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use xlb_common::types::Backend;

#[derive(Debug)]
pub struct RouteInfo {
    pub src_ip: u128,
    pub src_mac: [u8; 6],
    pub next_hop_mac: [u8; 6],
    pub ifindex: u32,
}

/// Populates the routing fields in a Backend struct by performing
/// route lookups using the `ip route get` command and ARP lookups.
///
/// This is a simplified implementation that uses command-line tools.
/// For production use, this should be replaced with proper netlink API calls.
pub async fn populate_backend_route(backend: &mut Backend) -> Result<()> {
    let backend_ip = u128_to_ip(backend.ip)?;

    let output = Command::new("ip")
        .args(&["route", "get", &backend_ip.to_string()])
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("ip route get failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let route_output = String::from_utf8_lossy(&output.stdout);

    let src_ip = parse_src_ip_from_route(&route_output)?;
    let dev_name = parse_dev_from_route(&route_output)?;
    let ifindex = get_ifindex(&dev_name)?;
    let src_mac = get_interface_mac(&dev_name)?;

    let next_hop_mac = match get_arp_entry(&backend_ip) {
        Ok(mac) => mac,
        Err(e) => {
            warn!("No ARP entry for {}, attempting ping", backend_ip);
            let _ = Command::new("ping")
                .args(&["-c", "1", "-W", "1", &backend_ip.to_string()])
                .output();

            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            get_arp_entry(&backend_ip)
                .map_err(|_| anyhow!("Failed to resolve MAC for {}: {}", backend_ip, e))?
        }
    };

    backend.src_iface_ip = ip_to_u128(src_ip);
    backend.src_iface_mac = src_mac;
    backend.next_hop_mac = next_hop_mac;
    backend.src_iface_ifindex = ifindex as u16;

    Ok(())
}

fn parse_src_ip_from_route(output: &str) -> Result<IpAddr> {
    for part in output.split_whitespace() {
        if let Some(idx) = output.find("src ") {
            let after_src = &output[idx + 4..];
            if let Some(ip_str) = after_src.split_whitespace().next() {
                return ip_str.parse()
                    .map_err(|e| anyhow!("Failed to parse source IP: {}", e));
            }
        }
    }
    Err(anyhow!("No source IP found in route output"))
}

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

fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u32::from(v4) as u128,
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn u128_to_ip(val: u128) -> Result<IpAddr> {
    if val <= u32::MAX as u128 {
        Ok(IpAddr::V4(Ipv4Addr::from(val as u32)))
    } else {
        Err(anyhow!("IPv6 not yet supported"))
    }
}

