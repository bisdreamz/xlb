use crate::config::routing::RoutingMode;
use crate::net::{IpVersion, Proto};
use crate::types::PortMapping;

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default)]
pub enum Strategy {
    #[default]
    RoundRobin,
    // LeastConns,
    //Adaptive
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Strategy {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EbpfConfig {
    pub mode: RoutingMode,
    pub strategy: Strategy,
    pub ip_addr: u128,
    pub ip_ver: IpVersion,
    pub proto: Proto,
    pub shutdown: bool, // only state field.. do we want to split this out?
    pub port_mappings: [PortMapping; 8],
}

impl EbpfConfig {
    pub const fn empty() -> Self {
        Self {
            ip_addr: 0,
            ip_ver: IpVersion::Ipv4,
            mode: RoutingMode::Nat,
            strategy: Strategy::RoundRobin,
            proto: Proto::Tcp,
            shutdown: false,
            port_mappings: [PortMapping {
                local_port: 0,
                remote_port: 0,
            }; 8],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EbpfConfig {}
