use crate::config::net::ListenAddr;
use crate::config::routing::RoutingMode;

/// Generic port mapping struct representing
/// a port on the local machine and a port
/// on some remote hos
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PortMapping {
    /// Port on this local machine e.g.
    /// could be the lb listen port,
    /// the source port we have assigned
    pub local_port: u16,
    /// Port on a remote host e.g.
    /// backend node service port, or a
    /// src port from a client connection
    pub remote_port: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum ListenProto {
    Tcp,
    Udp,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EbpfConfig {
    pub mode: RoutingMode,
    pub addr: ListenAddr,
    pub proto: ListenProto,
    pub shutdown: bool, // only state field.. do we want to split this out?
    pub port_mappings: [PortMapping; 8],
}

impl EbpfConfig {
    pub const fn empty() -> Self {
        Self {
            addr: ListenAddr::DefaultRoute,
            mode: RoutingMode::Nat,
            proto: ListenProto::Tcp,
            shutdown: false,
            port_mappings: [PortMapping {
                local_port: 0,
                remote_port: 0,
            }; 8],
        }
    }
}
