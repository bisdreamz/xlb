use serde::Deserialize;

/// Generic port mapping struct representing
/// a port on the local machine and a port
/// on some remote hos
#[repr(C)]
#[derive(Debug, Clone, Copy, Deserialize)]
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

#[cfg(feature = "user")]
unsafe impl aya::Pod for PortMapping {}
