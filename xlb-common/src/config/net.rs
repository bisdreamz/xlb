use strum::IntoStaticStr;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, IntoStaticStr)]
pub enum IpVersion {
    #[default]
    Ipv4,
    Ipv6,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, IntoStaticStr)]
pub enum Proto {
    #[default]
    Tcp,
    Udp,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub enum ListenAddr {
    /// Will attach to the interface and primary ip of
    /// associated with the default network route
    #[default]
    DefaultRoute,
    /// Specify an ipv4 listen addr, also used to determine
    /// the target interface
    Ipv4(u32),
    /// Specify an ipv6 listen addr, also used to determine
    /// the target interface
    Ipv6(u128),
}
