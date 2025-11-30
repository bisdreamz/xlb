use serde::{Deserialize, Serialize};
use strum::IntoStaticStr;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, IntoStaticStr)]
#[serde(rename_all = "lowercase")]
pub enum IpVersion {
    #[default]
    Ipv4,
    Ipv6,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IpVersion {}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, IntoStaticStr)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    #[default]
    Tcp,
    Udp,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Proto {}
