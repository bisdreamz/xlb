use serde::{Deserialize, Serialize};
use strum::IntoStaticStr;

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, IntoStaticStr)]
#[serde(rename_all = "lowercase")]
pub enum IpVersion {
    #[default]
    Ipv4,
    Ipv6,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IpVersion {}

#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, IntoStaticStr)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    #[default]
    Tcp,
    Udp,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Proto {}
