use strum::IntoStaticStr;
use serde::{Deserialize, Serialize};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, IntoStaticStr)]
#[serde(rename_all = "lowercase")]
pub enum IpVersion {
    #[default]
    Ipv4,
    Ipv6,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default,Serialize, Deserialize, IntoStaticStr)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    #[default]
    Tcp,
    Udp,
}

