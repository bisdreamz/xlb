use crate::net::ip::{Ipv4Header, Ipv6Header};
use crate::net::proto::{TcpHeader, UdpHeader};

pub enum IpHeader<'a> {
    Ipv4(Ipv4Header<'a>),
    #[allow(dead_code)]
    Ipv6(Ipv6Header<'a>),
}

pub enum ProtoHeader<'a> {
    Tcp(TcpHeader<'a>),
    #[allow(dead_code)]
    Udp(UdpHeader<'a>),
}
