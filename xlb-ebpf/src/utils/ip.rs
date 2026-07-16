use crate::utils::context::ptr_at;
use aya_ebpf::programs::XdpContext;
use network_types::eth::EthHdr;
use network_types::ip::{IpProto, Ipv4Hdr};

const IPV4_PROTOCOL_OFFSET: usize = 9;

#[inline(always)]
pub fn get_ipv4_hdr_ptr(ctx: &XdpContext) -> Result<*mut Ipv4Hdr, ()> {
    ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN).map_err(|_| ())
}

#[inline(always)]
pub fn extract_ipv4_protocol(ip_hdr_ptr: *const Ipv4Hdr) -> u8 {
    // Read the untrusted byte without constructing an IpProto enum; not every
    // possible protocol number is a valid enum discriminant.
    unsafe { ip_hdr_ptr.cast::<u8>().add(IPV4_PROTOCOL_OFFSET).read() }
}

#[inline(always)]
pub const fn is_tcp_protocol(protocol: u8) -> bool {
    protocol == IpProto::Tcp as u8
}

#[cfg(test)]
mod tests {
    use super::{extract_ipv4_protocol, is_tcp_protocol};
    use network_types::ip::Ipv4Hdr;

    #[test]
    fn unknown_protocol_bytes_are_classified_without_constructing_an_enum() {
        let mut raw_header = [0u8; Ipv4Hdr::LEN];
        raw_header[9] = 200;

        let protocol = extract_ipv4_protocol(raw_header.as_ptr().cast::<Ipv4Hdr>());

        assert_eq!(protocol, 200);
        assert!(!is_tcp_protocol(protocol));
        assert!(is_tcp_protocol(6));
    }
}
