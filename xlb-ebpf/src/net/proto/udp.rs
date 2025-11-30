use network_types::udp::UdpHdr;

pub struct UdpHeader<'a> {
    hdr: &'a mut UdpHdr,
}

impl<'a> UdpHeader<'a> {
    pub fn new(ptr: *mut UdpHdr) -> Self {
        Self {
            hdr: unsafe { &mut *ptr },
        }
    }
}
