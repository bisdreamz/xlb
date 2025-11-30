use network_types::ip::Ipv6Hdr;

pub struct Ipv6Header<'a> {
    hdr: &'a mut Ipv6Hdr,
}

impl<'a> Ipv6Header<'a> {
    pub fn new(ptr: *mut Ipv6Hdr) -> Self {
        Self {
            hdr: unsafe { &mut *ptr },
        }
    }
}
