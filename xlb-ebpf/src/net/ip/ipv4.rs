use network_types::ip::Ipv4Hdr;

pub struct Ipv4Header<'a> {
    hdr: &'a Ipv4Hdr,
}

impl<'a> Ipv4Header<'a> {
    pub fn new(ptr: *const Ipv4Hdr) -> Self {
        Self {
            hdr: unsafe { &*ptr },
        }
    }

    pub fn as_ptr(&self) -> *const Ipv4Hdr {
        self.hdr as *const Ipv4Hdr
    }

    pub fn src_addr(&self) -> u32 {
        u32::from_be_bytes(self.hdr.src_addr)
    }

    pub fn dst_addr(&self) -> u32 {
        u32::from_be_bytes(self.hdr.dst_addr)
    }
}
