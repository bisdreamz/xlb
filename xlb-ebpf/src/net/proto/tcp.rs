use network_types::tcp::TcpHdr;

pub struct TcpHeader<'a> {
    hdr: &'a TcpHdr,
}

impl<'a> TcpHeader<'a> {
    pub fn new(ptr: *const TcpHdr) -> Self {
        Self {
            hdr: unsafe { &*ptr },
        }
    }

    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.hdr.source)
    }
}
