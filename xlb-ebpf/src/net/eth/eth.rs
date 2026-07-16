use crate::net::eth::MacAddr;
use network_types::eth::EthHdr;

pub struct EthHeader<'a> {
    hdr: &'a mut EthHdr,
}

impl<'a> EthHeader<'a> {
    pub fn new(ptr: *mut EthHdr) -> Self {
        Self {
            hdr: unsafe { &mut *ptr },
        }
    }

    pub fn as_ptr(&self) -> *const EthHdr {
        self.hdr as *const EthHdr
    }

    pub fn src_mac(&self) -> MacAddr {
        self.hdr.src_addr.into()
    }

    pub fn dst_mac(&self) -> MacAddr {
        self.hdr.dst_addr.into()
    }

    pub fn set_src_mac(&mut self, new_mac: &MacAddr) {
        self.hdr.src_addr = new_mac.as_bytes();
    }

    pub fn set_dst_mac(&mut self, new_mac: &MacAddr) {
        self.hdr.dst_addr = new_mac.as_bytes();
    }
}
