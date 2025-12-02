use crate::net::checksum::fold_checksum;
use aya_ebpf::helpers::bpf_csum_diff;
use network_types::ip::Ipv4Hdr;

/// Wrapper around IPv4 header for safe manipulation and checksum management.
///
/// All address-modifying methods automatically update the IP header checksum
/// using efficient incremental checksum calculation via BPF helpers.
pub struct Ipv4Header<'a> {
    hdr: &'a mut Ipv4Hdr,
}

impl<'a> Ipv4Header<'a> {
    pub fn new(ptr: *mut Ipv4Hdr) -> Self {
        Self {
            hdr: unsafe { &mut *ptr },
        }
    }

    pub fn as_ptr(&self) -> *const Ipv4Hdr {
        self.hdr as *const Ipv4Hdr
    }

    /// Get source IP address in host byte order
    pub fn src_addr(&self) -> u32 {
        u32::from_be_bytes(self.hdr.src_addr)
    }

    /// Get destination IP address in host byte order
    pub fn dst_addr(&self) -> u32 {
        u32::from_be_bytes(self.hdr.dst_addr)
    }

    /// Packet total length in bytes
    pub fn total_len(&self) -> u16 {
        self.hdr.tot_len()
    }

    /// Update total length and adjust checksum incrementally.
    pub fn set_total_len(&mut self, new_len: u16) {
        if self.total_len() == new_len {
            return;
        }

        self.update_chksum_for_total_len(new_len);
        self.hdr.set_tot_len(new_len);
    }

    /// Header length (ihl) in bytes
    pub fn header_len_ihl(&self) -> u8 {
        self.hdr.ihl()
    }

    /// Set both source and destination addresses.
    ///
    /// **Automatically updates the IP header checksum** using incremental calculation.
    pub fn set_src_dst_addrs(&mut self, new_src: u32, new_dst: u32) {
        self.update_chksum_for_addr_change(new_src, new_dst);
        self.hdr.src_addr = new_src.to_be_bytes();
        self.hdr.dst_addr = new_dst.to_be_bytes();
    }

    /// Incrementally update IP header checksum after address changes.
    ///
    /// Uses `bpf_csum_diff` to efficiently compute the checksum delta from
    /// changing addresses, avoiding full header recalculation.
    fn update_chksum_for_addr_change(&mut self, new_src: u32, new_dst: u32) {
        let old_addrs = [self.src_addr().to_be(), self.dst_addr().to_be()];
        let new_addrs = [new_src.to_be(), new_dst.to_be()];

        let seed = (!u16::from_be_bytes(self.hdr.check)) as u32;
        let csum = unsafe {
            bpf_csum_diff(
                old_addrs.as_ptr() as *mut u32,
                8, // 2 addresses * 4 bytes each
                new_addrs.as_ptr() as *mut u32,
                8,
                seed,
            )
        };

        self.hdr.check = (!fold_checksum(csum as u64)).to_be_bytes();
    }

    fn update_chksum_for_total_len(&mut self, new_len: u16) {
        let old_word = [(self.total_len() as u32) << 16];
        let new_word = [(new_len as u32) << 16];
        let seed = (!u16::from_be_bytes(self.hdr.check)) as u32;

        let csum = unsafe {
            bpf_csum_diff(
                old_word.as_ptr() as *mut u32,
                4,
                new_word.as_ptr() as *mut u32,
                4,
                seed,
            )
        };

        self.hdr.check = (!fold_checksum(csum as u64)).to_be_bytes();
    }
}
