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
    #[allow(dead_code)]
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
    /// **Automatically updates the IP header checksum** using full recalculation.
    pub fn set_src_dst_addrs(&mut self, new_src: u32, new_dst: u32) {
        self.hdr.src_addr = new_src.to_be_bytes();
        self.hdr.dst_addr = new_dst.to_be_bytes();
        self.recalculate_checksum();
    }

    /// Fully recalculate IP header checksum from scratch.
    /// Use this when the original checksum might be invalid (e.g., from NIC offload).
    fn recalculate_checksum(&mut self) {
        self.hdr.check = [0, 0]; // Zero out checksum field

        // Manual checksum calculation - unrolled for verifier
        let hdr = unsafe { &*(self.hdr as *const Ipv4Hdr as *const [u8; 20]) };

        let mut sum: u32 = 0;

        // Sum all 16-bit words (skip checksum field at offset 10-11)
        sum += ((hdr[0] as u32) << 8) | (hdr[1] as u32); // version/ihl, tos
        sum += ((hdr[2] as u32) << 8) | (hdr[3] as u32); // total length
        sum += ((hdr[4] as u32) << 8) | (hdr[5] as u32); // id
        sum += ((hdr[6] as u32) << 8) | (hdr[7] as u32); // flags/offset
        sum += ((hdr[8] as u32) << 8) | (hdr[9] as u32); // ttl, protocol
        // Skip bytes 10-11 (checksum field itself)
        sum += ((hdr[12] as u32) << 8) | (hdr[13] as u32); // src ip [0:1]
        sum += ((hdr[14] as u32) << 8) | (hdr[15] as u32); // src ip [2:3]
        sum += ((hdr[16] as u32) << 8) | (hdr[17] as u32); // dst ip [0:1]
        sum += ((hdr[18] as u32) << 8) | (hdr[19] as u32); // dst ip [2:3]

        // Fold carries
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);

        // One's complement
        let checksum = (!sum) as u16;
        self.hdr.check = checksum.to_be_bytes();
    }

    fn update_chksum_for_total_len(&mut self, new_len: u16) {
        // Update total length field
        self.hdr.tot_len = new_len.to_be_bytes();
        // Recalculate entire checksum (simpler and more reliable than incremental)
        self.recalculate_checksum();
    }
}
