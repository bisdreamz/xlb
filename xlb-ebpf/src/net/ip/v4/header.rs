use network_types::ip::Ipv4Hdr;
use network_types::tcp::TcpHdr;

/// Wrapper around IPv4 header for safe manipulation and checksum management.
///
/// Address-modifying methods recalculate the fixed IPv4 header checksum after
/// mutation.
pub struct Ipv4Header<'a> {
    hdr: &'a mut Ipv4Hdr,
}

impl<'a> Ipv4Header<'a> {
    pub fn new(ptr: *mut Ipv4Hdr) -> Self {
        Self {
            hdr: unsafe { &mut *ptr },
        }
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

    /// Header length (ihl) in bytes
    pub fn header_len_ihl(&self) -> u8 {
        self.hdr.ihl()
    }

    /// Whether XLB can safely parse and manipulate TCP at its fixed offset.
    ///
    /// IPv4 options and fragments are passed untouched because XLB neither
    /// follows variable header offsets nor performs IP reassembly in XDP.
    pub fn supports_tcp_processing(&self) -> bool {
        let fragment_flags = self.hdr.frag_flags();
        let unsupported_flags = fragment_flags & !0x2 != 0;
        let nonzero_fragment_offset = self.hdr.frag_offset() != 0;
        let minimum_total_len = Ipv4Hdr::LEN + TcpHdr::LEN;

        self.hdr.version() == 4
            && self.header_len_ihl() as usize == Ipv4Hdr::LEN
            && self.total_len() as usize >= minimum_total_len
            && !unsupported_flags
            && !nonzero_fragment_offset
    }

    /// Set both source and destination addresses.
    ///
    /// **Automatically updates the IP header checksum** using full recalculation.
    pub fn set_src_dst_addrs(&mut self, new_src: u32, new_dst: u32) {
        self.hdr.src_addr = new_src.to_be_bytes();
        self.hdr.dst_addr = new_dst.to_be_bytes();
        self.recalculate_checksum();
    }

    /// Rewrite all IPv4 fields needed for a locally generated response and
    /// calculate the checksum once after the complete mutation.
    pub fn write_response_header(
        &mut self,
        new_src: u32,
        new_dst: u32,
        new_total_len: u16,
        ttl: u8,
    ) {
        self.hdr.src_addr = new_src.to_be_bytes();
        self.hdr.dst_addr = new_dst.to_be_bytes();
        self.hdr.set_tot_len(new_total_len);
        self.hdr.ttl = ttl;
        self.recalculate_checksum();
    }

    /// Fully recalculate IP header checksum from scratch.
    /// Use this when the original checksum might be invalid (e.g., from NIC offload).
    fn recalculate_checksum(&mut self) {
        self.hdr.check = [0, 0]; // Zero out checksum field

        // Manual checksum calculation - unrolled for verifier
        // SAFETY: Ipv4Header is constructed only after the complete 20-byte
        // base header has passed the XDP bounds check. RST generation rejects
        // options before this fixed-header checksum path; general IPv4-option
        // policy is handled separately.
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
}

#[cfg(test)]
mod tests {
    use super::Ipv4Header;
    use network_types::ip::{IpProto, Ipv4Hdr};

    fn ipv4_header(vihl: u8, fragments: u16) -> Ipv4Hdr {
        Ipv4Hdr {
            vihl,
            tos: 0,
            tot_len: 60u16.to_be_bytes(),
            id: 123u16.to_be_bytes(),
            frags: fragments.to_be_bytes(),
            ttl: 1,
            proto: IpProto::Tcp,
            check: [0xff, 0xff],
            src_addr: [192, 0, 2, 1],
            dst_addr: [198, 51, 100, 2],
        }
    }

    fn checksum_is_valid(header: &Ipv4Hdr) -> bool {
        // SAFETY: Ipv4Hdr has a stable C layout and the slice covers exactly
        // the live header value for the duration of this calculation.
        let bytes = unsafe {
            core::slice::from_raw_parts(header as *const Ipv4Hdr as *const u8, Ipv4Hdr::LEN)
        };
        let mut sum = 0u32;

        for word in bytes.chunks_exact(2) {
            sum += u16::from_be_bytes([word[0], word[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        sum == 0xffff
    }

    #[test]
    fn tcp_processing_requires_fixed_unfragmented_ipv4_header() {
        let cases = [
            (0x45, 0x0000, 40, true),
            (0x45, 0x4000, 40, true),
            (0x46, 0x0000, 40, false),
            (0x44, 0x0000, 40, false),
            (0x55, 0x0000, 40, false),
            (0x45, 0x8000, 40, false),
            (0x45, 0x2000, 40, false),
            (0x45, 0x0001, 40, false),
            (0x45, 0x0000, 39, false),
        ];

        for (vihl, fragments, total_len, expected) in cases {
            let mut raw = ipv4_header(vihl, fragments);
            raw.set_tot_len(total_len);
            let header = Ipv4Header::new(&mut raw);
            assert_eq!(header.supports_tcp_processing(), expected);
        }
    }

    #[test]
    fn response_rewrite_sets_fields_and_valid_checksum() {
        let mut raw = ipv4_header(0x45, 0x4000);

        Ipv4Header::new(&mut raw).write_response_header(0xc633_6402, 0xc000_0201, 40, 64);

        assert_eq!(raw.src_addr, [198, 51, 100, 2]);
        assert_eq!(raw.dst_addr, [192, 0, 2, 1]);
        assert_eq!(raw.tot_len, 40u16.to_be_bytes());
        assert_eq!(raw.ttl, 64);
        assert!(checksum_is_valid(&raw));
    }
}
