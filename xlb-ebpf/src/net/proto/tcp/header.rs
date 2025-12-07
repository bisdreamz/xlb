use super::utils::{calculate_segment_length, get_header_len, truncate_payload_for_rst};
use aya_ebpf::programs::XdpContext;
use network_types::tcp::TcpHdr;
use xlb_common::XlbErr;

/// Wrapper around TCP header for safe manipulation and checksum management.
///
/// Port-modifying methods automatically update the TCP checksum (which includes
/// IP addresses in the pseudo-header). The `to_rst()` method transforms a packet
/// into a RST response following RFC 793.
pub struct TcpHeader<'a> {
    hdr: &'a mut TcpHdr,
}

impl<'a> TcpHeader<'a> {
    pub fn new(ptr: *mut TcpHdr) -> Self {
        Self {
            hdr: unsafe { &mut *ptr },
        }
    }

    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const TcpHdr {
        self.hdr as *const TcpHdr
    }

    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.hdr.source)
    }

    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.hdr.dest)
    }

    pub fn is_syn(&self) -> bool {
        self.hdr.syn() != 0
    }

    pub fn is_fin(&self) -> bool {
        self.hdr.fin() != 0
    }

    pub fn is_rst(&self) -> bool {
        self.hdr.rst() != 0
    }

    /// Set both source and destination ports without updating checksum.
    ///
    /// Use this when you plan to fully recalculate the checksum afterwards.
    pub fn set_ports_no_checksum(&mut self, new_src: u16, new_dst: u16) {
        self.hdr.source = new_src.to_be_bytes();
        self.hdr.dest = new_dst.to_be_bytes();
    }


    /// Transform this packet into a RST response per RFC 793.
    ///
    /// Handles both ACK and non-ACK cases with proper sequence number calculation.
    /// Uses actual segment length (data + SYN + FIN) for RFC-compliant ACK values.
    ///
    /// **Must be called AFTER IP addresses have been swapped.**
    ///
    /// # Parameters
    /// - `ctx`: XDP context (needed for tail adjustments)
    /// - `src_ip`, `dst_ip`: IP addresses (host byte order) for checksum pseudo-header
    /// - `ip_total_len_bytes`: Total length from IP header in bytes (for segment length calculation)
    /// - `ip_hdr_len_bytes`: IP header length in bytes (for segment length calculation)
    ///
    /// # Returns
    /// Updated IP total length (header + TCP header) after payload truncation.
    pub fn rst(
        &mut self,
        ctx: &XdpContext,
        src_ip: u32,
        dst_ip: u32,
        ip_total_len_bytes: u16,
        ip_hdr_len_bytes: u8,
    ) -> Result<u16, XlbErr> {
        self.swap_ports();

        let incoming_ack = u32::from_be_bytes(self.hdr.ack_seq);
        let incoming_seq = u32::from_be_bytes(self.hdr.seq);

        if self.hdr.ack() != 0 {
            // RFC 793 If ACK is on, RST.SEQ = incoming.ACK
            self.hdr.seq = incoming_ack.to_be_bytes();

            self.set_rst_flags(false);
        } else {
            // RFC 793 If ACK is off, RST.SEQ = 0, RST.ACK = incoming.SEQ + SEG.LEN
            let seg_len = calculate_segment_length(self.hdr, ip_total_len_bytes, ip_hdr_len_bytes);

            self.hdr.seq = 0u32.to_be_bytes();
            self.hdr.ack_seq = incoming_seq.wrapping_add(seg_len).to_be_bytes();

            self.set_rst_flags(true);
        }

        self.clear_window_and_urgent();

        let tcp_len_bytes = get_header_len(self.hdr);
        let new_total_len =
            truncate_payload_for_rst(ctx, ip_total_len_bytes, ip_hdr_len_bytes, tcp_len_bytes)?;

        self.recalc_checksum(src_ip, dst_ip, tcp_len_bytes);

        Ok(new_total_len)
    }

    fn swap_ports(&mut self) {
        let tmp = self.hdr.source;

        self.hdr.source = self.hdr.dest;
        self.hdr.dest = tmp;
    }

    fn set_rst_flags(&mut self, with_ack: bool) {
        self.hdr.set_fin(0);
        self.hdr.set_syn(0);
        self.hdr.set_rst(1);
        self.hdr.set_psh(0);
        self.hdr.set_ack(if with_ack { 1 } else { 0 });
        self.hdr.set_urg(0);
    }

    fn clear_window_and_urgent(&mut self) {
        self.hdr.window = 0u16.to_be_bytes();
        self.hdr.urg_ptr = 0u16.to_be_bytes();
    }

    /// Recalculate TCP checksum from scratch using manual calculation.
    ///
    /// Used by RST generation where we've modified multiple fields and need a clean calculation.
    /// Manually calculates pseudo-header + TCP header checksum without using bpf_csum_diff.
    fn recalc_checksum(&mut self, src_ip: u32, dst_ip: u32, tcp_len_bytes: u32) {
        // Zero checksum before calculation
        self.hdr.check = [0, 0];

        let mut sum: u32 = 0;

        // Pseudo-header: src_ip (2 words), dst_ip (2 words), protocol (6), tcp_length
        sum += (src_ip >> 16) as u16 as u32;
        sum += (src_ip & 0xFFFF) as u16 as u32;
        sum += (dst_ip >> 16) as u16 as u32;
        sum += (dst_ip & 0xFFFF) as u16 as u32;
        sum += 6u32; // TCP protocol number
        sum += tcp_len_bytes & 0xFFFF;

        // TCP header: sum 16-bit words
        // Only summing the fixed 20-byte header for RST (no options, no data)
        let hdr_ptr = self.hdr as *const TcpHdr as *const u16;
        for i in 0..10 {
            // 20 bytes = 10 words
            let word = unsafe { core::ptr::read(hdr_ptr.add(i)) };
            sum += u16::from_be(word) as u32;
        }

        // Fold carries
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);

        // One's complement and store in network byte order
        self.hdr.check = (!sum as u16).to_be_bytes();
    }

    /// Update TCP checksum for complete NAT transformation (IPs + ports) in one operation.
    ///
    /// This is more accurate than two separate incremental updates because it avoids
    /// compounding any floating point or rounding errors.
    pub fn update_checksum_for_nat(
        &mut self,
        old_src_ip: u32,
        old_dst_ip: u32,
        old_src_port: u16,
        old_dst_port: u16,
        new_src_ip: u32,
        new_dst_ip: u32,
        new_src_port: u16,
        new_dst_port: u16,
    ) {
        // RFC 1624 incremental checksum update: HC' = ~(~HC + ~m + m')
        // where HC = old checksum, m = old value, m' = new value
        let old_cksum = u16::from_be_bytes(self.hdr.check);
        let mut sum = (!old_cksum) as u32;

        // subtract old IP addresses (as 16-bit words in network byte order)
        sum += !(old_src_ip >> 16) as u16 as u32;
        sum += !(old_src_ip & 0xFFFF) as u16 as u32;
        sum += !(old_dst_ip >> 16) as u16 as u32;
        sum += !(old_dst_ip & 0xFFFF) as u16 as u32;

        sum += (new_src_ip >> 16) as u16 as u32;
        sum += (new_src_ip & 0xFFFF) as u16 as u32;
        sum += (new_dst_ip >> 16) as u16 as u32;
        sum += (new_dst_ip & 0xFFFF) as u16 as u32;

        sum += !old_src_port as u32;
        sum += !old_dst_port as u32;

        sum += new_src_port as u32;
        sum += new_dst_port as u32;

        // fold carries
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);

        self.hdr.check = (!sum as u16).to_be_bytes();
    }

}
