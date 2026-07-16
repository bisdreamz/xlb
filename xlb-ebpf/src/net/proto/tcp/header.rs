use super::utils::{calculate_segment_length, get_header_len};
use network_types::tcp::TcpHdr;
use xlb_common::XlbErr;

/// Wrapper around TCP header for safe manipulation and checksum management.
///
/// Port-modifying methods automatically update the TCP checksum (which includes
/// IP addresses in the pseudo-header). `write_rst_response` transforms a packet
/// into a reset response following RFC 9293.
pub struct TcpHeader<'a> {
    hdr: &'a mut TcpHdr,
}

impl<'a> TcpHeader<'a> {
    #[inline(always)]
    pub fn new(ptr: *mut TcpHdr) -> Self {
        Self {
            hdr: unsafe { &mut *ptr },
        }
    }

    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const TcpHdr {
        self.hdr as *const TcpHdr
    }

    /// TCP header length in bytes derived from the data offset field.
    pub fn header_len_bytes(&self) -> u32 {
        get_header_len(self.hdr)
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

    /// Transform this packet into a RST response per RFC 9293.
    ///
    /// Handles both ACK and non-ACK cases with proper sequence number calculation.
    /// Uses actual segment length (data + SYN + FIN) for RFC-compliant ACK values.
    ///
    /// The supplied IP addresses must be the response source and destination;
    /// this method does not read or mutate the IPv4 header.
    ///
    /// # Parameters
    /// - `src_ip`, `dst_ip`: Response IP addresses (host byte order) for the checksum pseudo-header
    /// - `ip_total_len_bytes`: Total length from IP header in bytes (for segment length calculation)
    /// - `ip_hdr_len_bytes`: IP header length in bytes (for segment length calculation)
    ///
    /// # Returns
    /// The target IP total length (IP header + bare TCP header).
    #[inline(always)]
    pub fn write_rst_response(
        &mut self,
        src_ip: u32,
        dst_ip: u32,
        ip_total_len_bytes: u16,
        ip_hdr_len_bytes: u8,
    ) -> Result<u16, XlbErr> {
        let incoming_tcp_len = get_header_len(self.hdr);
        let headers_len = (ip_hdr_len_bytes as u32).saturating_add(incoming_tcp_len);

        if incoming_tcp_len < TcpHdr::LEN as u32 || headers_len > ip_total_len_bytes as u32 {
            return Err(XlbErr::ErrInvalidOp);
        }

        self.swap_ports();

        let incoming_ack = u32::from_be_bytes(self.hdr.ack_seq);
        let incoming_seq = u32::from_be_bytes(self.hdr.seq);

        if self.hdr.ack() != 0 {
            // RFC 9293: If ACK is on, RST.SEQ = incoming.ACK.
            self.hdr.seq = incoming_ack.to_be_bytes();
            self.hdr.ack_seq = 0u32.to_be_bytes();

            self.set_rst_flags(false);
        } else {
            // RFC 9293: If ACK is off, RST.SEQ = 0 and
            // RST.ACK = incoming.SEQ + SEG.LEN.
            let seg_len = calculate_segment_length(self.hdr, ip_total_len_bytes, ip_hdr_len_bytes);

            self.hdr.seq = 0u32.to_be_bytes();
            self.hdr.ack_seq = incoming_seq.wrapping_add(seg_len).to_be_bytes();

            self.set_rst_flags(true);
        }

        // Drop any TCP options for the RST we emit so checksum length matches a bare header.
        self.hdr.set_doff(5);

        self.clear_window_and_urgent();

        let tcp_len_bytes = get_header_len(self.hdr);

        self.recalc_checksum(src_ip, dst_ip, tcp_len_bytes);

        Ok((ip_hdr_len_bytes as u32).saturating_add(tcp_len_bytes) as u16)
    }

    fn swap_ports(&mut self) {
        let tmp = self.hdr.source;

        self.hdr.source = self.hdr.dest;
        self.hdr.dest = tmp;
    }

    fn set_rst_flags(&mut self, with_ack: bool) {
        self.hdr.set_res1(0);
        self.hdr.set_fin(0);
        self.hdr.set_syn(0);
        self.hdr.set_rst(1);
        self.hdr.set_psh(0);
        self.hdr.set_ack(if with_ack { 1 } else { 0 });
        self.hdr.set_urg(0);
        self.hdr.set_ece(0);
        self.hdr.set_cwr(0);
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
        // SAFETY: TcpHeader is constructed only after the complete fixed
        // header has passed the XDP bounds check. A byte array avoids making
        // any stronger alignment assumption about packet data.
        let header = unsafe { &*(self.hdr as *const TcpHdr as *const [u8; TcpHdr::LEN]) };
        for i in 0..10 {
            // 20 bytes = 10 words
            sum += u16::from_be_bytes([header[i * 2], header[i * 2 + 1]]) as u32;
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

#[cfg(test)]
mod tests {
    use super::TcpHeader;
    use network_types::tcp::TcpHdr;

    const CLIENT_IP: u32 = 0xc000_0201;
    const SERVER_IP: u32 = 0xc633_6402;

    fn tcp_header(ack: bool, syn: bool, fin: bool) -> TcpHdr {
        TcpHdr {
            source: 50_000u16.to_be_bytes(),
            dest: 443u16.to_be_bytes(),
            seq: 100u32.to_be_bytes(),
            ack_seq: 900u32.to_be_bytes(),
            _bitfield_align_1: [],
            _bitfield_1: TcpHdr::new_bitfield_1(
                0xf, 5, fin as u16, syn as u16, 0, 1, ack as u16, 1, 1, 1,
            ),
            window: 65_535u16.to_be_bytes(),
            check: [0xaa, 0xbb],
            urg_ptr: 7u16.to_be_bytes(),
        }
    }

    fn checksum_is_valid(header: &TcpHdr, src_ip: u32, dst_ip: u32) -> bool {
        let mut sum = 0u32;
        sum += src_ip >> 16;
        sum += src_ip & 0xffff;
        sum += dst_ip >> 16;
        sum += dst_ip & 0xffff;
        sum += 6;
        sum += TcpHdr::LEN as u32;

        // SAFETY: TcpHdr has a stable C layout and the slice covers exactly
        // the live header value for the duration of this calculation.
        let bytes = unsafe {
            core::slice::from_raw_parts(header as *const TcpHdr as *const u8, TcpHdr::LEN)
        };
        for word in bytes.chunks_exact(2) {
            sum += u16::from_be_bytes([word[0], word[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        sum == 0xffff
    }

    fn assert_bare_rst(header: &TcpHdr, with_ack: bool) {
        assert_eq!(header.source, 443u16.to_be_bytes());
        assert_eq!(header.dest, 50_000u16.to_be_bytes());
        assert_eq!(header.doff(), 5);
        assert_eq!(header.res1(), 0);
        assert_eq!(header.fin(), 0);
        assert_eq!(header.syn(), 0);
        assert_eq!(header.rst(), 1);
        assert_eq!(header.psh(), 0);
        assert_eq!(header.ack(), with_ack as u16);
        assert_eq!(header.urg(), 0);
        assert_eq!(header.ece(), 0);
        assert_eq!(header.cwr(), 0);
        assert_eq!(header.window, 0u16.to_be_bytes());
        assert_eq!(header.urg_ptr, 0u16.to_be_bytes());
        assert!(checksum_is_valid(header, SERVER_IP, CLIENT_IP));
    }

    #[test]
    fn ack_segment_generates_rst_with_ack_sequence() {
        let mut raw = tcp_header(true, false, false);

        let total_len = TcpHeader::new(&mut raw)
            .write_rst_response(SERVER_IP, CLIENT_IP, 60, 20)
            .expect("valid ACK segment should produce a reset");

        assert_eq!(total_len, 40);
        assert_eq!(raw.seq, 900u32.to_be_bytes());
        assert_eq!(raw.ack_seq, 0u32.to_be_bytes());
        assert_bare_rst(&raw, false);
    }

    #[test]
    fn non_ack_segment_acknowledges_data_syn_and_fin() {
        let mut raw = tcp_header(false, true, true);

        let total_len = TcpHeader::new(&mut raw)
            .write_rst_response(SERVER_IP, CLIENT_IP, 45, 20)
            .expect("valid non-ACK segment should produce a reset");

        assert_eq!(total_len, 40);
        assert_eq!(raw.seq, 0u32.to_be_bytes());
        assert_eq!(raw.ack_seq, 107u32.to_be_bytes());
        assert_bare_rst(&raw, true);
    }

    #[test]
    fn malformed_tcp_header_lengths_are_rejected_before_mutation() {
        let mut short_header = tcp_header(false, true, false);
        short_header.set_doff(4);

        assert!(
            TcpHeader::new(&mut short_header)
                .write_rst_response(SERVER_IP, CLIENT_IP, 40, 20)
                .is_err()
        );
        assert_eq!(short_header.source, 50_000u16.to_be_bytes());
        assert_eq!(short_header.dest, 443u16.to_be_bytes());
        assert_eq!(short_header.syn(), 1);

        let mut truncated_options = tcp_header(false, true, false);
        truncated_options.set_doff(15);

        assert!(
            TcpHeader::new(&mut truncated_options)
                .write_rst_response(SERVER_IP, CLIENT_IP, 40, 20)
                .is_err()
        );
        assert_eq!(truncated_options.source, 50_000u16.to_be_bytes());
        assert_eq!(truncated_options.dest, 443u16.to_be_bytes());
        assert_eq!(truncated_options.syn(), 1);
    }
}
