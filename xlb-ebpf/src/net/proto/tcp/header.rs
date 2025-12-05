use super::checksum::{calculate_tcp_checksum, calculate_tcp_checksum_checked};
use super::utils::{calculate_segment_length, get_header_len, truncate_payload_for_rst};
use crate::net::checksum::fold_checksum;
use aya_ebpf::helpers::bpf_csum_diff;
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

    pub fn as_ptr(&self) -> *const TcpHdr {
        self.hdr as *const TcpHdr
    }

    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.hdr.source)
    }

    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.hdr.dest)
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.hdr.check)
    }

    pub fn checksum_bytes(&self) -> [u8; 2] {
        self.hdr.check
    }

    /// Verify TCP checksum is correct by recalculating over header only.
    /// Returns (incoming_checksum, calculated_checksum) for debugging.
    ///
    /// This only checksums the TCP header (20 bytes), not payload, so it won't
    /// match perfectly but helps debug if incoming checksum is completely invalid.
    pub fn verify_checksum_header_only(&self, src_ip: u32, dst_ip: u32) -> (u16, u16) {
        let incoming = self.checksum();

        // Calculate what checksum should be for just pseudo-header + TCP header
        let mut sum: u32 = 0;

        // Pseudo-header
        sum += (src_ip >> 16) as u16 as u32;
        sum += (src_ip & 0xFFFF) as u16 as u32;
        sum += (dst_ip >> 16) as u16 as u32;
        sum += (dst_ip & 0xFFFF) as u16 as u32;
        sum += 6u32;  // TCP protocol
        sum += 20u32; // Just header length

        // TCP header (with checksum field zeroed)
        let hdr_bytes = unsafe { &*(self.hdr as *const TcpHdr as *const [u8; 20]) };

        for i in 0..10 {
            if i == 8 {
                // Skip checksum field (bytes 16-17)
                continue;
            }
            let offset = i * 2;
            let word = u16::from_be_bytes([hdr_bytes[offset], hdr_bytes[offset + 1]]);
            sum += word as u32;
        }

        // Fold carries
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);

        let calculated = !sum as u16;

        (incoming, calculated)
    }

    pub fn is_syn(&self) -> bool {
        self.hdr.syn() != 0
    }

    /// Set both source and destination ports.
    ///
    /// **Automatically updates TCP checksum** using incremental calculation.
    pub fn set_src_dst_ports(&mut self, new_src: u16, new_dst: u16) {
        self.update_checksum_for_ports(new_src, new_dst);

        self.hdr.source = new_src.to_be_bytes();
        self.hdr.dest = new_dst.to_be_bytes();
    }

    /// Set both source and destination ports without updating checksum.
    ///
    /// Use this when you plan to fully recalculate the checksum afterwards.
    pub fn set_ports_no_checksum(&mut self, new_src: u16, new_dst: u16) {
        self.hdr.source = new_src.to_be_bytes();
        self.hdr.dest = new_dst.to_be_bytes();
    }

    /// Zero out the TCP checksum field.
    ///
    /// This signals to the kernel/NIC to compute the checksum via offloading.
    /// Use this when XDP modifies packet headers and you want to defer checksum
    /// calculation to the network stack.
    pub fn zero_checksum(&mut self) {
        self.hdr.check = [0, 0];
    }

    /// Fully recalculate TCP checksum with bounds checking for verifier.
    ///
    /// # Parameters
    /// - `src_ip`, `dst_ip`: IP addresses (host byte order) for pseudo-header
    /// - `data_end`: End of packet data from XdpContext (for bounds checking)
    pub fn recalc_checksum_checked(
        &mut self,
        src_ip: u32,
        dst_ip: u32,
        tcp_len_bytes: u32,
        data_end: usize,
    ) -> Result<(), XlbErr> {
        self.hdr.check = [0, 0];
        self.hdr.check = calculate_tcp_checksum_checked(
            src_ip,
            dst_ip,
            self.hdr as *const _ as *const u8,
            tcp_len_bytes,
            data_end,
        )?;
        Ok(())
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

    /// Manually recalculate TCP checksum using RFC 1071 algorithm.
    ///
    /// This avoids eBPF verifier issues with `bpf_csum_diff` by using manual summation.
    /// Uses fixed-size loops that the verifier can analyze.
    ///
    /// # Parameters
    /// - `src_ip`, `dst_ip`: IP addresses (host byte order) for pseudo-header
    /// - `tcp_len`: Total TCP segment length in bytes (header + data)
    pub fn recalc_checksum_manual(&mut self, src_ip: u32, dst_ip: u32, tcp_len: u16) {
        self.hdr.check = [0, 0];

        let mut sum: u32 = 0;

        // Pseudo-header: src_ip + dst_ip + protocol + tcp_length
        sum += (src_ip >> 16) as u16 as u32;
        sum += (src_ip & 0xFFFF) as u16 as u32;
        sum += (dst_ip >> 16) as u16 as u32;
        sum += (dst_ip & 0xFFFF) as u16 as u32;
        sum += 6u32;  // TCP protocol
        sum += tcp_len as u32;

        // Add TCP header (minimum 20 bytes = 10 words)
        let hdr_bytes = unsafe { &*(self.hdr as *const TcpHdr as *const [u8; 20]) };

        // Unrolled loop for exactly 10 x u16 words (20 bytes)
        sum += u16::from_be_bytes([hdr_bytes[0], hdr_bytes[1]]) as u32;
        sum += u16::from_be_bytes([hdr_bytes[2], hdr_bytes[3]]) as u32;
        sum += u16::from_be_bytes([hdr_bytes[4], hdr_bytes[5]]) as u32;
        sum += u16::from_be_bytes([hdr_bytes[6], hdr_bytes[7]]) as u32;
        sum += u16::from_be_bytes([hdr_bytes[8], hdr_bytes[9]]) as u32;
        sum += u16::from_be_bytes([hdr_bytes[10], hdr_bytes[11]]) as u32;
        sum += u16::from_be_bytes([hdr_bytes[12], hdr_bytes[13]]) as u32;
        sum += u16::from_be_bytes([hdr_bytes[14], hdr_bytes[15]]) as u32;
        sum += u16::from_be_bytes([hdr_bytes[16], hdr_bytes[17]]) as u32;
        sum += u16::from_be_bytes([hdr_bytes[18], hdr_bytes[19]]) as u32;

        // Fold carries (max 2 iterations needed)
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);

        // One's complement
        self.hdr.check = (!(sum as u16)).to_be_bytes();
    }

    /// Fully recalculate TCP checksum from scratch.
    /// Use this when the original checksum might be invalid (e.g., from NIC offload).
    ///
    /// # Parameters
    /// - `src_ip`, `dst_ip`: IP addresses (host byte order) for pseudo-header
    /// - `tcp_len_bytes`: Total TCP segment length in bytes (header + data)
    pub fn recalc_checksum(&mut self, src_ip: u32, dst_ip: u32, tcp_len_bytes: u32) {
        self.hdr.check = [0, 0];
        self.hdr.check = calculate_tcp_checksum(
            src_ip,
            dst_ip,
            self.hdr as *const _ as *const u8,
            tcp_len_bytes,
        );
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

        // Subtract old IP addresses (as 16-bit words in network byte order)
        sum += !(old_src_ip >> 16) as u16 as u32;
        sum += !(old_src_ip & 0xFFFF) as u16 as u32;
        sum += !(old_dst_ip >> 16) as u16 as u32;
        sum += !(old_dst_ip & 0xFFFF) as u16 as u32;

        // Add new IP addresses
        sum += (new_src_ip >> 16) as u16 as u32;
        sum += (new_src_ip & 0xFFFF) as u16 as u32;
        sum += (new_dst_ip >> 16) as u16 as u32;
        sum += (new_dst_ip & 0xFFFF) as u16 as u32;

        // Subtract old ports
        sum += !old_src_port as u32;
        sum += !old_dst_port as u32;

        // Add new ports
        sum += new_src_port as u32;
        sum += new_dst_port as u32;

        // Fold carries
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);

        self.hdr.check = (!sum as u16).to_be_bytes();
    }

    /// Incrementally update TCP checksum for IP address changes in pseudo-header.
    ///
    /// When NAT rewrites IP addresses, the TCP checksum must be updated because
    /// it includes source and destination IPs in the pseudo-header calculation.
    ///
    /// # Parameters
    /// - `old_src_ip`, `old_dst_ip`: Original IP addresses (host byte order)
    /// - `new_src_ip`, `new_dst_ip`: New IP addresses (host byte order)
    pub fn update_checksum_for_ip_change(
        &mut self,
        old_src_ip: u32,
        old_dst_ip: u32,
        new_src_ip: u32,
        new_dst_ip: u32,
    ) {
        // Pack IPs as u32 array - bpf_csum_diff expects network byte order
        let old_ips = [old_src_ip.to_be(), old_dst_ip.to_be()];
        let new_ips = [new_src_ip.to_be(), new_dst_ip.to_be()];

        let seed = (!u16::from_be_bytes(self.hdr.check)) as u32;
        let csum = unsafe {
            bpf_csum_diff(
                old_ips.as_ptr() as *mut u32,
                8, // 8 bytes: two u32 IP addresses
                new_ips.as_ptr() as *mut u32,
                8,
                seed,
            )
        };

        self.hdr.check = (!fold_checksum(csum as u64)).to_be_bytes();
    }

    /// Incrementally update TCP checksum for port changes.
    ///
    /// Packs both ports as they appear in TCP header byte layout.
    fn update_checksum_for_ports(&mut self, new_src: u16, new_dst: u16) {
        // Read current checksum
        let old_cksum = u16::from_be_bytes(self.hdr.check);

        // Get old and new port values (already in host byte order from src_port/dst_port)
        let old_src = self.src_port();
        let old_dst = self.dst_port();

        // Manual checksum update using RFC 1624 algorithm
        // new_cksum = ~(~old_cksum + ~old_data + new_data)
        let mut sum = (!old_cksum) as u32;
        sum += (!old_src) as u32;
        sum += (!old_dst) as u32;
        sum += new_src as u32;
        sum += new_dst as u32;

        // Fold carries
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);

        self.hdr.check = (!sum as u16).to_be_bytes();
    }
}
