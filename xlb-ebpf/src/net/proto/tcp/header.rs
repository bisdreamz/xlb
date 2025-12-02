use super::checksum::calculate_tcp_checksum;
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

    /// Set both source and destination ports.
    ///
    /// **Automatically updates TCP checksum** using incremental calculation.
    pub fn set_src_dst_ports(&mut self, new_src: u16, new_dst: u16) {
        self.update_checksum_for_ports(new_src, new_dst);

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

    fn recalc_checksum(&mut self, src_ip: u32, dst_ip: u32, tcp_len_bytes: u32) {
        self.hdr.check = [0, 0];
        self.hdr.check = calculate_tcp_checksum(
            src_ip,
            dst_ip,
            self.hdr as *const _ as *const u8,
            tcp_len_bytes,
        );
    }

    /// Incrementally update TCP checksum for port changes.
    ///
    /// Packs both ports into a single u32 (src in upper 16 bits, dst in lower 16 bits)
    /// for efficient 4-byte checksum delta calculation.
    fn update_checksum_for_ports(&mut self, new_src: u16, new_dst: u16) {
        // Pack ports: [src_port (16 bits) | dst_port (16 bits)]
        let old_ports = [((self.src_port() as u32) << 16 | self.dst_port() as u32).to_be()];
        let new_ports = [((new_src as u32) << 16 | new_dst as u32).to_be()];

        let seed = (!u16::from_be_bytes(self.hdr.check)) as u32;
        let csum = unsafe {
            bpf_csum_diff(
                old_ports.as_ptr() as *mut u32,
                4, // 4 bytes: both ports packed into one u32
                new_ports.as_ptr() as *mut u32,
                4,
                seed,
            )
        };

        self.hdr.check = (!fold_checksum(csum as u64)).to_be_bytes();
    }
}
