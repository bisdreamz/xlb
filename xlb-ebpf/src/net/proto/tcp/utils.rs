use aya_ebpf::{helpers::bpf_xdp_adjust_tail, programs::XdpContext};
use network_types::tcp::TcpHdr;
use xlb_common::XlbErr;

/// Shrink packet payload so only TCP header remains before emitting RST.
pub(super) fn truncate_payload_for_rst(
    ctx: &XdpContext,
    current_total_len: u16,
    ip_hdr_len_bytes: u8,
    tcp_hdr_len_bytes: u32,
) -> Result<u16, XlbErr> {
    let desired_total_len = (ip_hdr_len_bytes as u32).saturating_add(tcp_hdr_len_bytes);

    if desired_total_len > current_total_len as u32 {
        return Err(XlbErr::ErrInvalidOp);
    }

    let delta = desired_total_len as i32 - current_total_len as i32;
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };
        if ret < 0 {
            return Err(XlbErr::ErrInvalidOp);
        }
    }

    Ok(desired_total_len as u16)
}

/// Get TCP header length in bytes from data offset field.
///
/// The `doff` field specifies header length in 32-bit words, so multiply by 4
/// to get bytes. Minimum is 20 bytes (5 words), maximum is 60 bytes (15 words).
pub(super) fn get_header_len(tcp_hdr: &TcpHdr) -> u32 {
    tcp_hdr.doff() as u32 * 4
}

/// Calculate TCP segment length for RFC 793 sequence number calculations.
///
/// Per RFC 793 Section 3.3, segment length is the number of octets occupied
/// by the data in the segment, counting SYN and FIN flags as one octet each.
///
/// # Formula
/// `SEG.LEN = data_bytes + SYN + FIN`
///
/// # Parameters
/// - `tcp_hdr`: TCP header to analyze
/// - `ip_total_len_bytes`: Total length from IP header in bytes (IP header + TCP header + data)
/// - `ip_hdr_len_bytes`: IP header length in bytes
///
/// # Returns
/// Segment length for use in sequence number calculations (e.g., RST ACK generation)
pub(super) fn calculate_segment_length(
    tcp_hdr: &TcpHdr,
    ip_total_len_bytes: u16,
    ip_hdr_len_bytes: u8,
) -> u32 {
    let tcp_hdr_len = get_header_len(tcp_hdr);

    // Calculate data length: IP_total - IP_header - TCP_header
    let data_len = (ip_total_len_bytes as u32)
        .saturating_sub(ip_hdr_len_bytes as u32)
        .saturating_sub(tcp_hdr_len);

    // SYN and FIN each count as 1 byte in sequence space
    let syn = tcp_hdr.syn() as u32;
    let fin = tcp_hdr.fin() as u32;

    data_len + syn + fin
}
