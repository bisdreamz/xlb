use crate::net::checksum::fold_checksum;
use aya_ebpf::helpers::bpf_csum_diff;
use xlb_common::XlbErr;

/// Calculate TCP checksum including pseudo-header using BPF helpers.
///
/// Uses `bpf_csum_diff` to efficiently calculate checksum over pseudo-header
/// and TCP segment.
///
/// **Automatically inverts the final checksum (ones' complement).**
///
/// # Parameters
/// - `src_ip`: Source IP address (host byte order)
/// - `dst_ip`: Destination IP address (host byte order)
/// - `tcp_hdr`: Pointer to TCP header (checksum field should be zeroed)
/// - `tcp_len_bytes`: Total TCP segment length in bytes (header + data)
///
/// # Returns
/// 16-bit checksum in network byte order, ready to write to TCP header
pub(super) fn calculate_tcp_checksum(
    src_ip: u32,
    dst_ip: u32,
    tcp_hdr: *const u8,
    tcp_len_bytes: u32,
) -> [u8; 2] {
    // Build pseudo-header: src_ip, dst_ip, zero+protocol, tcp_length
    let pseudo_header = [
        src_ip.to_be(),
        dst_ip.to_be(),
        ((6u32 << 16) | (tcp_len_bytes & 0xffff)).to_be(),
    ];

    // Checksum pseudo-header
    let csum = unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            pseudo_header.as_ptr() as *mut u32,
            12, // 3 u32s = 12 bytes
            0,
        )
    };

    // Add TCP header + data to checksum
    let csum = unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            tcp_hdr as *mut u32,
            tcp_len_bytes,
            csum as u32,
        )
    };

    (!fold_checksum(csum as u64)).to_be_bytes()
}

/// Calculate TCP checksum with explicit bounds checking for eBPF verifier.
///
/// This version validates that tcp_hdr + tcp_len_bytes <= data_end before
/// calling bpf_csum_diff, satisfying verifier requirements.
///
/// # Parameters
/// - `src_ip`: Source IP address (host byte order)
/// - `dst_ip`: Destination IP address (host byte order)
/// - `tcp_hdr`: Pointer to TCP header (checksum field should be zeroed)
/// - `tcp_len_bytes`: TCP segment length (header + data) in bytes
/// - `data_end`: End of packet data (from XdpContext)
///
/// # Returns
/// 16-bit checksum in network byte order, or error if bounds check fails
pub(super) fn calculate_tcp_checksum_checked(
    src_ip: u32,
    dst_ip: u32,
    tcp_hdr: *const u8,
    tcp_len_bytes: u32,
    data_end: usize,
) -> Result<[u8; 2], XlbErr> {
    let tcp_ptr = tcp_hdr as usize;

    if tcp_ptr >= data_end || tcp_len_bytes == 0 {
        return Err(XlbErr::ErrInvalidOp);
    }

    let available = data_end
        .checked_sub(tcp_ptr)
        .and_then(|rem| u32::try_from(rem).ok())
        .ok_or(XlbErr::ErrInvalidOp)?;

    let mut tcp_len_bytes = tcp_len_bytes;
    if tcp_len_bytes > available {
        tcp_len_bytes = available;
    }

    if tcp_len_bytes == 0 {
        return Err(XlbErr::ErrInvalidOp);
    }

    Ok(calculate_tcp_checksum(
        src_ip,
        dst_ip,
        tcp_hdr,
        tcp_len_bytes,
    ))
}
