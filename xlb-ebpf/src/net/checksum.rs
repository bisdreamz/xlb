/// Fold a 64-bit checksum value down to 16-bit for use in IP/TCP/UDP checksums.
///
/// # What
/// Converts a 64-bit accumulated checksum into the final 16-bit checksum value
/// required by Internet Protocol headers (IP, TCP, UDP, etc).
///
/// # Why
/// BPF helpers like `bpf_csum_diff` return 64-bit values that accumulate carries.
/// Internet checksums are 16-bit ones' complement, so we must fold the carry bits
/// back into the lower 16 bits.
///
/// # When
/// Call this after:
/// - Using `bpf_csum_diff` for incremental checksum updates
/// - Accumulating multiple checksum values (e.g., pseudo-header + TCP header)
/// - Before writing the final checksum to a packet header
///
/// # Algorithm
/// 1. Add upper 48 bits into lower 16 bits (fold carries)
/// 2. Repeat once more to handle any new carries from step 1
/// 3. Result is a proper 16-bit checksum value
pub(crate) fn fold_checksum(mut csum: u64) -> u16 {
    // Collapse upper 32 bits so repeated 16-bit folds converge quickly.
    csum = (csum & 0xffff_ffff) + (csum >> 32);

    // Bound the number of iterations so the verifier can unroll it.
    for _ in 0..4 {
        if (csum >> 16) == 0 {
            break;
        }

        csum = (csum & 0xffff) + (csum >> 16);
    }

    (csum & 0xffff) as u16
}
