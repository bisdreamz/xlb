use aya_ebpf::bindings::bpf_fib_lookup;
use aya_ebpf::helpers::bpf_fib_lookup as bpf_fib_lookup_helper;
use aya_ebpf::programs::XdpContext;
use core::mem;
use xlb_common::net::IpVersion;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const BPF_FIB_LKUP_RET_SUCCESS: i32 = 0;
const BPF_FIB_LOOKUP_OUTPUT: u32 = 2;

#[derive(Debug, Clone)]
pub struct Iface {
    pub idx: u16,
    pub mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub src_ip: u128,
}

/// Ask the kernel what iface index and next hop mac
/// is used to reach the provided destination IP.
/// When using BPF_FIB_LOOKUP_OUTPUT flag, the kernel will perform
/// source address selection and write it back to ipv4_src/ipv6_src.
pub fn fib_lookup(ctx: &XdpContext, src_ip: u128, dst_ip: u128, ip_ver: IpVersion, tot_len: u16, flags: u32) -> Result<Iface, i32> {
    let mut params: bpf_fib_lookup = unsafe { mem::zeroed() };
    params.ifindex = ctx.ingress_ifindex() as u32;
    params.__bindgen_anon_1.tot_len = tot_len;

    // sport/dport set to 0 for basic routing (not using L4-aware FIB rules)
    params.sport = 0;
    params.dport = 0;

    match ip_ver {
        IpVersion::Ipv4 => {
            if dst_ip > u32::MAX as u128 {
                return Err(-1);
            }
            params.family = AF_INET;
            // Set src to 0 when using OUTPUT flag - kernel will select source IP
            params.__bindgen_anon_3.ipv4_src = 0;
            params.__bindgen_anon_4.ipv4_dst = (dst_ip as u32).to_be();
            params.l4_protocol = 6; // TCP
        }
        IpVersion::Ipv6 => {
            params.family = AF_INET6;
            params.__bindgen_anon_3.ipv6_src = [0, 0, 0, 0];
            params.__bindgen_anon_4.ipv6_dst = ipv6_words(dst_ip);
            params.l4_protocol = 6; // TCP
        }
    }

    let rc = unsafe {
        bpf_fib_lookup_helper(
            ctx.ctx.cast(),
            &mut params as *mut _ as *mut _,
            mem::size_of::<bpf_fib_lookup>() as i32,
            flags,
        )
    } as i32;

    if rc == BPF_FIB_LKUP_RET_SUCCESS {
        let src_ip = unsafe {
            match params.family {
                AF_INET => u128::from(params.__bindgen_anon_3.ipv4_src.to_be()),
                AF_INET6 => ipv6_from_words(params.__bindgen_anon_3.ipv6_src),
                _ => 0,
            }
        };

        Ok(Iface {
            idx: params.ifindex as u16,
            mac: params.dmac,
            src_mac: params.smac,
            src_ip,
        })
    } else {
        Err(rc)
    }
}

fn ipv6_words(ip: u128) -> [u32; 4] {
    let bytes = ip.to_be_bytes();
    [
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
    ]
}

fn ipv6_from_words(words: [u32; 4]) -> u128 {
    let b0 = words[0].to_be_bytes();
    let b1 = words[1].to_be_bytes();
    let b2 = words[2].to_be_bytes();
    let b3 = words[3].to_be_bytes();
    u128::from_be_bytes([
        b0[0], b0[1], b0[2], b0[3], b1[0], b1[1], b1[2], b1[3], b2[0], b2[1], b2[2], b2[3], b3[0],
        b3[1], b3[2], b3[3],
    ])
}
