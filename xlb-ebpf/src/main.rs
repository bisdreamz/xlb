#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

mod net;
mod utils;

use crate::net::Packet;
use crate::net::types::IpHeader;
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{debug, info, warn};
use xlb_common::config::ebpf::EbpfConfig;

/// Shared global state config
#[unsafe(no_mangle)]
static mut CONFIG: EbpfConfig = EbpfConfig::empty();

#[unsafe(no_mangle)]
static mut SHUTDOWN: bool = false;

#[xdp]
pub fn xlb(ctx: XdpContext) -> u32 {
    let packet = match Packet::new(&ctx) {
        Ok(Some(packet)) => packet,
        Ok(None) => {
            debug!(&ctx, "Valid packet but misc protos, passing");

            return xdp_action::XDP_PASS;
        }
        Err(err) => {
            let err_str: &'static str = err.into();
            warn!(&ctx, "Failed to parse packet: {}", err_str);

            return xdp_action::XDP_ABORTED;
        }
    };

    let proto: &'static str = packet.proto().into();
    let ipv: &'static str = packet.ip_version().into();

    match packet.ip_hdr() {
        IpHeader::Ipv4(ipv4_header) => {
            info!(
                &ctx,
                "Packet parsed successfully {} -> {} @ {:i}",
                ipv,
                proto,
                ipv4_header.src_addr()
            );
        }
        IpHeader::Ipv6(_) => {
            debug!(&ctx, "IPv6 packet");
        }
    }

    xdp_action::XDP_PASS
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
