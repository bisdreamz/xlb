#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

mod balancing;
mod handler;
mod net;
mod utils;

use crate::handler::{PacketEvent, PacketHandler};
use crate::net::packet::Packet;
use aya_ebpf::helpers::bpf_redirect;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{trace, warn};
use xlb_common::config::ebpf::EbpfConfig;
use xlb_common::consts;
use xlb_common::types::{Backend, Flow};

/// Shared global state config stored in a map for runtime updates
#[map(name = "CONFIG")]
static CONFIG: Array<EbpfConfig> = Array::with_max_entries(1, 0);

/// Shared global list of available ['Backend'] entries
/// which includes stat aggregations for live flows
#[map(name = "BACKENDS")]
static BACKENDS: Array<Backend> = Array::with_max_entries(consts::MAX_BACKENDS, 0);

#[map(name = "FLOW_MAP")]
static mut FLOW_MAP: HashMap<u64, Flow> = HashMap::with_max_entries(consts::MAX_ACTIVE_FLOWS, 0);

#[map(name = "SHUTDOWN")]
static SHUTDOWN: Array<u8> = Array::with_max_entries(1, 0);

#[xdp]
pub fn xlb(ctx: XdpContext) -> u32 {
    let mut packet = match Packet::new(&ctx) {
        Ok(Some(packet)) => packet,
        Ok(None) => {
            #[cfg(feature = "verbose-logs")]
            trace!(&ctx, "Valid packet but misc protos, passing");

            return xdp_action::XDP_PASS;
        }
        Err(err) => {
            let err_str: &'static str = err.into();
            warn!(&ctx, "Failed to parse packet: {}", err_str);

            return xdp_action::XDP_ABORTED;
        }
    };

    let config = match CONFIG.get_ptr(0) {
        Some(ptr) => unsafe { &*ptr },
        None => {
            warn!(&ctx, "CONFIG map is empty");
            return xdp_action::XDP_ABORTED;
        }
    };
    let flow_map = core::ptr::addr_of_mut!(FLOW_MAP);
    let shutdown = SHUTDOWN.get(0).map(|v| *v != 0).unwrap_or(false);

    unsafe {
        match PacketHandler::handle(&mut packet, config, &BACKENDS, &*flow_map, shutdown) {
            Ok(action) => match action {
                PacketEvent::Pass => {
                    packet_log_trace!(packet, "Handle pass");

                    xdp_action::XDP_PASS
                }
                PacketEvent::Return => {
                    packet_log_trace!(packet, "Handle return");

                    xdp_action::XDP_TX
                }
                PacketEvent::Forward(iface) => {
                    packet_log_debug!(packet, "Handle OK");
                    packet_log_trace!(
                        packet,
                        "Forwarding to iface {} (ingress={})",
                        iface.idx,
                        ctx.ingress_ifindex()
                    );

                    bpf_redirect(iface.idx as u32, 0) as u32
                }
            },
            Err(xlb_err) => {
                let err_str: &'static str = xlb_err.into();
                packet_log_warn!(packet, "Failed to handle packet: {}", err_str);

                xdp_action::XDP_DROP
            }
        }
    }
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
