#![no_std]
#![no_main]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

mod net;
mod utils;
mod handler;
mod balancing;

use crate::handler::{PacketEvent, PacketHandler};
use crate::net::packet::Packet;
use crate::net::types::IpHeader;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_ebpf::helpers::bpf_redirect;
use aya_log_ebpf::{debug, info, warn};
use xlb_common::config::ebpf::EbpfConfig;
use xlb_common::types::{Backend, Flow, FlowDirection, FlowKey};
use xlb_common::{consts, XlbErr};

/// Shared global state config stored in a map for runtime updates
#[map(name = "CONFIG")]
static CONFIG: Array<EbpfConfig> = Array::with_max_entries(1, 0);

/// Shared global list of available ['Backend'] entries
/// which includes stat aggregations for live flows
#[map(name = "BACKENDS")]
static BACKENDS: Array<Backend> = Array::with_max_entries(consts::MAX_BACKENDS, 0);

#[map(name = "FLOW_MAP")]
static mut FLOW_MAP: HashMap<FlowKey, Flow> = HashMap::with_max_entries(consts::MAX_ACTIVE_FLOWS, 0);

#[unsafe(no_mangle)]
static mut SHUTDOWN: bool = false;

#[xdp]
pub fn xlb(ctx: XdpContext) -> u32 {
    let mut packet = match Packet::new(&ctx) {
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

    let config = match CONFIG.get_ptr(0) {
        Some(ptr) => unsafe { &*ptr },
        None => {
            warn!(&ctx, "CONFIG map is empty");
            return xdp_action::XDP_ABORTED;
        }
    };
    let flow_map = unsafe { core::ptr::addr_of_mut!(FLOW_MAP) };

    unsafe {
        match PacketHandler::handle(&ctx, &mut packet, config, &BACKENDS, &*flow_map) {
            Ok(action) => {
                match action {
                    PacketEvent::Pass => {
                        info!(&ctx, "Handle pass");

                        xdp_action::XDP_PASS
                    },
                    PacketEvent::Forward(iface) => {
                        info!(&ctx, "Handle OK");

                        let ingress_ifindex = ctx.ingress_ifindex() as u32;
                        
                        info!(&ctx, "Forwarding to iface {} (ingress={})", iface.idx, ingress_ifindex);

                        let ret = bpf_redirect(iface.idx as u32, 0);
                        info!(&ctx, "bpf_redirect returned: {}", ret);
                        ret as u32
                    }
                }
            }
            Err(xlb_err) => {
                let err_str: &'static str = xlb_err.into();
                warn!(&ctx, "Failed to handle packet: {}", err_str);

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
