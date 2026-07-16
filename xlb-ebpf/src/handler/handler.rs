use crate::handler::iface::Iface;
use crate::handler::types::TcpOutcome;
use crate::handler::{tcp, utils};
use crate::net::eth::MacAddr;
use crate::net::packet::Packet;
use crate::net::types::ProtoHeader;
use crate::packet_log_debug;
use aya_ebpf::maps::{Array, HashMap};
use xlb_common::XlbErr;
use xlb_common::config::ebpf::EbpfConfig;
use xlb_common::types::{Backend, Flow};

pub enum PacketEvent {
    Pass,
    Reply,
    Forward(Iface),
}

pub struct PacketHandler;

#[inline(always)]
const fn should_send_shutdown_rst(shutdown: bool, incoming_rst: bool) -> bool {
    shutdown && !incoming_rst
}

impl PacketHandler {
    pub fn handle(
        packet: &mut Packet,
        config: &EbpfConfig,
        backends: &'static Array<Backend>,
        flow_map: &'static HashMap<u64, Flow>,
        shutdown: bool,
    ) -> Result<PacketEvent, XlbErr> {
        let (direction, port_map) = match utils::should_process_packet(config, packet) {
            Some(result) => result,
            None => return Ok(PacketEvent::Pass),
        };

        packet_log_debug!(packet, "Matched {}", Into::<&'static str>::into(direction));

        match packet.proto_hdr() {
            ProtoHeader::Tcp(tcp) => {
                if should_send_shutdown_rst(shutdown, tcp.is_rst()) {
                    packet_log_debug!(packet, "Shutting down, attempting to send RST");
                    packet.rst()?;

                    return Ok(PacketEvent::Reply);
                }

                match tcp::handle_tcp_packet(
                    packet,
                    &direction,
                    backends,
                    flow_map,
                    &config.strategy,
                    port_map.remote_port,
                )? {
                    TcpOutcome::Pass => Ok(PacketEvent::Pass),
                    TcpOutcome::Reply => Ok(PacketEvent::Reply),
                    TcpOutcome::Forward(flow) => {
                        packet.reroute(
                            &MacAddr::new(flow.src_mac),
                            &MacAddr::new(flow.dst_mac),
                            flow.src_ip,
                            flow.dst_ip,
                            flow.src_port,
                            flow.dst_port,
                        )?;

                        Ok(PacketEvent::Forward(flow.iface))
                    }
                }
            }
            _ => Ok(PacketEvent::Pass),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::should_send_shutdown_rst;

    #[test]
    fn shutdown_rst_policy() {
        assert!(should_send_shutdown_rst(true, false));
        assert!(!should_send_shutdown_rst(true, true));
        assert!(!should_send_shutdown_rst(false, false));
        assert!(!should_send_shutdown_rst(false, true));
    }
}
