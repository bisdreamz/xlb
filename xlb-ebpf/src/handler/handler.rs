use crate::handler::iface::Iface;
use crate::handler::{tcp, utils};
use crate::net::eth::MacAddr;
use crate::net::packet::Packet;
use crate::net::types::ProtoHeader;
use crate::packet_log_debug;
use aya_ebpf::maps::{Array, HashMap};
use xlb_common::config::ebpf::EbpfConfig;
use xlb_common::types::{Backend, Flow};
use xlb_common::XlbErr;

pub enum PacketEvent {
    Pass,
    Return,
    Forward(Iface),
}

pub struct PacketHandler;

impl PacketHandler {
    pub fn handle(packet: &mut Packet, config: &EbpfConfig,
                  backends: &'static Array<Backend>,
                  flow_map: &'static HashMap<u64, Flow>,
                  shutdown: bool) -> Result<PacketEvent, XlbErr> {

        let (direction, port_map) = match utils::should_process_packet(config, packet) {
            Some(result) => result,
            None => return Ok(PacketEvent::Pass)
        };

        packet_log_debug!(packet, "Matched {}", Into::<&'static str>::into(direction));

        match packet.proto_hdr() {
            ProtoHeader::Tcp(_) => {
                if shutdown {
                    packet_log_debug!(packet, "Shutting down, attempting to send RST");
                    packet.rst()?;

                    return Ok(PacketEvent::Return)
                }

                let packet_flow = match tcp::handle_tcp_packet(
                    packet,
                    &direction,
                    backends,
                    flow_map,
                    &config.strategy,
                    port_map.remote_port,
                )? {
                    Some(flow) => flow,
                    None => return Ok(PacketEvent::Pass),
                };

                packet.reroute(
                    &MacAddr::new(packet_flow.src_mac),
                    &MacAddr::new(packet_flow.dst_mac),
                    packet_flow.src_ip,
                    packet_flow.dst_ip,
                    packet_flow.src_port,
                    packet_flow.dst_port,
                )?;

                Ok(PacketEvent::Forward(packet_flow.iface))
            }
            _ => Ok(PacketEvent::Pass),
        }
    }

}
