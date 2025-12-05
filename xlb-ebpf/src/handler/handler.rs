use crate::handler::iface::Iface;
use crate::handler::{tcp, utils};
use crate::net::packet::Packet;
use crate::net::types::ProtoHeader;
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::info;
use xlb_common::config::ebpf::EbpfConfig;
use xlb_common::types::{Backend, Flow, FlowKey};
use xlb_common::XlbErr;
use crate::net::eth::MacAddr;

pub enum PacketEvent {
    Pass,
    Forward(Iface),
}

pub struct PacketHandler;

impl PacketHandler {
    pub fn handle(ctx: &XdpContext,
        packet: &mut Packet, config: &EbpfConfig,
                  backends: &'static Array<Backend>,
                  flow_map: &'static HashMap<FlowKey, Flow>) -> Result<PacketEvent, XlbErr> {

        if !utils::matches_ipver_and_proto(packet, config) {
            return Ok(PacketEvent::Pass)
        }

        let (direction, port_map) = match utils::get_direction_port_map(ctx, config, packet) {
            Some(direction) => direction,
            None => return Ok(PacketEvent::Pass)
        };

        let dir_str:&'static str = direction.into();
        info!(&ctx, "Matched {}", dir_str);

        match packet.proto_hdr() {
            ProtoHeader::Tcp(_) => {
                let packet_flow = tcp::handle_tcp_packet(
                    packet,
                    &direction,
                    backends,
                    flow_map,
                    &config.strategy,
                    port_map.remote_port,
                )?;

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
