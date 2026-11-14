//! Client and physical-node routing rules.
//!
//! This is the security-sensitive part of the multiplexer. It decides what a
//! client may send to the radio and what the radio may send to clients. The
//! rules mirror the original `message_router.py`, including the quirks:
//!
//! * `ADMIN_APP` is allowed from loopback, an allowlist, or when a client
//!   addresses the packet to itself (`from == to`).
//! * `removeByNodenum` is answered with a fabricated routing ACK so the app's
//!   delete gesture does not hang; the real command is never forwarded.
//! * `addContact` is blocked from every client, including loopback.
//! * PKI encryption is stripped from `from == 0` packets.
//! * Node config dumps are not broadcast to clients (they get a replay).

use std::net::IpAddr;
use std::str::FromStr;

use meshtastic::protobufs::{self as pb, admin_message, from_radio, routing, to_radio};
use meshtastic::Message;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    /// Parse `addr` or `addr/prefix`. `addr` alone matches exactly one host.
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.is_empty() || value.eq_ignore_ascii_case("localhost") {
            return None;
        }

        let (addr, prefix) = match value.split_once('/') {
            Some((addr, prefix)) => (
                IpAddr::from_str(addr).ok()?,
                Some(prefix.parse::<u8>().ok()?),
            ),
            None => (IpAddr::from_str(value).ok()?, None),
        };

        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return None;
        }
        Some(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = v4_mask(self.prefix);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = v6_mask(self.prefix);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAction {
    /// Send these unframed `ToRadio` bytes to the physical node.
    Forward(Vec<u8>),
    /// Send these unframed `FromRadio` bytes back to the requesting client.
    Reply(Vec<u8>),
    /// Hand an MQTT proxy message to the bridge (Phase 2).
    Proxy {
        topic: String,
        payload: Vec<u8>,
        retained: bool,
    },
    /// Handled locally, nothing to forward or reply.
    Ignore,
    /// Rejected by a security rule.
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRoute {
    pub action: ClientAction,
    /// Ask the daemon to re-read the node config after a settings write.
    pub resync: bool,
}

impl ClientRoute {
    fn ignore() -> Self {
        Self {
            action: ClientAction::Ignore,
            resync: false,
        }
    }

    fn blocked() -> Self {
        Self {
            action: ClientAction::Blocked,
            resync: false,
        }
    }
}

pub struct ClientContext<'a> {
    pub ip: IpAddr,
    pub node_num: u32,
    pub allow_admin_from: &'a [Cidr],
    pub blocked_portnums: &'a [i32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhysicalRoute {
    /// Forward the original bytes to every connected client.
    Broadcast,
    /// Suppress the node's own config dump (clients get a replay instead).
    ConfigDump,
    /// Divert an MQTT proxy frame to the bridge.
    Proxy {
        topic: String,
        payload: Vec<u8>,
        retained: bool,
    },
}

/// Route one `ToRadio` frame received from an app.
pub fn route_from_client(raw: &[u8], ctx: &ClientContext<'_>) -> ClientRoute {
    let Ok(to_radio) = pb::ToRadio::decode(raw) else {
        return ClientRoute::blocked();
    };
    route_from_client_decoded(&to_radio, ctx)
}

/// Route a `ToRadio` message that the caller has already decoded.
pub fn route_from_client_decoded(to_radio: &pb::ToRadio, ctx: &ClientContext<'_>) -> ClientRoute {
    match &to_radio.payload_variant {
        Some(to_radio::PayloadVariant::Disconnect(_))
        | Some(to_radio::PayloadVariant::Heartbeat(_))
        | Some(to_radio::PayloadVariant::WantConfigId(_)) => ClientRoute::ignore(),
        Some(to_radio::PayloadVariant::MqttClientProxyMessage(msg)) => ClientRoute {
            action: ClientAction::Proxy {
                topic: msg.topic.clone(),
                payload: proxy_payload(msg),
                retained: msg.retained,
            },
            resync: false,
        },
        Some(to_radio::PayloadVariant::Packet(packet)) => route_packet(to_radio, packet, ctx),
        _ => ClientRoute::ignore(),
    }
}

fn route_packet(
    to_radio: &pb::ToRadio,
    packet: &pb::MeshPacket,
    ctx: &ClientContext<'_>,
) -> ClientRoute {
    let portnum = match &packet.payload_variant {
        Some(pb::mesh_packet::PayloadVariant::Decoded(data)) => Some(data.portnum),
        _ => None,
    };

    let mut resync = false;

    if portnum == Some(pb::PortNum::AdminApp as i32) {
        if !admin_allowed(packet, ctx) {
            return ClientRoute::blocked();
        }

        if let Some(pb::mesh_packet::PayloadVariant::Decoded(data)) = &packet.payload_variant {
            if let Ok(admin) = pb::AdminMessage::decode(data.payload.as_slice()) {
                if let Some(variant) = &admin.payload_variant {
                    match variant {
                        admin_message::PayloadVariant::RemoveByNodenum(_node_num) => {
                            return ClientRoute {
                                action: ClientAction::Reply(build_fake_routing_ack(
                                    packet.id,
                                    packet,
                                    ctx.node_num,
                                )),
                                resync: false,
                            };
                        }
                        admin_message::PayloadVariant::AddContact(_) => {
                            return ClientRoute::blocked();
                        }
                        _ => resync = is_settings_write(variant),
                    }
                }
            }
        }
    } else if portnum.is_some_and(|portnum| ctx.blocked_portnums.contains(&portnum)) {
        return ClientRoute::blocked();
    }

    // Android sends PKI-encrypted packets with from=0; the node has no key for
    // node 0, so strip the encryption before forwarding.
    let forward = if packet.from == 0 && packet.pki_encrypted {
        let mut stripped = to_radio.clone();
        if let Some(to_radio::PayloadVariant::Packet(pkt)) = &mut stripped.payload_variant {
            pkt.pki_encrypted = false;
            pkt.public_key.clear();
        }
        stripped.encode_to_vec()
    } else {
        to_radio.encode_to_vec()
    };

    ClientRoute {
        action: ClientAction::Forward(forward),
        resync,
    }
}

fn admin_allowed(packet: &pb::MeshPacket, ctx: &ClientContext<'_>) -> bool {
    if packet.from != 0 && packet.from == packet.to {
        return true;
    }
    if ctx.ip.is_loopback() {
        return true;
    }
    ctx.allow_admin_from
        .iter()
        .any(|cidr| cidr.contains(ctx.ip))
}

fn is_settings_write(variant: &admin_message::PayloadVariant) -> bool {
    use admin_message::PayloadVariant as V;
    matches!(
        variant,
        V::SetHamMode(_)
            | V::SetScale(_)
            | V::SetOwner(_)
            | V::SetChannel(_)
            | V::SetConfig(_)
            | V::SetModuleConfig(_)
            | V::SetCannedMessageModuleMessages(_)
            | V::SetRingtoneMessage(_)
            | V::SetFavoriteNode(_)
            | V::SetFixedPosition(_)
            | V::SetIgnoredNode(_)
            | V::BeginEditSettings(_)
            | V::CommitEditSettings(_)
            | V::RemoveFavoriteNode(_)
            | V::RemoveFixedPosition(_)
            | V::RemoveIgnoredNode(_)
            | V::RemoveBackupPreferences(_)
    )
}

/// Fabricate a successful routing ACK for `removeByNodenum`.
fn build_fake_routing_ack(request_id: u32, packet: &pb::MeshPacket, node_num: u32) -> Vec<u8> {
    let requester = if packet.from != 0 {
        packet.from
    } else {
        node_num
    };

    let routing = pb::Routing {
        variant: Some(routing::Variant::ErrorReason(routing::Error::None as i32)),
    };
    let data = pb::Data {
        portnum: pb::PortNum::RoutingApp as i32,
        payload: routing.encode_to_vec(),
        request_id,
        ..Default::default()
    };
    let ack = pb::MeshPacket {
        id: request_id,
        from: node_num,
        to: requester,
        payload_variant: Some(pb::mesh_packet::PayloadVariant::Decoded(data)),
        ..Default::default()
    };
    pb::FromRadio {
        id: 0,
        payload_variant: Some(from_radio::PayloadVariant::Packet(ack)),
    }
    .encode_to_vec()
}

/// Route one already-decoded `FromRadio` frame received from the physical node.
pub fn route_from_physical(fr: &pb::FromRadio) -> PhysicalRoute {
    match &fr.payload_variant {
        Some(from_radio::PayloadVariant::MyInfo(_))
        | Some(from_radio::PayloadVariant::NodeInfo(_))
        | Some(from_radio::PayloadVariant::Config(_))
        | Some(from_radio::PayloadVariant::ModuleConfig(_))
        | Some(from_radio::PayloadVariant::Channel(_))
        | Some(from_radio::PayloadVariant::Metadata(_))
        | Some(from_radio::PayloadVariant::ConfigCompleteId(_))
        | Some(from_radio::PayloadVariant::FileInfo(_))
        | Some(from_radio::PayloadVariant::DeviceuiConfig(_)) => PhysicalRoute::ConfigDump,
        Some(from_radio::PayloadVariant::MqttClientProxyMessage(msg)) => PhysicalRoute::Proxy {
            topic: msg.topic.clone(),
            payload: proxy_payload(msg),
            retained: msg.retained,
        },
        _ => PhysicalRoute::Broadcast,
    }
}

fn proxy_payload(msg: &pb::MqttClientProxyMessage) -> Vec<u8> {
    use pb::mqtt_client_proxy_message::PayloadVariant as V;
    match &msg.payload_variant {
        Some(V::Data(data)) if !data.is_empty() => data.clone(),
        Some(V::Text(text)) if !text.is_empty() => text.clone().into_bytes(),
        _ => Vec::new(),
    }
}

/// Encode the framed heartbeat reply the daemon sends to a client.
pub fn queue_status_reply() -> Vec<u8> {
    let fr = pb::FromRadio {
        id: 0,
        payload_variant: Some(from_radio::PayloadVariant::QueueStatus(pb::QueueStatus {
            res: 0,
            free: 32,
            maxlen: 32,
            mesh_packet_id: 0,
        })),
    };
    fr.encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn admin_packet(admin: pb::AdminMessage) -> pb::ToRadio {
        let data = pb::Data {
            portnum: pb::PortNum::AdminApp as i32,
            payload: admin.encode_to_vec(),
            ..Default::default()
        };
        let packet = pb::MeshPacket {
            id: 9,
            from: 7,
            to: 7,
            payload_variant: Some(pb::mesh_packet::PayloadVariant::Decoded(data)),
            ..Default::default()
        };
        pb::ToRadio {
            payload_variant: Some(to_radio::PayloadVariant::Packet(packet)),
        }
    }

    fn ctx(ip: &str, allow: &[Cidr]) -> (IpAddr, Vec<Cidr>) {
        (ip.parse().unwrap(), allow.to_vec())
    }

    #[test]
    fn parses_and_matches_cidrs() {
        let cidr = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(cidr.contains("192.168.1.42".parse().unwrap()));
        assert!(!cidr.contains("192.168.2.1".parse().unwrap()));

        let exact = Cidr::parse("10.0.0.1").unwrap();
        assert!(exact.contains("10.0.0.1".parse().unwrap()));
        assert!(!exact.contains("10.0.0.2".parse().unwrap()));

        assert!(Cidr::parse("localhost").is_none());
        assert!(Cidr::parse("not-an-ip").is_none());
    }

    #[test]
    fn admin_is_blocked_from_remote_ips_without_an_allowlist() {
        let (ip, allow) = ctx("203.0.113.9", &[]);
        let to_radio = admin_packet(pb::AdminMessage {
            payload_variant: Some(admin_message::PayloadVariant::SetOwner(Default::default())),
            ..Default::default()
        });
        // from == to is the self-addressed bypass; make it a remote-addressed packet.
        let mut to_radio = to_radio;
        if let Some(to_radio::PayloadVariant::Packet(pkt)) = &mut to_radio.payload_variant {
            pkt.to = 99;
        }
        let route = route_from_client(
            &to_radio.encode_to_vec(),
            &ClientContext {
                ip,
                node_num: 7,
                allow_admin_from: &allow,
                blocked_portnums: &[],
            },
        );
        assert_eq!(route.action, ClientAction::Blocked);
    }

    #[test]
    fn admin_is_allowed_from_loopback_and_self_addressed() {
        let admin = pb::AdminMessage {
            payload_variant: Some(admin_message::PayloadVariant::SetOwner(Default::default())),
            ..Default::default()
        };

        let to_radio = admin_packet(admin.clone());
        let mut to_radio_remote = to_radio.clone();
        if let Some(to_radio::PayloadVariant::Packet(pkt)) = &mut to_radio_remote.payload_variant {
            pkt.to = 99;
        }

        let (ip, allow) = ctx("127.0.0.1", &[]);
        let route = route_from_client(
            &to_radio_remote.encode_to_vec(),
            &ClientContext {
                ip,
                node_num: 7,
                allow_admin_from: &allow,
                blocked_portnums: &[],
            },
        );
        assert!(matches!(route.action, ClientAction::Forward(_)));
        assert!(route.resync);

        let (ip, allow) = ctx("203.0.113.9", &[]);
        let route = route_from_client(
            &to_radio.encode_to_vec(),
            &ClientContext {
                ip,
                node_num: 7,
                allow_admin_from: &allow,
                blocked_portnums: &[],
            },
        );
        assert!(matches!(route.action, ClientAction::Forward(_)));
    }

    #[test]
    fn remove_by_nodenum_gets_a_fake_ack() {
        let to_radio = admin_packet(pb::AdminMessage {
            payload_variant: Some(admin_message::PayloadVariant::RemoveByNodenum(123)),
            ..Default::default()
        });
        let (ip, allow) = ctx("127.0.0.1", &[]);
        let route = route_from_client(
            &to_radio.encode_to_vec(),
            &ClientContext {
                ip,
                node_num: 7,
                allow_admin_from: &allow,
                blocked_portnums: &[],
            },
        );

        let ClientAction::Reply(bytes) = route.action else {
            panic!("expected a reply");
        };
        let fr = pb::FromRadio::decode(bytes.as_slice()).unwrap();
        let Some(from_radio::PayloadVariant::Packet(pkt)) = fr.payload_variant else {
            panic!("expected a packet");
        };
        assert_eq!(pkt.from, 7);
        assert_eq!(pkt.to, 7);
        assert_eq!(pkt.id, 9);
    }

    #[test]
    fn add_contact_is_blocked_even_from_loopback() {
        let to_radio = admin_packet(pb::AdminMessage {
            payload_variant: Some(admin_message::PayloadVariant::AddContact(Default::default())),
            ..Default::default()
        });
        let (ip, allow) = ctx("127.0.0.1", &[]);
        let route = route_from_client(
            &to_radio.encode_to_vec(),
            &ClientContext {
                ip,
                node_num: 7,
                allow_admin_from: &allow,
                blocked_portnums: &[],
            },
        );
        assert_eq!(route.action, ClientAction::Blocked);
    }

    #[test]
    fn blocked_portnums_are_rejected() {
        let data = pb::Data {
            portnum: pb::PortNum::TextMessageApp as i32,
            payload: b"hello".to_vec(),
            ..Default::default()
        };
        let to_radio = pb::ToRadio {
            payload_variant: Some(to_radio::PayloadVariant::Packet(pb::MeshPacket {
                id: 1,
                from: 7,
                to: 0xFFFF_FFFF,
                payload_variant: Some(pb::mesh_packet::PayloadVariant::Decoded(data)),
                ..Default::default()
            })),
        };
        let (ip, allow) = ctx("127.0.0.1", &[]);
        let blocked = [pb::PortNum::TextMessageApp as i32];

        let route = route_from_client(
            &to_radio.encode_to_vec(),
            &ClientContext {
                ip,
                node_num: 7,
                allow_admin_from: &allow,
                blocked_portnums: &blocked,
            },
        );
        assert_eq!(route.action, ClientAction::Blocked);

        let route = route_from_client(
            &to_radio.encode_to_vec(),
            &ClientContext {
                ip,
                node_num: 7,
                allow_admin_from: &allow,
                blocked_portnums: &[],
            },
        );
        assert!(matches!(route.action, ClientAction::Forward(_)));
    }

    #[test]
    fn strips_pki_from_zero_sender_packets() {
        let packet = pb::MeshPacket {
            from: 0,
            pki_encrypted: true,
            public_key: vec![1, 2, 3],
            payload_variant: Some(pb::mesh_packet::PayloadVariant::Encrypted(vec![9])),
            ..Default::default()
        };
        let to_radio = pb::ToRadio {
            payload_variant: Some(to_radio::PayloadVariant::Packet(packet)),
        };

        let (ip, allow) = ctx("127.0.0.1", &[]);
        let route = route_from_client(
            &to_radio.encode_to_vec(),
            &ClientContext {
                ip,
                node_num: 7,
                allow_admin_from: &allow,
                blocked_portnums: &[],
            },
        );

        let ClientAction::Forward(bytes) = route.action else {
            panic!("expected forward");
        };
        let forwarded = pb::ToRadio::decode(bytes.as_slice()).unwrap();
        let Some(to_radio::PayloadVariant::Packet(pkt)) = forwarded.payload_variant else {
            panic!("expected packet");
        };
        assert!(!pkt.pki_encrypted);
        assert!(pkt.public_key.is_empty());
    }

    #[test]
    fn physical_config_dumps_are_suppressed() {
        let fr = pb::FromRadio {
            id: 0,
            payload_variant: Some(from_radio::PayloadVariant::Channel(Default::default())),
        };
        assert_eq!(route_from_physical(&fr), PhysicalRoute::ConfigDump);

        let fr = pb::FromRadio {
            id: 0,
            payload_variant: Some(from_radio::PayloadVariant::Packet(Default::default())),
        };
        assert_eq!(route_from_physical(&fr), PhysicalRoute::Broadcast);
    }

    #[test]
    fn invalid_ip_strings_are_rejected() {
        assert!(Cidr::parse("").is_none());
        assert!(Cidr::parse("192.168.1.0/99").is_none());
        assert!(Ipv4Addr::from_str("256.0.0.1").is_err());
    }
}
