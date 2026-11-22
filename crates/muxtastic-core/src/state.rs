//! In-memory cache of the physical node's state.
//!
//! The cache is what a late-joining client sees: identity, channels, config
//! frames and the node database. It mirrors the original `StateCache`, but
//! stores typed protobufs instead of nested dictionaries.

use std::collections::BTreeMap;

use meshtastic::protobufs::{self as pb, config, from_radio, module_config};
use meshtastic::Message;

/// Upper bound for [`StateCache::known_nodes`]. Firmware node databases hold
/// a few hundred entries; the cap only matters when NodeInfo keeps arriving
/// for new senders (busy meshes, MQTT downlink) for a long time.
pub const MAX_KNOWN_NODES: usize = 2000;

#[derive(Debug, Default, Clone)]
pub struct StateCache {
    pub my_node_num: u32,
    pub my_info: Option<pb::MyNodeInfo>,
    pub node_info: Option<pb::NodeInfo>,
    pub metadata: Option<pb::DeviceMetadata>,
    pub lora_config: Option<pb::config::LoRaConfig>,
    pub channels: Vec<pb::Channel>,
    pub known_nodes: BTreeMap<u32, pb::NodeInfo>,
    /// Raw `FromRadio` config frames, keyed by config subtype ("lora", ...).
    pub config_frames: Vec<(String, Vec<u8>)>,
    /// Raw `FromRadio` module-config frames, keyed by subtype ("mqtt", ...).
    pub module_config_frames: Vec<(String, Vec<u8>)>,
}

impl StateCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode and apply one unframed `FromRadio` protobuf.
    pub fn apply(&mut self, raw: &[u8]) {
        let Ok(fr) = pb::FromRadio::decode(raw) else {
            return;
        };
        self.apply_message(&fr, raw);
    }

    pub fn apply_message(&mut self, fr: &pb::FromRadio, raw: &[u8]) {
        let Some(variant) = &fr.payload_variant else {
            return;
        };

        match variant {
            from_radio::PayloadVariant::MyInfo(mi) => {
                self.my_node_num = mi.my_node_num;
                self.my_info = Some(mi.clone());
            }
            from_radio::PayloadVariant::Metadata(md) => {
                self.metadata = Some(md.clone());
            }
            from_radio::PayloadVariant::Config(cfg) => {
                if let Some(config::PayloadVariant::Lora(lora)) = &cfg.payload_variant {
                    self.lora_config = Some(lora.clone());
                }
                if let Some(key) = config_key(cfg) {
                    upsert_frame(&mut self.config_frames, key, raw.to_vec());
                }
            }
            from_radio::PayloadVariant::ModuleConfig(mc) => {
                if let Some(key) = module_config_key(mc) {
                    upsert_frame(&mut self.module_config_frames, key, raw.to_vec());
                }
            }
            from_radio::PayloadVariant::Channel(ch) => self.upsert_channel(ch.clone()),
            from_radio::PayloadVariant::NodeInfo(ni) => self.upsert_node(ni.clone()),
            from_radio::PayloadVariant::Packet(pkt) => self.apply_packet(pkt),
            _ => {}
        }
    }

    fn upsert_channel(&mut self, channel: pb::Channel) {
        if let Some(existing) = self.channels.iter_mut().find(|c| c.index == channel.index) {
            *existing = channel;
        } else {
            self.channels.push(channel);
        }
        self.channels.sort_by_key(|c| c.index);
    }

    fn upsert_node(&mut self, node: pb::NodeInfo) {
        let num = node.num;
        if num == self.my_node_num {
            self.node_info = Some(node.clone());
        }
        self.known_nodes.insert(num, node);
        self.evict_stale_nodes(num);
    }

    /// Keep the node database within [`MAX_KNOWN_NODES`] by dropping the
    /// least recently heard nodes. The local node and the node that was just
    /// stored (`keep`) are never dropped.
    fn evict_stale_nodes(&mut self, keep: u32) {
        while self.known_nodes.len() > MAX_KNOWN_NODES {
            let my_node_num = self.my_node_num;
            let Some(stale) = self
                .known_nodes
                .iter()
                .filter(|(num, _)| **num != my_node_num && **num != keep)
                .min_by_key(|(_, node)| node.last_heard)
                .map(|(num, _)| *num)
            else {
                return;
            };
            self.known_nodes.remove(&stale);
        }
    }

    fn apply_packet(&mut self, pkt: &pb::MeshPacket) {
        if let Some(user) = crate::packet::nodeinfo(pkt) {
            let mut node = self.known_nodes.get(&pkt.from).cloned().unwrap_or_default();
            node.num = pkt.from;
            node.user = Some(user);
            node.snr = pkt.rx_snr;
            node.hops_away = Some(crate::packet::hops_away(pkt));
            node.via_mqtt = pkt.via_mqtt;
            node.last_heard = pkt.rx_time;
            self.upsert_node(node);
        } else if let Some(mut position) = crate::packet::position(pkt) {
            let Some(mut node) = self.known_nodes.get(&pkt.from).cloned() else {
                return;
            };
            if position.time == 0 {
                position.time = pkt.rx_time;
            }
            node.position = Some(position);
            self.upsert_node(node);
        }
    }
}

fn upsert_frame(frames: &mut Vec<(String, Vec<u8>)>, key: &'static str, raw: Vec<u8>) {
    if let Some(existing) = frames.iter_mut().find(|(k, _)| k == key) {
        existing.1 = raw;
    } else {
        frames.push((key.to_owned(), raw));
    }
}

fn config_key(cfg: &pb::Config) -> Option<&'static str> {
    use config::PayloadVariant as V;
    Some(match cfg.payload_variant.as_ref()? {
        V::Device(_) => "device",
        V::Position(_) => "position",
        V::Power(_) => "power",
        V::Network(_) => "network",
        V::Display(_) => "display",
        V::Lora(_) => "lora",
        V::Bluetooth(_) => "bluetooth",
        V::Security(_) => "security",
        V::Sessionkey(_) => "sessionkey",
        V::DeviceUi(_) => "deviceui",
    })
}

fn module_config_key(mc: &pb::ModuleConfig) -> Option<&'static str> {
    use module_config::PayloadVariant as V;
    Some(match mc.payload_variant.as_ref()? {
        V::Mqtt(_) => "mqtt",
        V::Serial(_) => "serial",
        V::ExternalNotification(_) => "external_notification",
        V::StoreForward(_) => "store_forward",
        V::RangeTest(_) => "range_test",
        V::Telemetry(_) => "telemetry",
        V::CannedMessage(_) => "canned_message",
        V::Audio(_) => "audio",
        V::RemoteHardware(_) => "remote_hardware",
        V::NeighborInfo(_) => "neighbor_info",
        V::AmbientLighting(_) => "ambient_lighting",
        V::DetectionSensor(_) => "detection_sensor",
        V::Paxcounter(_) => "paxcounter",
        V::Statusmessage(_) => "status_message",
        V::TrafficManagement(_) => "traffic_management",
        V::Tak(_) => "tak",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(fr: &pb::FromRadio) -> Vec<u8> {
        fr.encode_to_vec()
    }

    #[test]
    fn captures_identity_and_config_frames() {
        let mut cache = StateCache::new();

        let my_info = pb::MyNodeInfo {
            my_node_num: 0x1234_5678,
            ..Default::default()
        };
        let frame = pb::FromRadio {
            id: 1,
            payload_variant: Some(from_radio::PayloadVariant::MyInfo(my_info)),
        };
        cache.apply(&encode(&frame));
        assert_eq!(cache.my_node_num, 0x1234_5678);

        let lora = pb::Config {
            payload_variant: Some(config::PayloadVariant::Lora(Default::default())),
        };
        let frame = pb::FromRadio {
            id: 2,
            payload_variant: Some(from_radio::PayloadVariant::Config(lora)),
        };
        cache.apply(&encode(&frame));
        assert_eq!(
            cache.config_frames,
            vec![("lora".to_string(), encode(&frame))]
        );
    }

    #[test]
    fn channels_replace_by_index_and_sort() {
        let mut cache = StateCache::new();
        for (index, name) in [(2, "two"), (0, "zero"), (2, "two-updated")] {
            let channel = pb::Channel {
                index,
                settings: Some(pb::ChannelSettings {
                    name: name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            cache.apply_message(
                &pb::FromRadio {
                    id: 0,
                    payload_variant: Some(from_radio::PayloadVariant::Channel(channel)),
                },
                &[],
            );
        }

        let indexes: Vec<i32> = cache.channels.iter().map(|c| c.index).collect();
        assert_eq!(indexes, vec![0, 2]);
        assert_eq!(
            cache.channels[1].settings.as_ref().unwrap().name,
            "two-updated"
        );
    }

    #[test]
    fn tracks_own_node_and_known_nodes() {
        let mut cache = StateCache::new();
        cache.my_node_num = 7;

        let own = pb::NodeInfo {
            num: 7,
            ..Default::default()
        };
        cache.apply_message(
            &pb::FromRadio {
                id: 0,
                payload_variant: Some(from_radio::PayloadVariant::NodeInfo(own)),
            },
            &[],
        );

        assert!(cache.node_info.is_some());
        assert!(cache.known_nodes.contains_key(&7));
    }

    #[test]
    fn known_nodes_are_capped_and_evict_the_least_recently_heard() {
        let mut cache = StateCache::new();
        cache.my_node_num = 1;
        let add = |cache: &mut StateCache, num: u32, last_heard: u32| {
            cache.apply_message(
                &pb::FromRadio {
                    id: 0,
                    payload_variant: Some(from_radio::PayloadVariant::NodeInfo(pb::NodeInfo {
                        num,
                        last_heard,
                        ..Default::default()
                    })),
                },
                &[],
            );
        };

        // The local node is the stalest entry of all and must survive.
        add(&mut cache, 1, 0);
        for num in 2..=MAX_KNOWN_NODES as u32 {
            add(&mut cache, num, 1_000 + num);
        }
        assert_eq!(cache.known_nodes.len(), MAX_KNOWN_NODES);

        // One more: node 2 (oldest last_heard besides the local node) goes.
        add(&mut cache, 900_000, 5_000_000);
        assert_eq!(cache.known_nodes.len(), MAX_KNOWN_NODES);
        assert!(cache.known_nodes.contains_key(&1));
        assert!(!cache.known_nodes.contains_key(&2));
        assert!(cache.known_nodes.contains_key(&3));
        assert!(cache.known_nodes.contains_key(&900_000));

        // A new node with no timestamp is kept; the next stalest one goes.
        add(&mut cache, 900_001, 0);
        assert_eq!(cache.known_nodes.len(), MAX_KNOWN_NODES);
        assert!(cache.known_nodes.contains_key(&900_001));
        assert!(!cache.known_nodes.contains_key(&3));
        assert!(cache.node_info.is_some());
    }

    #[test]
    fn learns_nodes_from_nodeinfo_packets() {
        let mut cache = StateCache::new();

        let user = pb::User {
            id: "!0000002a".into(),
            long_name: "Alice".into(),
            short_name: "ALI".into(),
            ..Default::default()
        };
        let data = pb::Data {
            portnum: pb::PortNum::NodeinfoApp as i32,
            payload: user.encode_to_vec(),
            ..Default::default()
        };
        let pkt = pb::MeshPacket {
            from: 42,
            rx_snr: 7.5,
            hop_limit: 2,
            rx_time: 99,
            payload_variant: Some(pb::mesh_packet::PayloadVariant::Decoded(data)),
            ..Default::default()
        };

        cache.apply_message(
            &pb::FromRadio {
                id: 0,
                payload_variant: Some(from_radio::PayloadVariant::Packet(pkt)),
            },
            &[],
        );

        let node = cache.known_nodes.get(&42).unwrap();
        assert_eq!(node.user.as_ref().unwrap().long_name, "Alice");
        assert_eq!(node.hops_away, Some(1));
        assert_eq!(node.last_heard, 99);
    }
}
