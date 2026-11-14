//! PhoneAPI config-replay builder.
//!
//! When a client sends `want_config_id`, the firmware streams a fixed order:
//! MyNodeInfo, OwnNodeInfo, Metadata, Channels, Configs, ModuleConfigs,
//! NodeInfos, ConfigComplete. We reproduce that order from the cache.
//!
//! Two magic nonces change the payload: 69420 asks for config only (no node
//! database) and 69421 asks for the node database only.

use meshtastic::protobufs::{self as pb, channel, config, from_radio, module_config};
use meshtastic::Message;

use crate::config::Config;
use crate::state::StateCache;

/// Version reported in the metadata suffix (`-Mx{version}`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const NONCE_CONFIG_ONLY: u32 = 69_420;
pub const NONCE_DB_ONLY: u32 = 69_421;

const SYNTHETIC_NODES: usize = 80;

const SYNTHETIC_NAMES: [(&str, &str); 26] = [
    ("Node Alpha", "ALPH"),
    ("Node Beta", "BETA"),
    ("Node Gamma", "GMMA"),
    ("Node Delta", "DLTA"),
    ("Node Echo", "ECHO"),
    ("Node Foxtrot", "FOX"),
    ("Node Golf", "GOLF"),
    ("Node Hotel", "HTL"),
    ("Node India", "IND"),
    ("Node Juliet", "JLT"),
    ("Node Kilo", "KILO"),
    ("Node Lima", "LIMA"),
    ("Node Mike", "MIKE"),
    ("Node November", "NOV"),
    ("Node Oscar", "OSCR"),
    ("Node Papa", "PAPA"),
    ("Node Quebec", "QUE"),
    ("Node Romeo", "ROM"),
    ("Node Sierra", "SIR"),
    ("Node Tango", "TNG"),
    ("Node Uniform", "UNI"),
    ("Node Victor", "VIC"),
    ("Node Whiskey", "WHIS"),
    ("Node Xray", "XRAY"),
    ("Node Yankee", "YANK"),
    ("Node Zulu", "ZULU"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayMode {
    Full,
    ConfigOnly,
    DbOnly,
}

impl ReplayMode {
    pub fn from_nonce(id: u32) -> Self {
        match id {
            NONCE_DB_ONLY => Self::DbOnly,
            NONCE_CONFIG_ONLY => Self::ConfigOnly,
            _ => Self::Full,
        }
    }
}

pub struct ReplayInput<'a> {
    pub cache: &'a StateCache,
    pub config: &'a Config,
    pub node_num: u32,
    pub config_id: u32,
}

/// Build the complete replay for one client.
pub fn build_replay(input: &ReplayInput<'_>) -> Vec<pb::FromRadio> {
    let mode = ReplayMode::from_nonce(input.config_id);
    let mut builder = Builder::new(input);

    match mode {
        ReplayMode::DbOnly => {
            builder.send_own_node_info();
            builder.send_known_nodes();
            builder.send_config_complete();
        }
        ReplayMode::ConfigOnly | ReplayMode::Full => {
            builder.send_my_info();
            builder.send_own_node_info();
            builder.send_metadata();
            builder.send_channels();
            builder.send_configs();
            if mode == ReplayMode::Full {
                builder.send_known_nodes();
            }
            builder.send_config_complete();
        }
    }

    builder.out
}

struct Builder<'a> {
    input: &'a ReplayInput<'a>,
    next_id: u32,
    out: Vec<pb::FromRadio>,
}

impl<'a> Builder<'a> {
    fn new(input: &'a ReplayInput<'a>) -> Self {
        Self {
            input,
            next_id: 1,
            out: Vec::new(),
        }
    }

    fn push(&mut self, mut fr: pb::FromRadio) {
        fr.id = self.next_id;
        self.next_id += 1;
        self.out.push(fr);
    }

    fn push_raw(&mut self, raw: &[u8]) {
        if let Ok(fr) = pb::FromRadio::decode(raw) {
            self.push(fr);
        }
    }

    fn push_variant(&mut self, variant: from_radio::PayloadVariant) {
        self.push(pb::FromRadio {
            id: 0,
            payload_variant: Some(variant),
        });
    }

    fn send_my_info(&mut self) {
        let sync = self.input.config.virtual_node.sync_physical_identity;
        let my_info = if sync {
            self.input.cache.my_info.clone()
        } else {
            None
        }
        .unwrap_or_else(|| synthesized_my_info(self.input.node_num));

        self.push_variant(from_radio::PayloadVariant::MyInfo(my_info));
    }

    fn send_own_node_info(&mut self) {
        let sync = self.input.config.virtual_node.sync_physical_identity;
        let node_info = if sync {
            self.input.cache.node_info.clone()
        } else {
            None
        }
        .unwrap_or_else(|| {
            synthesized_node_info(
                self.input.node_num,
                &self.input.config.virtual_node.long_name,
                &self.input.config.virtual_node.short_name,
            )
        });

        self.push_variant(from_radio::PayloadVariant::NodeInfo(node_info));
    }

    fn send_metadata(&mut self) {
        let metadata = match self.input.cache.metadata.clone() {
            Some(mut md) => {
                if !md.firmware_version.is_empty() {
                    md.firmware_version = format!("{}-Mx{VERSION}", md.firmware_version);
                }
                md
            }
            None => synthesized_metadata(),
        };

        self.push_variant(from_radio::PayloadVariant::Metadata(metadata));
    }

    fn send_channels(&mut self) {
        if self.input.cache.channels.is_empty() {
            for channel in default_channels() {
                self.push_variant(from_radio::PayloadVariant::Channel(channel));
            }
        } else {
            for channel in &self.input.cache.channels {
                self.push_variant(from_radio::PayloadVariant::Channel(channel.clone()));
            }
        }
    }

    fn send_configs(&mut self) {
        let has_real_frames = !self.input.cache.config_frames.is_empty()
            || !self.input.cache.module_config_frames.is_empty();

        if has_real_frames {
            for (_, raw) in &self.input.cache.config_frames {
                self.push_raw(raw);
            }
            for (_, raw) in &self.input.cache.module_config_frames {
                self.push_raw(raw);
            }
            return;
        }

        for cfg in default_configs() {
            self.push_variant(from_radio::PayloadVariant::Config(cfg));
        }
        for mc in default_module_configs() {
            self.push_variant(from_radio::PayloadVariant::ModuleConfig(mc));
        }
    }

    fn send_known_nodes(&mut self) {
        if self.input.cache.known_nodes.is_empty() {
            for i in 0..SYNTHETIC_NODES {
                self.push_variant(from_radio::PayloadVariant::NodeInfo(synthetic_node(i)));
            }
            return;
        }

        for (num, node) in &self.input.cache.known_nodes {
            if *num == 0xFFFF_FFFF {
                continue;
            }
            self.push_variant(from_radio::PayloadVariant::NodeInfo(node.clone()));
        }
    }

    fn send_config_complete(&mut self) {
        self.push_variant(from_radio::PayloadVariant::ConfigCompleteId(
            self.input.config_id,
        ));
    }
}

fn synthesized_my_info(node_num: u32) -> pb::MyNodeInfo {
    pb::MyNodeInfo {
        my_node_num: node_num,
        min_app_version: 20_200,
        device_id: format!("virtual-{node_num:08x}").into_bytes(),
        firmware_edition: pb::FirmwareEdition::Vanilla as i32,
        ..Default::default()
    }
}

fn synthesized_node_info(node_num: u32, long_name: &str, short_name: &str) -> pb::NodeInfo {
    pb::NodeInfo {
        num: node_num,
        user: Some(pb::User {
            id: format!("!{node_num:08x}"),
            long_name: long_name.to_owned(),
            short_name: short_name.to_owned(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn synthesized_metadata() -> pb::DeviceMetadata {
    pb::DeviceMetadata {
        firmware_version: format!("2.6.0-virtual-mux-Mx{VERSION}"),
        role: config::device_config::Role::Client as i32,
        ..Default::default()
    }
}

fn default_channels() -> Vec<pb::Channel> {
    (0..8i32)
        .map(|index| {
            if index == 0 {
                let mut psk = vec![0x01u8];
                psk.extend_from_slice(&[0u8; 31]);
                pb::Channel {
                    index,
                    role: channel::Role::Primary as i32,
                    settings: Some(pb::ChannelSettings {
                        name: "MediumFast".into(),
                        psk,
                        uplink_enabled: true,
                        downlink_enabled: true,
                        ..Default::default()
                    }),
                }
            } else {
                pb::Channel {
                    index,
                    role: channel::Role::Disabled as i32,
                    ..Default::default()
                }
            }
        })
        .collect()
}

fn default_configs() -> Vec<pb::Config> {
    let lora = config::LoRaConfig {
        use_preset: true,
        modem_preset: config::lo_ra_config::ModemPreset::MediumFast as i32,
        region: config::lo_ra_config::RegionCode::Unset as i32,
        hop_limit: 3,
        tx_power: 20,
        ..Default::default()
    };
    let device = config::DeviceConfig {
        role: config::device_config::Role::Client as i32,
        ..Default::default()
    };
    let display = config::DisplayConfig {
        units: config::display_config::DisplayUnits::Metric as i32,
        ..Default::default()
    };
    let network = config::NetworkConfig {
        wifi_enabled: false,
        eth_enabled: false,
        ..Default::default()
    };

    vec![
        wrap_config(config::PayloadVariant::Lora(lora)),
        wrap_config(config::PayloadVariant::Device(device)),
        wrap_config(config::PayloadVariant::Display(display)),
        wrap_config(config::PayloadVariant::Power(Default::default())),
        wrap_config(config::PayloadVariant::Network(network)),
        wrap_config(config::PayloadVariant::Bluetooth(Default::default())),
    ]
}

fn default_module_configs() -> Vec<pb::ModuleConfig> {
    let mqtt = module_config::MqttConfig {
        enabled: false,
        ..Default::default()
    };
    let telemetry = module_config::TelemetryConfig {
        device_update_interval: 120,
        environment_update_interval: 120,
        air_quality_interval: 120,
        ..Default::default()
    };

    vec![
        wrap_module_config(module_config::PayloadVariant::Mqtt(mqtt)),
        wrap_module_config(module_config::PayloadVariant::Telemetry(telemetry)),
    ]
}

fn wrap_config(variant: config::PayloadVariant) -> pb::Config {
    pb::Config {
        payload_variant: Some(variant),
    }
}

fn wrap_module_config(variant: module_config::PayloadVariant) -> pb::ModuleConfig {
    pb::ModuleConfig {
        payload_variant: Some(variant),
    }
}

fn synthetic_node(i: usize) -> pb::NodeInfo {
    let seed = 0xABCD_0000u32.wrapping_add(i as u32);
    let (long_name, short_name) = if i < SYNTHETIC_NAMES.len() {
        let (name, short) = SYNTHETIC_NAMES[i];
        (name.to_owned(), short.to_owned())
    } else {
        (format!("Node {seed:04x}"), format!("N{:04}", i))
    };

    pb::NodeInfo {
        num: seed,
        user: Some(pb::User {
            id: format!("!{seed:08x}"),
            long_name,
            short_name,
            hw_model: (i % 10) as i32,
            ..Default::default()
        }),
        last_heard: (i as u32) * 3600,
        snr: (i % 20) as f32 - 10.0,
        hops_away: Some((i % 4) as u32),
        device_metrics: Some(pb::DeviceMetrics {
            battery_level: Some(50 + (i % 50) as u32),
            voltage: Some(3.7 + (i % 10) as f32 * 0.1),
            channel_utilization: Some((i % 100) as f32 / 100.0),
            air_util_tx: Some((i % 50) as f32 / 100.0),
            ..Default::default()
        }),
        position: Some(pb::Position {
            latitude_i: Some(373_000_000 + (i as i32) * 1_000),
            longitude_i: Some(-1_220_000_000 - (i as i32) * 1_000),
            altitude: Some(10 + (i % 100) as i32),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn sampled_cache() -> StateCache {
        let mut cache = StateCache::new();
        cache.my_node_num = 0x0102_0304;
        cache.my_info = Some(pb::MyNodeInfo {
            my_node_num: cache.my_node_num,
            ..Default::default()
        });
        cache.metadata = Some(pb::DeviceMetadata {
            firmware_version: "2.7.0".into(),
            ..Default::default()
        });
        cache.channels = default_channels();
        cache.known_nodes.insert(
            1,
            pb::NodeInfo {
                num: 1,
                ..Default::default()
            },
        );
        cache
    }

    fn variants(messages: &[pb::FromRadio]) -> Vec<&str> {
        messages
            .iter()
            .filter_map(|m| m.payload_variant.as_ref())
            .map(|v| match v {
                from_radio::PayloadVariant::MyInfo(_) => "my_info",
                from_radio::PayloadVariant::NodeInfo(_) => "node_info",
                from_radio::PayloadVariant::Metadata(_) => "metadata",
                from_radio::PayloadVariant::Channel(_) => "channel",
                from_radio::PayloadVariant::Config(_) => "config",
                from_radio::PayloadVariant::ModuleConfig(_) => "module_config",
                from_radio::PayloadVariant::ConfigCompleteId(_) => "config_complete",
                _ => "other",
            })
            .collect()
    }

    #[test]
    fn full_replay_follows_the_firmware_order() {
        let cache = sampled_cache();
        let config = Config::default();
        let messages = build_replay(&ReplayInput {
            cache: &cache,
            config: &config,
            node_num: cache.my_node_num,
            config_id: 1234,
        });

        let kinds = variants(&messages);
        assert_eq!(kinds[0], "my_info");
        assert_eq!(kinds[1], "node_info");
        assert_eq!(kinds[2], "metadata");
        assert_eq!(kinds[3], "channel");
        assert_eq!(*kinds.last().unwrap(), "config_complete");

        // IDs are contiguous starting at 1.
        let ids: Vec<u32> = messages.iter().map(|m| m.id).collect();
        assert_eq!(ids, (1..=messages.len() as u32).collect::<Vec<_>>());

        let last = messages.last().unwrap();
        assert_eq!(
            last.payload_variant,
            Some(from_radio::PayloadVariant::ConfigCompleteId(1234))
        );
    }

    #[test]
    fn metadata_gets_the_version_suffix() {
        let cache = sampled_cache();
        let config = Config::default();
        let messages = build_replay(&ReplayInput {
            cache: &cache,
            config: &config,
            node_num: cache.my_node_num,
            config_id: 1,
        });

        let metadata = messages
            .iter()
            .find_map(|m| match &m.payload_variant {
                Some(from_radio::PayloadVariant::Metadata(md)) => Some(md),
                _ => None,
            })
            .unwrap();
        assert_eq!(metadata.firmware_version, format!("2.7.0-Mx{VERSION}"));
    }

    #[test]
    fn config_only_skips_the_node_database() {
        let cache = sampled_cache();
        let config = Config::default();
        let messages = build_replay(&ReplayInput {
            cache: &cache,
            config: &config,
            node_num: cache.my_node_num,
            config_id: NONCE_CONFIG_ONLY,
        });

        let kinds = variants(&messages);
        // Only the node's own NodeInfo; the node database is skipped.
        assert_eq!(kinds.iter().filter(|k| **k == "node_info").count(), 1);
        assert_eq!(*kinds.last().unwrap(), "config_complete");
    }

    #[test]
    fn db_only_sends_only_nodes() {
        let cache = sampled_cache();
        let config = Config::default();
        let messages = build_replay(&ReplayInput {
            cache: &cache,
            config: &config,
            node_num: cache.my_node_num,
            config_id: NONCE_DB_ONLY,
        });

        // Own node info plus the one cached known node, then completion.
        assert_eq!(
            variants(&messages),
            vec!["node_info", "node_info", "config_complete"]
        );
    }
}
