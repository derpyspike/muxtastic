//! Typed configuration shared by the legacy YAML and native TOML loaders.
//!
//! Both formats deserialize into these types. Field aliases keep the original
//! `multiplextashtic` keys working so an existing `config.yaml` is a drop-in.

use std::collections::HashSet;

use serde::Deserialize;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("server.port 4403 conflicts with the physical node default; use 4404 or higher")]
    PortConflictsWithNode,
    #[error("node name is empty")]
    EmptyNodeName,
    #[error("duplicate node name: {0}")]
    DuplicateNodeName(String),
    #[error("duplicate server.port: {0}")]
    DuplicateServerPort(u16),
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    #[serde(alias = "physical_node")]
    pub node: NodeConfig,
    pub server: ServerConfig,
    pub virtual_node: VirtualNodeConfig,
    pub security: SecurityConfig,
    pub discovery: DiscoveryConfig,
    pub web: WebConfig,
    pub mqtt_bridge: MqttBridgeConfig,
    pub logging: LoggingConfig,
    /// Optional multi-node layout. When empty, the legacy `node`/`server`/
    /// `virtual_node`/`mqtt_bridge` fields form one implicit node.
    pub nodes: Vec<NodeInstanceConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeInstanceConfig {
    pub name: String,
    pub node: NodeConfig,
    pub server: ServerConfig,
    pub virtual_node: VirtualNodeConfig,
    pub mqtt_bridge: MqttBridgeConfig,
}

impl Default for NodeInstanceConfig {
    fn default() -> Self {
        Self {
            name: "default".into(),
            node: NodeConfig::default(),
            server: ServerConfig::default(),
            virtual_node: VirtualNodeConfig::default(),
            mqtt_bridge: MqttBridgeConfig::default(),
        }
    }
}

impl Config {
    /// Reject settings that would make the multiplexer fight a physical node.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut ports = HashSet::new();
        let mut names = HashSet::new();
        for instance in self.instances() {
            if instance.server.port == 4403 {
                return Err(ConfigError::PortConflictsWithNode);
            }
            if instance.name.trim().is_empty() {
                return Err(ConfigError::EmptyNodeName);
            }
            if !names.insert(instance.name.clone()) {
                return Err(ConfigError::DuplicateNodeName(instance.name));
            }
            if !ports.insert(instance.server.port) {
                return Err(ConfigError::DuplicateServerPort(instance.server.port));
            }
        }
        Ok(())
    }

    /// The configured nodes, or one implicit node built from the legacy keys.
    pub fn instances(&self) -> Vec<NodeInstanceConfig> {
        if self.nodes.is_empty() {
            vec![NodeInstanceConfig {
                name: "default".into(),
                node: self.node.clone(),
                server: self.server.clone(),
                virtual_node: self.virtual_node.clone(),
                mqtt_bridge: self.mqtt_bridge.clone(),
            }]
        } else {
            self.nodes.clone()
        }
    }

    /// Clone the shared configuration with one node's settings substituted.
    pub fn for_instance(&self, instance: &NodeInstanceConfig) -> Self {
        let mut config = self.clone();
        config.node = instance.node.clone();
        config.server = instance.server.clone();
        config.virtual_node = instance.virtual_node.clone();
        config.mqtt_bridge = instance.mqtt_bridge.clone();
        config.nodes = Vec::new();
        config
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionType {
    #[default]
    Serial,
    Tcp,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeConfig {
    #[serde(rename = "type", alias = "connection_type")]
    pub connection_type: ConnectionType,
    pub serial_port: String,
    pub baud_rate: u32,
    pub tcp_host: String,
    pub tcp_port: u16,
    #[serde(alias = "tcp_idle_timeout")]
    pub tcp_idle_timeout_secs: u64,
    #[serde(alias = "serial_poke_timeout")]
    pub serial_poke_timeout_secs: u64,
    #[serde(alias = "serial_idle_timeout")]
    pub serial_idle_timeout_secs: u64,
    pub reconnect: ReconnectConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            connection_type: ConnectionType::Serial,
            serial_port: "/dev/ttyUSB0".into(),
            baud_rate: 115_200,
            tcp_host: "192.168.1.100".into(),
            tcp_port: 4403,
            tcp_idle_timeout_secs: 300,
            serial_poke_timeout_secs: 45,
            serial_idle_timeout_secs: 90,
            reconnect: ReconnectConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReconnectConfig {
    pub enabled: bool,
    #[serde(alias = "initial_delay")]
    pub initial_delay_secs: u64,
    #[serde(alias = "max_delay")]
    pub max_delay_secs: u64,
    pub multiplier: u32,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            initial_delay_secs: 1,
            max_delay_secs: 60,
            multiplier: 2,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub max_clients: usize,
    /// Reserved for compatibility; the wire cap is always 512 bytes.
    pub max_payload_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".into(),
            port: 4404,
            max_clients: 20,
            max_payload_size: 10_240,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VirtualNodeConfig {
    pub long_name: String,
    pub short_name: String,
    pub sync_physical_identity: bool,
}

impl Default for VirtualNodeConfig {
    fn default() -> Self {
        Self {
            long_name: "Virtual Multiplexer".into(),
            short_name: "VMUX".into(),
            sync_physical_identity: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    pub blocked_portnums: Vec<String>,
    #[serde(alias = "allow_admin_from_ips")]
    pub allow_admin_from: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            blocked_portnums: vec!["ADMIN_APP".into()],
            allow_admin_from: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiscoveryConfig {
    pub enabled: bool,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebStorage {
    /// Persistent SQLite file from `web.database`.
    #[default]
    Sqlite,
    /// Volatile SQLite database kept entirely in RAM.
    Memory,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExtraChannelConfig {
    pub name: String,
    pub key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    /// SQLite file path; `:memory:` is accepted for tests.
    pub database: String,
    /// Storage backend: `sqlite` (persistent) or `memory` (volatile).
    pub storage: WebStorage,
    /// Days of packet history to keep; 0 disables cleanup.
    pub retention_days: u64,
    /// Optional read-only MQTT source: `--web-only`, or alongside physical nodes.
    pub mqtt: WebMqttConfig,
    /// Extra channel names/keys tried against opaque packets.
    pub extra_channels: Vec<ExtraChannelConfig>,
    /// Append all 255 non-zero one-byte PSKs to the extra channel list.
    pub try_all_one_byte_keys: bool,
    /// MeshCore channels to decrypt besides Public: `#hashtag` names need no
    /// key, private channels need their 16- or 32-byte key (base64 or hex).
    pub meshcore_channels: Vec<ExtraChannelConfig>,
    /// MeshCore region names tried against region-scoped packets.
    pub meshcore_regions: Vec<String>,
    /// Map tile URL template; the browser fetches tiles from it directly.
    /// Empty disables the background map.
    pub map_tile_url: String,
    /// Attribution shown on the map for the tile source.
    pub map_attribution: String,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            host: "127.0.0.1".into(),
            port: 8080,
            database: "data/muxtastic.db".into(),
            storage: WebStorage::Sqlite,
            retention_days: 7,
            mqtt: WebMqttConfig::default(),
            extra_channels: Vec::new(),
            try_all_one_byte_keys: false,
            meshcore_channels: Vec::new(),
            meshcore_regions: Vec::new(),
            map_tile_url: "https://tile.openstreetmap.org/{z}/{x}/{y}.png".into(),
            map_attribution: "© OpenStreetMap contributors".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebMqttConfig {
    pub enabled: bool,
    pub broker: String,
    pub port: u16,
    pub tls: bool,
    pub username: String,
    pub password: String,
    pub client_id: String,
    pub topics: Vec<String>,
    pub keepalive: u64,
}

impl Default for WebMqttConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            broker: "mqtt.meshtastic.org".into(),
            port: 8883,
            tls: true,
            username: String::new(),
            password: String::new(),
            client_id: "muxtastic-webd".into(),
            topics: vec![
                "msh/#".into(),
                "raw/#".into(),
                "jencore/#".into(),
                "jenrnode/#".into(),
            ],
            keepalive: 60,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub level: LogLevel,
    pub file: Option<String>,
    pub console: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            file: Some("logs/muxtastic.log".into()),
            console: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
pub enum LogLevel {
    #[serde(rename = "debug", alias = "DEBUG")]
    Debug,
    #[default]
    #[serde(rename = "info", alias = "INFO")]
    Info,
    #[serde(rename = "warning", alias = "WARNING")]
    Warning,
    #[serde(rename = "error", alias = "ERROR")]
    Error,
}

/// MQTT bridge configuration.
///
/// Parsed in Phase 1 so existing configs load unchanged; the bridge itself is
/// implemented in Phase 2.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MqttBridgeConfig {
    pub enabled: bool,
    pub broker: String,
    pub port: u16,
    pub tls: bool,
    pub username: String,
    pub password: String,
    pub uplink_enabled: bool,
    pub downlink_enabled: bool,
    pub ignore_ok_to_mqtt: bool,
    pub mqtt_username: String,
    pub root_topic: String,
    pub raw_root_topic: String,
    pub region: String,
    pub raw_uplink: bool,
    pub raw_scope: RawScope,
    pub standard_mirror: StandardMirror,
    /// Publish reassembled Nexus JRAW MeshCore frames to `jencore_root_topic`.
    pub jencore_raw_uplink: bool,
    /// Publish reassembled Nexus JRAW RNode/Reticulum frames to `jenrnode_root_topic`.
    pub jenrnode_raw_uplink: bool,
    pub jencore_root_topic: String,
    pub jenrnode_root_topic: String,
    pub keepalive: u64,
    pub broker2: Option<SecondaryMqttConfig>,
}

impl Default for MqttBridgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            broker: "mqtt.meshtastic.org".into(),
            port: 8883,
            tls: true,
            username: String::new(),
            password: String::new(),
            uplink_enabled: true,
            downlink_enabled: false,
            ignore_ok_to_mqtt: false,
            mqtt_username: String::new(),
            root_topic: "msh".into(),
            raw_root_topic: "raw".into(),
            region: String::new(),
            raw_uplink: false,
            raw_scope: RawScope::Uncovered,
            standard_mirror: StandardMirror::Auto,
            jencore_raw_uplink: false,
            jenrnode_raw_uplink: false,
            jencore_root_topic: "jencore".into(),
            jenrnode_root_topic: "jenrnode".into(),
            keepalive: 60,
            broker2: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecondaryMqttConfig {
    pub enabled: bool,
    pub broker: String,
    pub port: u16,
    pub tls: bool,
    pub username: String,
    pub password: String,
    pub keepalive: u64,
    pub raw_uplink: bool,
    pub raw_scope: RawScope,
}

impl Default for SecondaryMqttConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            broker: String::new(),
            port: 8883,
            tls: true,
            username: String::new(),
            password: String::new(),
            keepalive: 60,
            raw_uplink: false,
            raw_scope: RawScope::Uncovered,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RawScope {
    #[default]
    Uncovered,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum StandardMirror {
    #[default]
    Auto,
    On,
    Off,
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY_YAML: &str = r#"
physical_node:
  connection_type: "tcp"
  tcp_host: "10.0.0.2"
  tcp_port: 4403
  tcp_idle_timeout: 123
  serial_poke_timeout: 11
  serial_idle_timeout: 22
  reconnect:
    enabled: false
    initial_delay: 2
    max_delay: 30
    multiplier: 3
server:
  host: "127.0.0.1"
  port: 4405
  max_clients: 7
  max_payload_size: 4096
virtual_node:
  long_name: "Mux"
  short_name: "MX"
  sync_physical_identity: false
security:
  blocked_portnums: ["ADMIN_APP"]
  allow_admin_from_ips: ["127.0.0.1", "192.168.0.0/16"]
discovery:
  enabled: false
logging:
  level: "DEBUG"
  file: ""
  console: false
mqtt_bridge:
  enabled: false
  broker: "mqtt.meshtastic.org"
  port: 8883
  tls: true
  username: ""
  password: ""
  uplink_enabled: true
  downlink_enabled: false
  ignore_ok_to_mqtt: false
  mqtt_username: ""
  root_topic: "msh"
  raw_root_topic: "raw"
  region: ""
  raw_uplink: false
  raw_scope: "uncovered"
  standard_mirror: "auto"
  keepalive: 60
"#;

    const NATIVE_TOML: &str = r#"
[node]
type = "tcp"
tcp_host = "10.0.0.2"
tcp_port = 4403
tcp_idle_timeout_secs = 123
serial_poke_timeout_secs = 11
serial_idle_timeout_secs = 22

[node.reconnect]
enabled = false
initial_delay_secs = 2
max_delay_secs = 30
multiplier = 3

[server]
host = "127.0.0.1"
port = 4405
max_clients = 7

[virtual_node]
long_name = "Mux"
short_name = "MX"
sync_physical_identity = false

[security]
allow_admin_from = ["127.0.0.1", "192.168.0.0/16"]

[discovery]
enabled = false

[logging]
level = "debug"
file = ""
console = false
"#;

    #[test]
    fn legacy_yaml_and_native_toml_agree() {
        let legacy: Config = serde_yaml_ng::from_str(LEGACY_YAML).unwrap();
        let native: Config = toml::from_str(NATIVE_TOML).unwrap();

        assert_eq!(legacy.node.connection_type, ConnectionType::Tcp);
        assert_eq!(legacy.node.tcp_idle_timeout_secs, 123);
        assert_eq!(legacy.node.reconnect.initial_delay_secs, 2);
        assert_eq!(legacy.server.max_payload_size, 4096);
        assert_eq!(legacy.security.allow_admin_from.len(), 2);
        assert_eq!(legacy.logging.level, LogLevel::Debug);

        assert_eq!(legacy.node.connection_type, native.node.connection_type);
        assert_eq!(
            legacy.node.tcp_idle_timeout_secs,
            native.node.tcp_idle_timeout_secs
        );
        assert_eq!(legacy.server.port, native.server.port);
        assert_eq!(
            legacy.security.allow_admin_from,
            native.security.allow_admin_from
        );
        assert_eq!(legacy.logging.level, native.logging.level);
    }

    #[test]
    fn defaults_are_applied() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.server.port, 4404);
        assert_eq!(config.node.connection_type, ConnectionType::Serial);
        assert!(config.discovery.enabled);
        assert!(config.web.enabled);
        assert_eq!(config.web.host, "127.0.0.1");
        assert_eq!(config.web.port, 8080);
        assert_eq!(config.web.retention_days, 7);
        assert!(!config.web.mqtt.enabled);
        assert_eq!(config.web.mqtt.topics.len(), 4);
        assert!(!config.web.try_all_one_byte_keys);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn parses_extra_channels() {
        let config: Config = toml::from_str(
            r#"
[web]
try_all_one_byte_keys = true

[[web.extra_channels]]
name = "Madrid"
key = "AQ=="

[[web.extra_channels]]
name = "*"
key = "AQ=="
"#,
        )
        .unwrap();
        assert_eq!(config.web.extra_channels.len(), 2);
        assert_eq!(config.web.extra_channels[0].name, "Madrid");
        assert_eq!(config.web.extra_channels[1].name, "*");
        assert!(config.web.try_all_one_byte_keys);
    }

    #[test]
    fn parses_memory_storage() {
        let config: Config = toml::from_str("[web]\nstorage = \"memory\"\n").unwrap();
        assert_eq!(config.web.storage, WebStorage::Memory);
    }

    #[test]
    fn rejects_the_physical_node_port() {
        let config: Config = toml::from_str("[server]\nport = 4403\n").unwrap();
        assert_eq!(config.validate(), Err(ConfigError::PortConflictsWithNode));
    }

    #[test]
    fn legacy_keys_form_one_implicit_node() {
        let config: Config = toml::from_str("[server]\nport = 4405\n").unwrap();
        let instances = config.instances();
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].name, "default");
        assert_eq!(instances[0].server.port, 4405);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn parses_multiple_nodes() {
        let config: Config = toml::from_str(
            r#"
[[nodes]]
name = "alpha"
[nodes.server]
port = 4404

[[nodes]]
name = "beta"
[nodes.server]
port = 4405
"#,
        )
        .unwrap();

        let instances = config.instances();
        assert_eq!(instances.len(), 2);
        assert_eq!(instances[0].name, "alpha");
        assert_eq!(instances[1].server.port, 4405);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_duplicate_ports_and_names() {
        let duplicate_port: Config = toml::from_str(
            r#"
[[nodes]]
name = "alpha"
[nodes.server]
port = 4404

[[nodes]]
name = "beta"
[nodes.server]
port = 4404
"#,
        )
        .unwrap();
        assert_eq!(
            duplicate_port.validate(),
            Err(ConfigError::DuplicateServerPort(4404))
        );

        let duplicate_name: Config = toml::from_str(
            r#"
[[nodes]]
name = "same"
[nodes.server]
port = 4404

[[nodes]]
name = "same"
[nodes.server]
port = 4405
"#,
        )
        .unwrap();
        assert_eq!(
            duplicate_name.validate(),
            Err(ConfigError::DuplicateNodeName("same".into()))
        );
    }

    #[test]
    fn rejects_renamed_keys() {
        assert!(toml::from_str::<Config>("[mqtt_bridge]\ngateway_enabled = true\n").is_err());
        assert!(toml::from_str::<Config>("[mqtt_bridge]\nraw_mirror_all = true\n").is_err());
    }
}
