//! Pure MQTT bridge policy: topics, identity, coverage and dedupe windows.
//!
//! Everything here is deterministic and clock-free. The daemon supplies the
//! monotonic time in milliseconds so the dedupe windows can be unit-tested.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use meshtastic::protobufs as pb;
use meshtastic::Message;

use crate::config::{MqttBridgeConfig, RawScope, SecondaryMqttConfig, StandardMirror};
use crate::state::StateCache;

pub const MAX_PAYLOAD: usize = 512;
pub const DEFAULT_REGION: &str = "EU_868";
pub const DEFAULT_BROKER: &str = "mqtt.meshtastic.org";

/// Node MQTT state captured by provisioning.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeMqttSnapshot {
    pub enabled: bool,
    pub proxy: bool,
    pub has_net: Option<bool>,
    pub address: String,
}

/// Sanitize a client id to printable ASCII and the 32-byte broker limit.
pub fn sanitize_client_id(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|character| character.is_ascii_graphic())
        .take(32)
        .collect();
    if cleaned.is_empty() {
        "multiplextashtic".to_owned()
    } else {
        cleaned
    }
}

/// Shared client id for both legs.
///
/// `mux-v{ver}-{username}-{nodehex}` when a username is configured, otherwise
/// `mux-v{ver}-{nodehex}-{uuid12}`. The username is budgeted so the node id is
/// never truncated off the 32-character limit.
pub fn client_id(version: &str, mqtt_username: &str, node_num: u32, uuid12: &str) -> String {
    let prefix = format!("mux-v{version}-");
    let node = format!("{node_num:08x}");

    let raw = if mqtt_username.is_empty() {
        format!("{prefix}{node}-{uuid12}")
    } else {
        let budget = 32usize.saturating_sub(prefix.len() + 1 + node.len());
        let username: String = mqtt_username
            .chars()
            .filter(|character| character.is_ascii_graphic())
            .take(budget)
            .collect();
        format!("{prefix}{username}-{node}")
    };

    sanitize_client_id(&raw)
}

/// Bare lowercase host used for broker comparisons.
pub fn normalize_broker_host(address: &str) -> String {
    let mut host = address.trim().to_ascii_lowercase();
    for prefix in ["mqtt://", "mqtts://", "tcp://", "ssl://"] {
        if let Some(rest) = host.strip_prefix(prefix) {
            host = rest.to_owned();
            break;
        }
    }
    let host = host
        .split('/')
        .next()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default();
    if host.is_empty() {
        DEFAULT_BROKER.to_owned()
    } else {
        host.to_owned()
    }
}

/// True when the secondary broker points at the primary host:port.
pub fn brokers_overlap(
    primary: &MqttBridgeConfig,
    secondary: Option<&SecondaryMqttConfig>,
) -> bool {
    let Some(secondary) = secondary else {
        return false;
    };
    if secondary.broker.is_empty() {
        return false;
    }
    normalize_broker_host(&secondary.broker) == normalize_broker_host(&primary.broker)
        && secondary.port == primary.port
}

/// True when the secondary leg should connect.
pub fn broker2_active(primary: &MqttBridgeConfig, secondary: Option<&SecondaryMqttConfig>) -> bool {
    primary.enabled
        && secondary.is_some_and(|config| config.enabled && !config.broker.is_empty())
        && !brokers_overlap(primary, secondary)
}

/// Ensure a proxy topic lives under the configured root.
pub fn topic_for_proxy(root: &str, topic: &str) -> String {
    let root = root.trim_end_matches('/');
    if topic.starts_with(root) {
        topic.to_owned()
    } else {
        format!("{root}/{}", topic.trim_start_matches('/'))
    }
}

/// Only `msh/...` and `raw/...` (plus the bare roots) are downlink topics.
pub fn is_valid_downlink_topic(root: &str, raw_root: &str, topic: &str) -> bool {
    let root = root.trim_end_matches('/');
    let raw_root = raw_root.trim_end_matches('/');
    topic == root
        || topic.starts_with(&format!("{root}/"))
        || topic == raw_root
        || topic.starts_with(&format!("{raw_root}/"))
}

/// Explicit region, learned region, then the EU_868 fallback.
pub fn resolve_region(explicit: &str, observed: Option<&str>) -> String {
    if !explicit.is_empty() {
        return explicit.to_owned();
    }
    if let Some(observed) = observed.filter(|region| !region.is_empty()) {
        return observed.to_owned();
    }
    DEFAULT_REGION.to_owned()
}

/// Learn the region from `{root}/{region}/...` proxy topics.
pub fn observed_region(root: &str, topic: &str) -> Option<String> {
    let root = root.trim_end_matches('/');
    let mut parts = topic.split('/');
    if parts.next()? != root {
        return None;
    }
    let region = parts.next()?;
    if region.is_empty() {
        None
    } else {
        Some(region.to_owned())
    }
}

pub fn raw_topic(raw_root: &str, region: &str, sender: u32) -> String {
    let raw_root = raw_root.trim_end_matches('/');
    format!("{raw_root}/{region}/!{sender:08x}")
}

pub fn standard_topic(root: &str, region: &str, channel: &str, node_num: u32) -> Option<String> {
    if channel.is_empty() {
        return None;
    }
    let root = root.trim_end_matches('/');
    Some(format!("{root}/{region}/2/e/{channel}/!{node_num:08x}"))
}

pub fn channel_name(cache: &StateCache, index: u32) -> Option<String> {
    let channel = cache
        .channels
        .iter()
        .find(|channel| channel.index == index as i32)?;
    let settings = channel.settings.as_ref()?;
    if settings.name.is_empty() {
        None
    } else {
        Some(settings.name.clone())
    }
}

pub fn channel_uplink(cache: &StateCache, index: u32) -> Option<bool> {
    let channel = cache
        .channels
        .iter()
        .find(|channel| channel.index == index as i32)?;
    channel
        .settings
        .as_ref()
        .map(|settings| settings.uplink_enabled)
}

/// True when the proxy path already owns this channel.
pub fn is_proxy_covered(cache: &StateCache, index: u32) -> bool {
    channel_uplink(cache, index).unwrap_or(false)
}

/// True when some other reporter (proxy or node-direct) carries this channel.
pub fn is_mqtt_covered(
    cache: &StateCache,
    index: u32,
    snapshot: Option<&NodeMqttSnapshot>,
) -> bool {
    if !is_proxy_covered(cache, index) {
        return false;
    }
    match snapshot {
        None => true,
        Some(snapshot) if snapshot.proxy => true,
        Some(snapshot) => snapshot.enabled && !snapshot.proxy && snapshot.has_net.unwrap_or(false),
    }
}

/// `auto` mirrors only when the node's broker differs from the bridge's broker.
pub fn standard_mirror_active(
    mode: StandardMirror,
    node_address: Option<&str>,
    bridge_broker: &str,
) -> bool {
    match mode {
        StandardMirror::On => true,
        StandardMirror::Off => false,
        StandardMirror::Auto => {
            let node = normalize_broker_host(node_address.unwrap_or_default());
            let bridge = normalize_broker_host(bridge_broker);
            node != bridge
        }
    }
}

/// Per-leg raw scope: `all` or everything not already proxy-covered.
pub fn matches_raw_scope(scope: RawScope, proxy_published: bool) -> bool {
    match scope {
        RawScope::All => true,
        RawScope::Uncovered => !proxy_published,
    }
}

/// Only LoRa transports (1..=4) are gatewayed/mirrored.
pub fn is_lora_transport(packet: &pb::MeshPacket) -> bool {
    matches!(packet.transport_mechanism, 1..=4)
}

pub fn gateway_id(node_num: u32) -> String {
    format!("!{node_num:08x}")
}

pub fn build_envelope(packet: &pb::MeshPacket, node_num: u32) -> Vec<u8> {
    build_envelope_with_channel(packet, node_num, "")
}

/// Build an envelope with the channel name used by the standard mirror.
pub fn build_envelope_with_channel(
    packet: &pb::MeshPacket,
    node_num: u32,
    channel_id: &str,
) -> Vec<u8> {
    pb::ServiceEnvelope {
        packet: Some(packet.clone()),
        channel_id: channel_id.to_owned(),
        gateway_id: gateway_id(node_num),
    }
    .encode_to_vec()
}

pub fn decode_envelope(payload: &[u8]) -> Option<pb::ServiceEnvelope> {
    pb::ServiceEnvelope::decode(payload).ok()
}

/// Packet id carried by a serialized service envelope, if any.
pub fn envelope_packet_id(payload: &[u8]) -> Option<u32> {
    decode_envelope(payload)?.packet.map(|packet| packet.id)
}

/// Loop guard: did this envelope come from our own gateway?
pub fn is_own_envelope(payload: &[u8], node_num: u32) -> bool {
    node_num != 0
        && decode_envelope(payload)
            .is_some_and(|envelope| envelope.gateway_id == gateway_id(node_num))
}

/// Fixed-window keyed set shared by the packet-id and echo caches.
#[derive(Debug, Clone)]
struct RecentWindow<K> {
    window_ms: u64,
    capacity: usize,
    entries: HashMap<K, u64>,
}

impl<K> RecentWindow<K>
where
    K: Eq + std::hash::Hash,
{
    fn new(window_ms: u64, capacity: usize) -> Self {
        Self {
            window_ms,
            capacity,
            entries: HashMap::new(),
        }
    }

    fn contains(&mut self, key: &K, now_ms: u64) -> bool {
        match self.entries.get(key).copied() {
            Some(timestamp) if now_ms.saturating_sub(timestamp) <= self.window_ms => true,
            Some(_) => {
                self.entries.remove(key);
                false
            }
            None => false,
        }
    }

    fn note(&mut self, key: K, now_ms: u64) {
        self.entries.insert(key, now_ms);
        if self.entries.len() > self.capacity {
            self.prune(now_ms);
        }
    }

    fn prune(&mut self, now_ms: u64) {
        let window = self.window_ms;
        self.entries
            .retain(|_, timestamp| now_ms.saturating_sub(*timestamp) <= window);
    }
}

/// Fixed-window packet-id dedupe set.
#[derive(Debug, Clone)]
pub struct RecentIds {
    inner: RecentWindow<u32>,
}

impl RecentIds {
    pub fn new(window_ms: u64, capacity: usize) -> Self {
        Self {
            inner: RecentWindow::new(window_ms, capacity),
        }
    }

    pub fn contains(&mut self, id: u32, now_ms: u64) -> bool {
        self.inner.contains(&id, now_ms)
    }

    pub fn note(&mut self, id: u32, now_ms: u64) {
        self.inner.note(id, now_ms);
    }

    /// Returns true when the id was already present and not stale.
    pub fn note_if_new(&mut self, id: u32, now_ms: u64) -> bool {
        if self.contains(id, now_ms) {
            return false;
        }
        self.note(id, now_ms);
        true
    }
}

/// Fixed-window echo suppression keyed by topic plus payload hash.
#[derive(Debug, Clone)]
pub struct RecentPublishes {
    inner: RecentWindow<(String, u64)>,
}

impl RecentPublishes {
    pub fn new(window_ms: u64, capacity: usize) -> Self {
        Self {
            inner: RecentWindow::new(window_ms, capacity),
        }
    }

    pub fn is_recent(&mut self, topic: &str, payload: &[u8], now_ms: u64) -> bool {
        let key = (topic.to_owned(), payload_hash(payload));
        self.inner.contains(&key, now_ms)
    }

    pub fn remember(&mut self, topic: &str, payload: &[u8], now_ms: u64) {
        let key = (topic.to_owned(), payload_hash(payload));
        self.inner.note(key, now_ms);
    }
}

fn payload_hash(payload: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    payload.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    fn primary() -> MqttBridgeConfig {
        MqttBridgeConfig::default()
    }

    fn secondary(broker: &str, port: u16) -> SecondaryMqttConfig {
        SecondaryMqttConfig {
            enabled: true,
            broker: broker.into(),
            port,
            ..Default::default()
        }
    }

    #[test]
    fn client_ids_are_stable_and_bounded() {
        assert_eq!(
            client_id("1.0.0", "", 0xD86C_BF84, "55a0ef813976"),
            "mux-v1.0.0-d86cbf84-55a0ef813976"
        );
        let with_user = client_id("1.0.0", "alice", 0xD86C_BF84, "x");
        assert!(with_user.starts_with("mux-v1.0.0-alice-d86cbf84"));
        assert!(with_user.len() <= 32);

        let long = client_id("1.0.0", &"x".repeat(80), 1, "y");
        assert!(long.len() <= 32);
        assert!(long.ends_with("00000001"));
        assert_eq!(sanitize_client_id("a b\tc"), "abc");
        assert_eq!(sanitize_client_id(""), "multiplextashtic");
    }

    #[test]
    fn broker_normalization_and_overlap() {
        assert_eq!(
            normalize_broker_host("MQTT://Example.COM:1883/path"),
            "example.com"
        );
        assert_eq!(normalize_broker_host(""), DEFAULT_BROKER);

        let p = primary();
        assert!(!brokers_overlap(&p, None));
        assert!(brokers_overlap(
            &p,
            Some(&secondary("mqtt.meshtastic.org", 8883))
        ));
        assert!(!brokers_overlap(
            &p,
            Some(&secondary("other.example", 8883))
        ));
    }

    #[test]
    fn topics_region_and_roots() {
        assert_eq!(topic_for_proxy("msh", "/2/e/foo"), "msh/2/e/foo");
        assert_eq!(topic_for_proxy("msh/", "msh/2/e/foo"), "msh/2/e/foo");
        assert!(is_valid_downlink_topic("msh", "raw", "msh/2/e/x"));
        assert!(is_valid_downlink_topic("msh", "raw", "raw/EU_868/x"));
        assert!(!is_valid_downlink_topic("msh", "raw", "other/x"));

        assert_eq!(
            observed_region("msh", "msh/EU_868/2/e/x"),
            Some("EU_868".into())
        );
        assert_eq!(observed_region("msh", "other/EU_868/x"), None);
        assert_eq!(resolve_region("", Some("US")), "US");
        assert_eq!(resolve_region("", None), DEFAULT_REGION);
        assert_eq!(resolve_region("ANZ", Some("US")), "ANZ");

        assert_eq!(raw_topic("raw", "EU_868", 0xAB), "raw/EU_868/!000000ab");
        assert_eq!(
            standard_topic("msh", "EU_868", "LongFast", 0xAB),
            Some("msh/EU_868/2/e/LongFast/!000000ab".into())
        );
        assert_eq!(standard_topic("msh", "EU_868", "", 0xAB), None);
    }

    #[test]
    fn standard_mirror_auto_rules() {
        assert!(standard_mirror_active(
            StandardMirror::On,
            Some(DEFAULT_BROKER),
            DEFAULT_BROKER
        ));
        assert!(!standard_mirror_active(
            StandardMirror::Off,
            Some("other"),
            DEFAULT_BROKER
        ));
        assert!(!standard_mirror_active(
            StandardMirror::Auto,
            Some(DEFAULT_BROKER),
            DEFAULT_BROKER
        ));
        assert!(standard_mirror_active(
            StandardMirror::Auto,
            Some("local.example"),
            DEFAULT_BROKER
        ));
        assert!(!standard_mirror_active(
            StandardMirror::Auto,
            None,
            DEFAULT_BROKER
        ));
    }

    #[test]
    fn raw_scope_and_transport_rules() {
        assert!(matches_raw_scope(RawScope::All, true));
        assert!(!matches_raw_scope(RawScope::Uncovered, true));
        assert!(matches_raw_scope(RawScope::Uncovered, false));

        let mut packet = pb::MeshPacket::default();
        for transport in 1..=4 {
            packet.transport_mechanism = transport;
            assert!(is_lora_transport(&packet));
        }
        for transport in [0, 5, 6, 7] {
            packet.transport_mechanism = transport;
            assert!(!is_lora_transport(&packet));
        }
    }

    #[test]
    fn channels_and_coverage() {
        use meshtastic::protobufs as pb;

        let mut cache = StateCache::new();
        cache.channels = vec![
            pb::Channel {
                index: 0,
                settings: Some(pb::ChannelSettings {
                    name: "LongFast".into(),
                    uplink_enabled: true,
                    ..Default::default()
                }),
                ..Default::default()
            },
            pb::Channel {
                index: 1,
                settings: Some(pb::ChannelSettings {
                    name: String::new(),
                    uplink_enabled: false,
                    ..Default::default()
                }),
                ..Default::default()
            },
        ];

        assert_eq!(channel_name(&cache, 0), Some("LongFast".into()));
        assert_eq!(channel_name(&cache, 1), None);
        assert_eq!(channel_uplink(&cache, 0), Some(true));
        assert_eq!(channel_uplink(&cache, 1), Some(false));
        assert_eq!(channel_uplink(&cache, 9), None);
        assert!(is_proxy_covered(&cache, 0));
        assert!(!is_proxy_covered(&cache, 1));

        let snapshot = NodeMqttSnapshot {
            enabled: true,
            proxy: false,
            has_net: Some(true),
            address: String::new(),
        };
        assert!(is_mqtt_covered(&cache, 0, Some(&snapshot)));
        assert!(!is_mqtt_covered(&cache, 1, Some(&snapshot)));
        assert!(is_mqtt_covered(&cache, 0, None));
    }

    #[test]
    fn recent_ids_expire_and_dedupe() {
        let mut ids = RecentIds::new(60_000, 2);
        assert!(!ids.contains(1, 0));
        assert!(ids.note_if_new(1, 0));
        assert!(!ids.note_if_new(1, 1_000));
        assert!(ids.contains(1, 60_000));
        assert!(!ids.contains(1, 60_001));
        assert!(ids.note_if_new(1, 60_001));
    }

    #[test]
    fn recent_publishes_suppress_echoes() {
        let mut recent = RecentPublishes::new(30_000, 10);
        recent.remember("msh/2/e/x", b"hello", 1_000);
        assert!(recent.is_recent("msh/2/e/x", b"hello", 2_000));
        assert!(!recent.is_recent("msh/2/e/x", b"other", 2_000));
        assert!(!recent.is_recent("msh/2/e/x", b"hello", 31_001));
    }

    #[test]
    fn envelopes_carry_the_gateway_id() {
        let packet = pb::MeshPacket {
            id: 42,
            ..Default::default()
        };
        let payload = build_envelope(&packet, 0xAB);
        assert_eq!(envelope_packet_id(&payload), Some(42));
        assert!(is_own_envelope(&payload, 0xAB));
        assert!(!is_own_envelope(&payload, 0xCD));
        assert!(!is_own_envelope(&payload, 0));
        assert_eq!(gateway_id(0xAB), "!000000ab");

        let with_channel = build_envelope_with_channel(&packet, 0xAB, "LongFast");
        let envelope = decode_envelope(&with_channel).unwrap();
        assert_eq!(envelope.channel_id, "LongFast");
    }
}
