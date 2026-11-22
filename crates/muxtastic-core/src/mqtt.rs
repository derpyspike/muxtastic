//! Pure MQTT bridge policy: topics, identity, coverage and dedupe windows.
//!
//! Everything here is deterministic and clock-free. The daemon supplies the
//! monotonic time in milliseconds so the dedupe windows can be unit-tested.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::Ipv6Addr;

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

/// Bare lowercase host used for broker comparisons and for connecting.
///
/// Strips a URL scheme, a path and a `:port` suffix. IPv6 literals are
/// returned without brackets: `[fd7a::1]:1883` and `fd7a::1` both give
/// `fd7a::1`. Only a genuinely empty input falls back to the public default
/// broker; anything that cannot be understood is returned as-is so the
/// connection fails visibly instead of silently going to the wrong host.
pub fn normalize_broker_host(address: &str) -> String {
    let lowered = address.trim().to_ascii_lowercase();
    let mut rest = lowered.as_str();
    for prefix in ["mqtt://", "mqtts://", "tcp://", "ssl://"] {
        if let Some(stripped) = rest.strip_prefix(prefix) {
            rest = stripped;
            break;
        }
    }
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return if rest.is_empty() {
            DEFAULT_BROKER.to_owned()
        } else {
            rest.to_owned()
        };
    }

    // `[v6]` or `[v6]:port`.
    if let Some(bracketed) = authority.strip_prefix('[') {
        return match bracketed.split_once(']') {
            Some((host, _port)) if !host.is_empty() => host.to_owned(),
            _ => authority.to_owned(),
        };
    }

    // A bare IPv6 literal has several colons and no port.
    if authority.parse::<Ipv6Addr>().is_ok() {
        return authority.to_owned();
    }

    match authority.split_once(':') {
        None => authority.to_owned(),
        // `host:port`. More colons that are not an IPv6 address, or an empty
        // host, are not something we can interpret.
        Some((host, port)) if !host.is_empty() && !port.contains(':') => host.to_owned(),
        Some(_) => authority.to_owned(),
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
    let under_root = topic
        .strip_prefix(root)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
    if under_root {
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
///
/// `capacity` is a hard cap: when the set is full the oldest entry is evicted,
/// even if it has not expired yet. `order` remembers insertion order so both
/// expiry and eviction pop from the front instead of scanning the map.
/// Timestamps are expected to be monotonic (the daemon passes elapsed time).
#[derive(Debug, Clone)]
struct RecentWindow<K> {
    window_ms: u64,
    capacity: usize,
    entries: HashMap<K, u64>,
    /// `(key, timestamp)` in insertion order. An element is stale when the map
    /// holds a newer timestamp for its key (the key was noted again).
    order: VecDeque<(K, u64)>,
}

impl<K> RecentWindow<K>
where
    K: Eq + std::hash::Hash + Clone,
{
    fn new(window_ms: u64, capacity: usize) -> Self {
        Self {
            window_ms,
            capacity: capacity.max(1),
            entries: HashMap::new(),
            order: VecDeque::new(),
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
        self.drop_expired(now_ms);
        self.entries.insert(key.clone(), now_ms);
        self.order.push_back((key, now_ms));
        while self.entries.len() > self.capacity {
            if !self.pop_oldest() {
                break;
            }
        }
        // Re-noting the same keys leaves stale elements behind; compact
        // before they can outgrow the cap. Amortised O(1) per insert.
        if self.order.len() > self.capacity.saturating_mul(2) {
            let entries = &self.entries;
            self.order
                .retain(|(key, timestamp)| entries.get(key) == Some(timestamp));
        }
    }

    /// Pop the front element and remove its key unless a newer note exists.
    fn pop_oldest(&mut self) -> bool {
        let Some((key, timestamp)) = self.order.pop_front() else {
            return false;
        };
        if self.entries.get(&key) == Some(&timestamp) {
            self.entries.remove(&key);
        }
        true
    }

    fn drop_expired(&mut self, now_ms: u64) {
        while let Some((_, timestamp)) = self.order.front() {
            if now_ms.saturating_sub(*timestamp) <= self.window_ms {
                break;
            }
            self.pop_oldest();
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
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

    /// Records the id and returns true when it is new (absent or stale);
    /// returns false, without refreshing it, when it was seen within the window.
    pub fn note_if_new(&mut self, id: u32, now_ms: u64) -> bool {
        if self.contains(id, now_ms) {
            return false;
        }
        self.note(id, now_ms);
        true
    }
}

/// Fixed-window echo suppression keyed by a hash of topic plus payload.
#[derive(Debug, Clone)]
pub struct RecentPublishes {
    inner: RecentWindow<u64>,
}

impl RecentPublishes {
    pub fn new(window_ms: u64, capacity: usize) -> Self {
        Self {
            inner: RecentWindow::new(window_ms, capacity),
        }
    }

    pub fn is_recent(&mut self, topic: &str, payload: &[u8], now_ms: u64) -> bool {
        self.inner.contains(&publish_key(topic, payload), now_ms)
    }

    pub fn remember(&mut self, topic: &str, payload: &[u8], now_ms: u64) {
        self.inner.note(publish_key(topic, payload), now_ms);
    }
}

/// One 64-bit key for a publish; avoids copying the topic for every lookup.
fn publish_key(topic: &str, payload: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    topic.hash(&mut hasher);
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
        assert_eq!(normalize_broker_host("  "), DEFAULT_BROKER);
        assert_eq!(normalize_broker_host("mqtt://"), DEFAULT_BROKER);
        assert_eq!(normalize_broker_host("broker.local:1883"), "broker.local");
        assert_eq!(normalize_broker_host("192.168.1.6:1883"), "192.168.1.6");

        // IPv6 literals keep every group and lose only brackets and port.
        assert_eq!(normalize_broker_host("::1"), "::1");
        assert_eq!(normalize_broker_host("[fd7a::1]"), "fd7a::1");
        assert_eq!(normalize_broker_host("[FD7A::1]:1883"), "fd7a::1");
        assert_eq!(normalize_broker_host("2001:db8::1"), "2001:db8::1");
        assert_eq!(
            normalize_broker_host("mqtts://[2001:db8::1]:8883/x"),
            "2001:db8::1"
        );

        // Unparseable input is never replaced by the public broker.
        for odd in [":1883", "[fd7a::1", "[]", "a:b:c", "mqtt:///path"] {
            assert_ne!(normalize_broker_host(odd), DEFAULT_BROKER, "{odd}");
        }
        assert_eq!(normalize_broker_host("a:b:c"), "a:b:c");

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

        // Two different IPv6 brokers no longer collapse into one host.
        let mut v6 = primary();
        v6.broker = "[fd7a::1]".into();
        assert!(!brokers_overlap(&v6, Some(&secondary("[fd7a::2]", 8883))));
        assert!(brokers_overlap(&v6, Some(&secondary("fd7a::1", 8883))));
    }

    #[test]
    fn topics_region_and_roots() {
        assert_eq!(topic_for_proxy("msh", "/2/e/foo"), "msh/2/e/foo");
        assert_eq!(topic_for_proxy("msh/", "msh/2/e/foo"), "msh/2/e/foo");
        assert_eq!(topic_for_proxy("msh", "msh"), "msh");
        // A shared prefix is not the root: these stay confined under it.
        assert_eq!(topic_for_proxy("msh", "mshx/2/e/foo"), "msh/mshx/2/e/foo");
        assert_eq!(topic_for_proxy("msh", "msh2"), "msh/msh2");
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
    fn recent_window_capacity_is_a_hard_cap() {
        // Nothing expires (huge window), so only the cap can bound the set.
        let mut ids = RecentIds::new(u64::MAX, 3);
        for id in 1..=10 {
            ids.note(id, u64::from(id));
            assert!(ids.inner.len() <= 3);
        }
        // The three newest survive, the oldest were evicted.
        assert!(!ids.contains(7, 11));
        assert!(ids.contains(8, 11));
        assert!(ids.contains(10, 11));

        // Re-noting a key refreshes it: it is no longer the oldest.
        ids.note(8, 12);
        ids.note(11, 13);
        ids.note(12, 14);
        assert!(ids.contains(8, 15));
        assert!(!ids.contains(9, 15));
        assert!(!ids.contains(10, 15));

        // Hammering one key does not let the bookkeeping grow.
        for now in 20..10_000 {
            ids.note(8, now);
        }
        assert!(ids.inner.order.len() <= 6);
        assert!(ids.inner.len() <= 3);

        let mut publishes = RecentPublishes::new(u64::MAX, 4);
        for index in 0..100u64 {
            publishes.remember("msh/x", &index.to_le_bytes(), index);
        }
        assert_eq!(publishes.inner.len(), 4);
        assert!(publishes.is_recent("msh/x", &99u64.to_le_bytes(), 100));
        assert!(!publishes.is_recent("msh/x", &0u64.to_le_bytes(), 100));
    }

    #[test]
    fn recent_window_drops_expired_entries_on_insert() {
        let mut ids = RecentIds::new(1_000, 100);
        for id in 0..50 {
            ids.note(id, 0);
        }
        ids.note(99, 5_000);
        assert_eq!(ids.inner.len(), 1);
        assert!(ids.contains(99, 5_500));
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
