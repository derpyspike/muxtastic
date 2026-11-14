use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use meshtastic::protobufs::{self as pb, to_radio};
use meshtastic::Message;
use muxtastic_core::config::{MqttBridgeConfig, SecondaryMqttConfig};
use muxtastic_core::mqtt::{
    self, broker2_active as compute_broker2_active, client_id, is_lora_transport, is_own_envelope,
    is_valid_downlink_topic, matches_raw_scope, observed_region, raw_topic, resolve_region,
    standard_mirror_active, standard_topic, topic_for_proxy, NodeMqttSnapshot, RecentIds,
    RecentPublishes, MAX_PAYLOAD,
};
use muxtastic_core::raw_tunnel::{feed_topic, RawTunnelFrame, RawTunnelKind};
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS, TlsConfiguration, Transport};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::app::AppState;

const ECHO_WINDOW_MS: u64 = 30_000;
const ID_WINDOW_MS: u64 = 60_000;
const STATS_INTERVAL: Duration = Duration::from_secs(300);

type DownlinkCallback = Arc<dyn Fn(String, Vec<u8>, bool) + Send + Sync>;

struct MqttEndpoint {
    host: String,
    port: u16,
    username: String,
    password: String,
    tls: bool,
    keepalive: u64,
}

impl MqttEndpoint {
    fn from_primary(config: &MqttBridgeConfig) -> Self {
        Self {
            host: default_host(&config.broker),
            port: config.port,
            username: config.username.clone(),
            password: config.password.clone(),
            tls: config.tls,
            keepalive: config.keepalive,
        }
    }

    fn from_secondary(config: &SecondaryMqttConfig) -> Self {
        Self {
            host: default_host(&config.broker),
            port: config.port,
            username: config.username.clone(),
            password: config.password.clone(),
            tls: config.tls,
            keepalive: config.keepalive,
        }
    }
}

fn default_host(host: &str) -> String {
    mqtt::normalize_broker_host(host)
}

/// One broker connection: reconnect loop, publish and counters.
struct MqttLeg {
    name: &'static str,
    client_id: String,
    endpoint: MqttEndpoint,
    subscribe_topics: Vec<String>,
    client: StdMutex<Option<AsyncClient>>,
    connected: AtomicBool,
    published: AtomicU64,
    dropped: AtomicU64,
}

impl MqttLeg {
    fn new(
        name: &'static str,
        client_id: String,
        endpoint: MqttEndpoint,
        subscribe_topics: Vec<String>,
    ) -> Self {
        Self {
            name,
            client_id,
            endpoint,
            subscribe_topics,
            client: StdMutex::new(None),
            connected: AtomicBool::new(false),
            published: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    fn note_drop(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn published(&self) -> u64 {
        self.published.load(Ordering::Relaxed)
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    async fn publish(&self, topic: &str, payload: &[u8], retain: bool) -> bool {
        let client = self
            .client
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let Some(client) = client else {
            self.note_drop();
            debug!(leg = self.name, "publish dropped: not connected");
            return false;
        };
        if !self.is_connected() {
            self.note_drop();
            debug!(leg = self.name, "publish dropped: no session");
            return false;
        }

        match client
            .publish(topic, QoS::AtMostOnce, retain, payload.to_vec())
            .await
        {
            Ok(()) => {
                self.published.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(error) => {
                self.note_drop();
                warn!(leg = self.name, %error, "MQTT publish failed");
                false
            }
        }
    }

    async fn run(
        self: Arc<Self>,
        downlink: Option<DownlinkCallback>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut backoff = 1u64;

        'outer: loop {
            if *shutdown.borrow() {
                break;
            }

            let mut options = MqttOptions::new(
                self.client_id.as_str(),
                self.endpoint.host.as_str(),
                self.endpoint.port,
            );
            options.set_keep_alive(Duration::from_secs(self.endpoint.keepalive.max(1)));
            if !self.endpoint.username.is_empty() {
                options.set_credentials(
                    self.endpoint.username.as_str(),
                    self.endpoint.password.as_str(),
                );
            }
            if self.endpoint.tls {
                options.set_transport(Transport::tls_with_config(TlsConfiguration::default()));
            }

            let (client, mut eventloop) = AsyncClient::new(options, 10);
            *self
                .client
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = Some(client.clone());

            info!(
                leg = self.name,
                host = %self.endpoint.host,
                port = self.endpoint.port,
                tls = self.endpoint.tls,
                client_id = %self.client_id,
                "MQTT connecting"
            );

            loop {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break 'outer;
                        }
                    }
                    event = eventloop.poll() => {
                        match event {
                            Ok(Event::Incoming(Packet::ConnAck(_))) => {
                                self.connected.store(true, Ordering::SeqCst);
                                backoff = 1;
                                info!(leg = self.name, "MQTT connected");
                                for topic in &self.subscribe_topics {
                                    if let Err(error) =
                                        client.subscribe(topic.as_str(), QoS::AtMostOnce).await
                                    {
                                        warn!(leg = self.name, topic, %error, "MQTT subscribe failed");
                                    }
                                }
                            }
                            Ok(Event::Incoming(Packet::Publish(publish))) => {
                                if let Some(callback) = &downlink {
                                    callback(
                                        publish.topic,
                                        publish.payload.to_vec(),
                                        publish.retain,
                                    );
                                }
                            }
                            Ok(_) => {}
                            Err(error) => {
                                warn!(leg = self.name, %error, "MQTT connection lost");
                                break;
                            }
                        }
                    }
                }
            }

            self.connected.store(false, Ordering::SeqCst);
            *self
                .client
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = None;

            if *shutdown.borrow() {
                break;
            }

            info!(leg = self.name, seconds = backoff, "MQTT reconnecting");
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(backoff)) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
            backoff = (backoff * 2).min(60);
        }

        self.connected.store(false, Ordering::SeqCst);
        *self
            .client
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
        info!(leg = self.name, "MQTT leg stopped");
    }
}

/// Policy and fan-out over the primary and optional secondary leg.
pub struct MqttBridge {
    state: Arc<AppState>,
    config: MqttBridgeConfig,
    node_num: u32,
    primary: Arc<MqttLeg>,
    secondary: Option<Arc<MqttLeg>>,
    broker2_active: bool,
    observed_region: StdMutex<Option<String>>,
    node_mqtt: StdMutex<Option<NodeMqttSnapshot>>,
    gateway_ids: StdMutex<RecentIds>,
    proxy_ids: StdMutex<RecentIds>,
    recent_publishes: StdMutex<RecentPublishes>,
    last_channel: StdMutex<Option<u32>>,
    ok_to_mqtt_missing_logged: AtomicBool,
    gateway_published: AtomicU64,
    standard_mirrored: AtomicU64,
    jencore_raw_published: AtomicU64,
    jenrnode_raw_published: AtomicU64,
    dropped_uplink: AtomicU64,
    dropped_downlink_disabled: AtomicU64,
    loop_guard_drops: AtomicU64,
    echo_suppressed: AtomicU64,
    retained_skipped: AtomicU64,
    started: Instant,
    tasks: StdMutex<Vec<JoinHandle<()>>>,
}

impl MqttBridge {
    pub fn new(state: Arc<AppState>, node_num: u32) -> Self {
        let config = state.config.mqtt_bridge.clone();
        let secondary_config = config.broker2.as_ref();
        let broker2_active = compute_broker2_active(&config, secondary_config);

        let uuid12 = format!("{:012x}", rand::random::<u64>() & 0x0000_FFFF_FFFF_FFFF);
        let id = client_id(
            env!("CARGO_PKG_VERSION"),
            &config.mqtt_username,
            node_num,
            &uuid12,
        );

        let root = config.root_topic.trim_end_matches('/');
        let raw_root = config.raw_root_topic.trim_end_matches('/');
        let topics = vec![format!("{root}/#"), format!("{raw_root}/#")];

        let primary = Arc::new(MqttLeg::new(
            "primary",
            id.clone(),
            MqttEndpoint::from_primary(&config),
            topics,
        ));

        let secondary = if broker2_active {
            secondary_config.map(|secondary| {
                Arc::new(MqttLeg::new(
                    "secondary",
                    id.clone(),
                    MqttEndpoint::from_secondary(secondary),
                    Vec::new(),
                ))
            })
        } else {
            None
        };

        Self {
            state,
            config,
            node_num,
            primary,
            secondary,
            broker2_active,
            observed_region: StdMutex::new(None),
            node_mqtt: StdMutex::new(None),
            gateway_ids: StdMutex::new(RecentIds::new(ID_WINDOW_MS, 500)),
            proxy_ids: StdMutex::new(RecentIds::new(ID_WINDOW_MS, 500)),
            recent_publishes: StdMutex::new(RecentPublishes::new(ECHO_WINDOW_MS, 200)),
            last_channel: StdMutex::new(None),
            ok_to_mqtt_missing_logged: AtomicBool::new(false),
            gateway_published: AtomicU64::new(0),
            standard_mirrored: AtomicU64::new(0),
            jencore_raw_published: AtomicU64::new(0),
            jenrnode_raw_published: AtomicU64::new(0),
            dropped_uplink: AtomicU64::new(0),
            dropped_downlink_disabled: AtomicU64::new(0),
            loop_guard_drops: AtomicU64::new(0),
            echo_suppressed: AtomicU64::new(0),
            retained_skipped: AtomicU64::new(0),
            started: Instant::now(),
            tasks: StdMutex::new(Vec::new()),
        }
    }

    pub fn start(self: &Arc<Self>) {
        let shutdown = self.state.subscribe_shutdown();

        let downlink: DownlinkCallback = {
            let bridge = Arc::clone(self);
            Arc::new(move |topic, payload, retained| {
                bridge.handle_downlink(topic, payload, retained);
            })
        };

        let mut tasks = Vec::new();
        tasks.push(tokio::spawn(
            Arc::clone(&self.primary).run(Some(downlink), shutdown.clone()),
        ));
        if let Some(secondary) = &self.secondary {
            tasks.push(tokio::spawn(
                Arc::clone(secondary).run(None, shutdown.clone()),
            ));
        }
        tasks.push(tokio::spawn(stats_loop(Arc::clone(self), shutdown)));

        *self.tasks.lock().unwrap_or_else(|error| error.into_inner()) = tasks;

        info!(
            client_id = %self.primary.client_id,
            broker = %self.config.broker,
            port = self.config.port,
            "MQTT bridge started"
        );

        if self.broker2_active {
            if let Some(secondary) = &self.secondary {
                info!(
                    client_id = %secondary.client_id,
                    broker = %secondary.endpoint.host,
                    port = secondary.endpoint.port,
                    "MQTT secondary leg started"
                );
            }
        } else if self.config.broker2.is_some()
            && mqtt::brokers_overlap(&self.config, self.config.broker2.as_ref())
        {
            warn!("broker2 duplicates the primary broker; secondary leg disabled");
        }
    }

    pub fn stop(&self) {
        let tasks: Vec<JoinHandle<()>> = self
            .tasks
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .drain(..)
            .collect();
        for task in tasks {
            task.abort();
        }
        info!("MQTT bridge stopped");
    }

    pub fn is_connected(&self) -> bool {
        self.primary.is_connected()
    }

    pub fn set_node_mqtt_snapshot(&self, snapshot: Option<NodeMqttSnapshot>) {
        *self
            .node_mqtt
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = snapshot;
    }

    pub fn mark_channel(&self, index: i32) {
        *self
            .last_channel
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(index as u32);
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn observe_region(&self, topic: &str) {
        let Some(region) = observed_region(&self.config.root_topic, topic) else {
            return;
        };
        let mut observed = self
            .observed_region
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if observed.as_deref() != Some(region.as_str()) {
            *observed = Some(region.clone());
            info!(region, "learned MQTT region from a proxy topic");
        }
    }

    fn resolve_region(&self) -> String {
        let observed = self
            .observed_region
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        resolve_region(&self.config.region, observed.as_deref())
    }

    fn standard_mirror_active(&self) -> bool {
        let node = self
            .node_mqtt
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        standard_mirror_active(
            self.config.standard_mirror,
            node.as_ref().map(|snapshot| snapshot.address.as_str()),
            &self.config.broker,
        )
    }

    fn note_proxy_published(&self, id: u32) {
        let now = self.now_ms();
        self.proxy_ids
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .note(id, now);
    }

    fn is_proxy_published(&self, id: u32) -> bool {
        let now = self.now_ms();
        self.proxy_ids
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .contains(id, now)
    }

    fn note_gateway_id(&self, id: u32) -> bool {
        let now = self.now_ms();
        self.gateway_ids
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .note_if_new(id, now)
    }

    fn remember_publish(&self, topic: &str, payload: &[u8]) {
        let now = self.now_ms();
        self.recent_publishes
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remember(topic, payload, now);
    }

    fn is_recent_echo(&self, topic: &str, payload: &[u8]) -> bool {
        let now = self.now_ms();
        self.recent_publishes
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_recent(topic, payload, now)
    }

    fn check_uplink_allowed(&self) -> bool {
        if self.config.ignore_ok_to_mqtt {
            return true;
        }
        let Some(index) = *self
            .last_channel
            .lock()
            .unwrap_or_else(|error| error.into_inner())
        else {
            return true;
        };
        let allowed = {
            let cache = self
                .state
                .cache
                .read()
                .unwrap_or_else(|error| error.into_inner());
            mqtt::channel_uplink(&cache, index)
        };
        match allowed {
            Some(allowed) => {
                if !allowed && !self.ok_to_mqtt_missing_logged.swap(true, Ordering::Relaxed) {
                    warn!("channel uplink_enabled=false; set ignore_ok_to_mqtt=true to bypass");
                }
                allowed
            }
            None => true,
        }
    }

    async fn publish_secondary(&self, topic: &str, payload: &[u8]) -> bool {
        let Some(secondary) = &self.secondary else {
            return false;
        };
        if !self.broker2_active {
            return false;
        }
        if payload.len() > MAX_PAYLOAD {
            secondary.note_drop();
            return false;
        }
        if !secondary.is_connected() {
            secondary.note_drop();
            debug!("MQTT secondary not connected; dropping mirror");
            return false;
        }
        secondary.publish(topic, payload, false).await
    }

    /// Proxy relay: publish a node/client proxy message verbatim.
    pub async fn publish_proxy(&self, topic: String, payload: Vec<u8>, retain: bool) -> bool {
        if !self.config.enabled || !self.config.uplink_enabled {
            self.dropped_uplink.fetch_add(1, Ordering::Relaxed);
            debug!("MQTT uplink disabled; dropped proxy message");
            return false;
        }
        if !self.config.ignore_ok_to_mqtt && !self.check_uplink_allowed() {
            self.dropped_uplink.fetch_add(1, Ordering::Relaxed);
            debug!("channel uplink flag blocked the proxy publish");
            return false;
        }

        let topic = topic_for_proxy(&self.config.root_topic, &topic);
        self.observe_region(&topic);
        if payload.len() > MAX_PAYLOAD {
            warn!(
                bytes = payload.len(),
                "MQTT payload exceeds {MAX_PAYLOAD}; dropping"
            );
            return false;
        }
        if !self.primary.is_connected() {
            self.dropped_uplink.fetch_add(1, Ordering::Relaxed);
            debug!("MQTT primary not connected; dropping proxy publish");
            return false;
        }
        if !self.primary.publish(&topic, &payload, retain).await {
            return false;
        }

        self.remember_publish(&topic, &payload);
        let _ = self.publish_secondary(&topic, &payload).await;
        true
    }

    /// A proxy frame arrived from the physical node.
    pub async fn publish_from_physical_proxy(
        &self,
        topic: String,
        payload: Vec<u8>,
        retained: bool,
    ) -> bool {
        if let Some(id) = mqtt::envelope_packet_id(&payload).filter(|id| *id != 0) {
            self.note_proxy_published(id);
        }
        self.publish_proxy(topic, payload, retained).await
    }

    /// Raw gateway: publish one LoRa packet to `raw/{region}/!{sender}`.
    pub async fn publish_packet(&self, packet: &pb::MeshPacket) -> bool {
        if !self.config.enabled {
            return false;
        }
        if packet.via_mqtt {
            debug!("MQTT gateway skipping a via_mqtt packet");
            return false;
        }
        if !is_lora_transport(packet) {
            debug!(
                transport = packet.transport_mechanism,
                "MQTT gateway skipping a non-LoRa packet"
            );
            return false;
        }

        let proxy_covered = self.is_proxy_published(packet.id);
        let primary_want =
            self.config.raw_uplink && matches_raw_scope(self.config.raw_scope, proxy_covered);
        let secondary_want = self.broker2_active
            && self.config.broker2.as_ref().is_some_and(|secondary| {
                secondary.raw_uplink && matches_raw_scope(secondary.raw_scope, proxy_covered)
            });
        if !primary_want && !secondary_want {
            debug!(id = packet.id, "MQTT gateway skipped: no leg wants raw");
            return false;
        }
        if !self.note_gateway_id(packet.id) {
            debug!(id = packet.id, "MQTT gateway skipped a duplicate id");
            return false;
        }

        let payload = mqtt::build_envelope(packet, self.node_num);
        if payload.len() > MAX_PAYLOAD {
            warn!(
                bytes = payload.len(),
                "MQTT gateway payload too large; dropping"
            );
            return false;
        }
        let topic = raw_topic(
            &self.config.raw_root_topic,
            &self.resolve_region(),
            packet.from,
        );

        let mut published = false;
        if primary_want {
            if !self.primary.is_connected() {
                debug!("MQTT gateway primary not connected; dropping packet");
            } else if self.primary.publish(&topic, &payload, false).await {
                self.gateway_published.fetch_add(1, Ordering::Relaxed);
                published = true;
            }
        }
        if secondary_want && self.publish_secondary(&topic, &payload).await {
            published = true;
        }

        if published {
            self.remember_publish(&topic, &payload);
            debug!(topic, bytes = payload.len(), "MQTT gateway published");
        }
        published
    }

    /// Standard mirror: publish a known channel to `msh/{region}/2/e/{chan}`.
    pub async fn publish_standard(&self, packet: &pb::MeshPacket) -> bool {
        if !self.config.enabled || !self.standard_mirror_active() {
            return false;
        }
        if packet.via_mqtt {
            return false;
        }
        if !is_lora_transport(packet) {
            debug!(
                transport = packet.transport_mechanism,
                "standard mirror skipping a non-LoRa packet"
            );
            return false;
        }

        let channel = {
            let cache = self
                .state
                .cache
                .read()
                .unwrap_or_else(|error| error.into_inner());
            mqtt::channel_name(&cache, packet.channel)
        };
        let Some(channel) = channel else {
            return false;
        };
        let Some(topic) = standard_topic(
            &self.config.root_topic,
            &self.resolve_region(),
            &channel,
            self.node_num,
        ) else {
            return false;
        };
        if self.is_proxy_published(packet.id) {
            debug!(
                id = packet.id,
                "standard mirror skipping a proxy-covered id"
            );
            return false;
        }

        let payload = mqtt::build_envelope_with_channel(packet, self.node_num, &channel);
        if payload.len() > MAX_PAYLOAD {
            warn!(
                bytes = payload.len(),
                "standard mirror payload too large; dropping"
            );
            return false;
        }
        if !self.primary.is_connected() {
            debug!("standard mirror primary not connected; dropping packet");
            return false;
        }
        if !self.primary.publish(&topic, &payload, false).await {
            return false;
        }

        self.standard_mirrored.fetch_add(1, Ordering::Relaxed);
        self.remember_publish(&topic, &payload);
        info!(topic, bytes = payload.len(), "standard mirror published");
        let _ = self.publish_secondary(&topic, &payload).await;
        true
    }

    /// Publish one reassembled Nexus JRAW frame to its per-feed topic.
    /// Independent of `raw_uplink` and `standard_mirror`.
    pub async fn publish_raw_tunnel_frame(&self, frame: &RawTunnelFrame) -> bool {
        if !self.config.enabled
            || (!self.config.jencore_raw_uplink && !self.config.jenrnode_raw_uplink)
        {
            return false;
        }

        let (enabled, root, counter) = match frame.kind {
            RawTunnelKind::MeshCore => (
                self.config.jencore_raw_uplink,
                self.config.jencore_root_topic.as_str(),
                &self.jencore_raw_published,
            ),
            RawTunnelKind::RNode => (
                self.config.jenrnode_raw_uplink,
                self.config.jenrnode_root_topic.as_str(),
                &self.jenrnode_raw_published,
            ),
        };
        if !enabled || frame.frame.is_empty() {
            return false;
        }

        let root = if root.trim().is_empty() {
            frame.kind.label()
        } else {
            root
        };
        let topic = feed_topic(root, &self.resolve_region(), frame.gateway);
        if !self.primary.is_connected() {
            debug!(%topic, "raw tunnel feed dropped: primary not connected");
            return false;
        }
        if !self.primary.publish(&topic, &frame.frame, false).await {
            return false;
        }

        counter.fetch_add(1, Ordering::Relaxed);
        self.remember_publish(&topic, &frame.frame);
        let _ = self.publish_secondary(&topic, &frame.frame).await;
        debug!(
            %topic,
            kind = frame.kind.label(),
            sequence = frame.sequence,
            bytes = frame.frame.len(),
            "raw tunnel feed published"
        );
        true
    }

    /// Handle one broker message (downlink) and inject it into the node.
    fn handle_downlink(&self, topic: String, payload: Vec<u8>, retained: bool) {
        if !is_valid_downlink_topic(&self.config.root_topic, &self.config.raw_root_topic, &topic) {
            debug!(%topic, "ignoring non-root downlink topic");
            return;
        }
        if !self.config.downlink_enabled {
            self.dropped_downlink_disabled
                .fetch_add(1, Ordering::Relaxed);
            debug!(%topic, "downlink disabled; dropped message");
            return;
        }
        if self.is_recent_echo(&topic, &payload) {
            self.echo_suppressed.fetch_add(1, Ordering::Relaxed);
            debug!(%topic, "echo suppression dropped our own uplink");
            return;
        }
        if retained {
            self.retained_skipped.fetch_add(1, Ordering::Relaxed);
            info!(%topic, "skipping retained downlink (stale replay guard)");
            return;
        }
        if is_own_envelope(&payload, self.node_num) {
            self.loop_guard_drops.fetch_add(1, Ordering::Relaxed);
            debug!("loop guard dropped our own envelope");
            return;
        }
        if !self.state.connected.load(Ordering::SeqCst) || self.node_num == 0 {
            debug!("downlink deferred until the physical link is ready");
            return;
        }

        debug!(%topic, bytes = payload.len(), "injecting MQTT downlink into the mesh");
        let to_radio = pb::ToRadio {
            payload_variant: Some(to_radio::PayloadVariant::MqttClientProxyMessage(
                pb::MqttClientProxyMessage {
                    topic,
                    retained: false,
                    payload_variant: Some(pb::mqtt_client_proxy_message::PayloadVariant::Data(
                        payload,
                    )),
                },
            )),
        };
        self.state.queue_to_node(to_radio.encode_to_vec());
    }

    fn stats(&self) -> MqttStats {
        let published2 = self
            .secondary
            .as_ref()
            .map(|leg| leg.published())
            .unwrap_or(0);
        let dropped2 = self
            .secondary
            .as_ref()
            .map(|leg| leg.dropped())
            .unwrap_or(0);

        MqttStats {
            published: self.primary.published(),
            gateway: self.gateway_published.load(Ordering::Relaxed),
            standard: self.standard_mirrored.load(Ordering::Relaxed),
            jencore_raw: self.jencore_raw_published.load(Ordering::Relaxed),
            jenrnode_raw: self.jenrnode_raw_published.load(Ordering::Relaxed),
            dropped_uplink: self.dropped_uplink.load(Ordering::Relaxed),
            dropped_downlink: self.dropped_downlink_disabled.load(Ordering::Relaxed),
            loop_guard: self.loop_guard_drops.load(Ordering::Relaxed),
            echo: self.echo_suppressed.load(Ordering::Relaxed),
            published2,
            dropped2,
        }
    }
}

struct MqttStats {
    published: u64,
    gateway: u64,
    standard: u64,
    jencore_raw: u64,
    jenrnode_raw: u64,
    dropped_uplink: u64,
    dropped_downlink: u64,
    loop_guard: u64,
    echo: u64,
    published2: u64,
    dropped2: u64,
}

async fn stats_loop(bridge: Arc<MqttBridge>, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(STATS_INTERVAL) => {
                let stats = bridge.stats();
                info!(
                    connected = bridge.primary.is_connected(),
                    published = stats.published,
                    gateway = stats.gateway,
                    standard = stats.standard,
                    jencore_raw = stats.jencore_raw,
                    jenrnode_raw = stats.jenrnode_raw,
                    dropped_uplink = stats.dropped_uplink,
                    dropped_downlink = stats.dropped_downlink,
                    loop_guard = stats.loop_guard,
                    echo = stats.echo,
                    published2 = stats.published2,
                    dropped2 = stats.dropped2,
                    "MQTT bridge stats"
                );
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}
