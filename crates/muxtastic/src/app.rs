use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, RwLock, Weak};
use std::time::Instant;

use meshtastic::protobufs as pb;
use muxtastic_core::config::Config;
use muxtastic_core::nexus::NexusDiagnostics;
use muxtastic_core::protocol::encode_frame;
use muxtastic_core::raw_tunnel::{AssemblerResult, RawTunnelAssembler, RawTunnelFrame};
use muxtastic_core::router::Cidr;
use muxtastic_core::state::StateCache;
use muxtastic_web::Database;
use tokio::io::AsyncWrite;
use tokio::sync::{broadcast, mpsc, watch, Mutex};
use tracing::{debug, warn};

pub type PhysicalWriter = Box<dyn AsyncWrite + Unpin + Send>;

/// One frame queued for connected clients.
///
/// `exclude_client` lets a client-originated echo skip the client that sent it,
/// so apps do not receive their own outgoing packet a second time.
#[derive(Clone, Debug)]
pub struct ClientFrame {
    pub payload: Arc<[u8]>,
    pub exclude_client: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ClientSnapshot {
    pub id: u64,
    pub peer: String,
    pub connected_secs: u64,
    pub idle_secs: u64,
    pub rx_frames: u64,
    pub tx_frames: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

struct ClientRecord {
    peer: SocketAddr,
    connected_at: Instant,
    last_rx: Option<Instant>,
    last_tx: Option<Instant>,
    rx_frames: u64,
    tx_frames: u64,
    rx_bytes: u64,
    tx_bytes: u64,
}

/// Shared daemon state. Cheap to clone through an `Arc`.
pub struct AppState {
    pub config: Config,
    pub allow_admin_from: Vec<Cidr>,
    pub blocked_portnums: Vec<i32>,
    pub cache: RwLock<StateCache>,
    /// Frames from the physical node that should reach every client.
    pub broadcast: broadcast::Sender<ClientFrame>,
    /// Every frame from the physical node, before routing (used by provisioning).
    pub physical_frames: broadcast::Sender<Arc<[u8]>>,
    /// Client-to-node queue (bounded, like the original 100-message queue).
    pub to_node: mpsc::Sender<Vec<u8>>,
    /// The current physical node writer, if connected.
    pub writer: Mutex<Option<PhysicalWriter>>,
    /// Debounced "please re-read the node config" signal.
    pub resync: mpsc::Sender<()>,
    pub active_clients: AtomicUsize,
    pub next_client_id: AtomicU64,
    clients: StdMutex<HashMap<u64, ClientRecord>>,
    pub connected: AtomicBool,
    pub shutdown: watch::Sender<bool>,
    mqtt_bridge: OnceLock<Weak<crate::mqtt::MqttBridge>>,
    raw_tunnel: StdMutex<RawTunnelAssembler>,
    started: Instant,
    database: OnceLock<Arc<Database>>,
}

impl AppState {
    pub fn new(
        config: Config,
        shutdown: watch::Sender<bool>,
    ) -> (Arc<Self>, mpsc::Receiver<Vec<u8>>, mpsc::Receiver<()>) {
        let allow_admin_from = config
            .security
            .allow_admin_from
            .iter()
            .filter_map(|entry| {
                let cidr = Cidr::parse(entry);
                if cidr.is_none() {
                    warn!(entry, "ignoring invalid allow_admin_from entry");
                }
                cidr
            })
            .collect();

        let blocked_portnums = config
            .security
            .blocked_portnums
            .iter()
            .filter_map(|name| {
                let portnum = pb::PortNum::from_str_name(name.trim());
                if portnum.is_none() {
                    warn!(name, "ignoring unknown blocked_portnums entry");
                }
                portnum.map(|portnum| portnum as i32)
            })
            .collect();

        let (broadcast, _) = broadcast::channel(256);
        let (physical_frames, _) = broadcast::channel(256);
        let (to_node, to_node_rx) = mpsc::channel(100);
        let (resync, resync_rx) = mpsc::channel(1);

        let state = Arc::new(Self {
            config,
            allow_admin_from,
            blocked_portnums,
            cache: RwLock::new(StateCache::new()),
            broadcast,
            physical_frames,
            to_node,
            writer: Mutex::new(None),
            resync,
            active_clients: AtomicUsize::new(0),
            next_client_id: AtomicU64::new(1),
            clients: StdMutex::new(HashMap::new()),
            connected: AtomicBool::new(false),
            shutdown,
            mqtt_bridge: OnceLock::new(),
            raw_tunnel: StdMutex::new(RawTunnelAssembler::new()),
            started: Instant::now(),
            database: OnceLock::new(),
        });

        (state, to_node_rx, resync_rx)
    }

    pub fn subscribe_shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    /// Register the MQTT bridge once it has been created.
    pub fn set_mqtt_bridge(&self, bridge: &Arc<crate::mqtt::MqttBridge>) {
        let _ = self.mqtt_bridge.set(Arc::downgrade(bridge));
    }

    pub fn mqtt_bridge(&self) -> Option<Arc<crate::mqtt::MqttBridge>> {
        self.mqtt_bridge.get().and_then(Weak::upgrade)
    }

    /// Register the web history database once it has been opened.
    pub fn set_database(&self, database: &Arc<Database>) {
        let _ = self.database.set(Arc::clone(database));
    }

    pub fn database(&self) -> Option<Arc<Database>> {
        self.database.get().cloned()
    }

    /// Reassemble Nexus JRAW chunks into complete raw frames.
    pub fn ingest_raw_tunnel(
        &self,
        packet: &pb::MeshPacket,
        diagnostics: NexusDiagnostics,
    ) -> Option<RawTunnelFrame> {
        let now_ms = self.started.elapsed().as_millis() as u64;
        match self
            .raw_tunnel
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .accept(packet, now_ms, diagnostics)
        {
            AssemblerResult::Complete(frame) => Some(frame),
            _ => None,
        }
    }

    /// Publish a physical-node frame to observers that need raw frames.
    pub fn broadcast_physical(&self, payload: &[u8]) {
        let _ = self.physical_frames.send(Arc::from(payload));
    }

    pub fn client_connected(&self, id: u64, peer: SocketAddr) {
        let mut clients = self
            .clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        clients.insert(
            id,
            ClientRecord {
                peer,
                connected_at: Instant::now(),
                last_rx: None,
                last_tx: None,
                rx_frames: 0,
                tx_frames: 0,
                rx_bytes: 0,
                tx_bytes: 0,
            },
        );
    }

    pub fn client_disconnected(&self, id: u64) {
        self.clients
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&id);
    }

    pub fn client_rx(&self, id: u64, bytes: u64) {
        let mut clients = self
            .clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(client) = clients.get_mut(&id) {
            client.rx_bytes = client.rx_bytes.saturating_add(bytes);
            client.last_rx = Some(Instant::now());
        }
    }

    pub fn client_rx_frame(&self, id: u64) {
        let mut clients = self
            .clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(client) = clients.get_mut(&id) {
            client.rx_frames = client.rx_frames.saturating_add(1);
            client.last_rx = Some(Instant::now());
        }
    }

    pub fn client_tx(&self, id: u64, bytes: u64) {
        let mut clients = self
            .clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(client) = clients.get_mut(&id) {
            client.tx_frames = client.tx_frames.saturating_add(1);
            client.tx_bytes = client.tx_bytes.saturating_add(bytes);
            client.last_tx = Some(Instant::now());
        }
    }

    pub fn client_snapshots(&self) -> Vec<ClientSnapshot> {
        let now = Instant::now();
        let clients = self
            .clients
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut snapshots: Vec<_> = clients
            .iter()
            .map(|(&id, client)| {
                let last_seen = client
                    .last_rx
                    .into_iter()
                    .chain(client.last_tx)
                    .max()
                    .unwrap_or(client.connected_at);
                ClientSnapshot {
                    id,
                    peer: client.peer.to_string(),
                    connected_secs: now.duration_since(client.connected_at).as_secs(),
                    idle_secs: now.duration_since(last_seen).as_secs(),
                    rx_frames: client.rx_frames,
                    tx_frames: client.tx_frames,
                    rx_bytes: client.rx_bytes,
                    tx_bytes: client.tx_bytes,
                }
            })
            .collect();
        snapshots.sort_by_key(|client| client.id);
        snapshots
    }

    pub fn node_num(&self) -> u32 {
        self.cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .my_node_num
    }

    /// Queue one unframed `ToRadio` message for the physical node.
    pub fn queue_to_node(&self, payload: Vec<u8>) -> bool {
        match self.to_node.try_send(payload) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("physical-node queue full; dropping client message");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Broadcast one unframed `FromRadio` message to all clients.
    pub fn broadcast_to_clients(&self, payload: Vec<u8>) {
        let _ = self.broadcast.send(ClientFrame {
            payload: payload.into(),
            exclude_client: None,
        });
    }

    /// Broadcast one unframed `FromRadio` message to every client except `client_id`.
    ///
    /// Used for locally echoed client packets: the sending app already records
    /// its own outbound packet, so sending the echo back would duplicate it.
    pub fn broadcast_to_other_clients(&self, payload: Vec<u8>, client_id: u64) {
        let _ = self.broadcast.send(ClientFrame {
            payload: payload.into(),
            exclude_client: Some(client_id),
        });
    }
}

/// Single writer for the physical link, paced like the original queue.
pub async fn dispatcher(state: Arc<AppState>, mut rx: mpsc::Receiver<Vec<u8>>) {
    let mut shutdown = state.subscribe_shutdown();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            message = rx.recv() => {
                let Some(payload) = message else { break };
                let Ok(frame) = encode_frame(&payload) else {
                    debug!("dropping oversized client payload");
                    continue;
                };

                let mut slot = state.writer.lock().await;
                let Some(writer) = slot.as_mut() else {
                    debug!("physical node not connected; dropping client payload");
                    continue;
                };

                use tokio::io::AsyncWriteExt;
                if let Err(error) = writer.write_all(&frame).await {
                    warn!(%error, "write to physical node failed");
                    *slot = None;
                    state.connected.store(false, Ordering::SeqCst);
                    continue;
                }
                if let Err(error) = writer.flush().await {
                    warn!(%error, "flush to physical node failed");
                    *slot = None;
                    state.connected.store(false, Ordering::SeqCst);
                    continue;
                }
                drop(slot);

                // 10 ms between sends keeps a burst of clients from flooding
                // the firmware's single API session.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
}

/// Debounced config re-read after an admin settings write.
pub async fn resync_worker(state: Arc<AppState>, mut rx: mpsc::Receiver<()>) {
    let mut shutdown = state.subscribe_shutdown();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            request = rx.recv() => {
                if request.is_none() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                while rx.try_recv().is_ok() {}
                crate::physical::send_want_config(&state).await;
            }
        }
    }
}
