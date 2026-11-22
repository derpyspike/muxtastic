//! SQLite history for mesh packets, messages, nodes and Nexus raw frames.
//!
//! Writes arrive on a bounded channel and are applied by a single writer task;
//! HTTP handlers query the same connection through short blocking tasks. The
//! database is a normal SQLite file, so it can be opened with any SQLite client
//! while the daemon is running.

use crate::util::now_unix;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use anyhow::{Context, Result};
use meshtastic::protobufs::{self as pb, from_radio};
use meshtastic::Message as ProstMessage;
use muxtastic_core::channel_crypto::{self, ExtraChannel};
use muxtastic_core::meshcore::MeshCoreKeys;
use muxtastic_core::nexus::NexusDiagnostics;
use muxtastic_core::raw_tunnel::{
    meshcore_payload_name, meshcore_route_name, parse_chunk, parse_meshcore_frame,
    parse_reticulum_frame, reticulum_context_name, reticulum_packet_type_name, MeshCoreInfo,
    RawTunnelFrame, RawTunnelKind,
};
use muxtastic_core::util::hex;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Where a frame entered the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbSource {
    /// Read from the physical node's PhoneAPI stream.
    Physical,
    /// Read from a broker by the read-only web source.
    Mqtt,
    /// Echoed locally from a connected client.
    Client,
}

impl DbSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Physical => "physical",
            Self::Mqtt => "mqtt",
            Self::Client => "client",
        }
    }
}

pub enum DbWrite {
    Frame {
        frame: Box<pb::FromRadio>,
        diagnostics: Option<NexusDiagnostics>,
        source: DbSource,
        receiver: Option<String>,
        /// Channel name known from outside the packet (an MQTT topic or
        /// envelope). Takes precedence over the per-receiver index lookup.
        channel_name: Option<String>,
    },
    Raw(Box<RawTunnelFrame>),
}

pub type DbReceiver = mpsc::Receiver<DbWrite>;

const QUEUE_CAPACITY: usize = 4096;
const BATCH_SIZE: usize = 1024;
/// Read-only connections for HTTP queries. WAL lets them run while the
/// writer holds its own connection, so slow queries never stall ingestion.
const READER_CONNECTIONS: usize = 4;
/// Rows deleted per transaction by the retention cleanup.
const CLEANUP_CHUNK: usize = 5_000;
const STATEMENT_CACHE: usize = 128;
/// Candidate names reported for one ambiguous MeshCore hash.
const MAX_HASH_NAMES: usize = 4;
/// MeshCore ("JenCore") channels are labelled `JC:<name>` next to Meshtastic ones.
const MESHCORE_CHANNEL_PREFIX: &str = "JC:";
/// Newest MeshCore group frames scanned for the chat log.
const MESHCORE_CHAT_SCAN: i64 = 5_000;
/// A bridged Meshtastic copy of a MeshCore message arrives within this time.
const MESHCORE_TWIN_SECS: i64 = 120;
/// Newest frames of one raw feed parsed for the per-feed statistics.
const JRAW_STATS_SCAN: i64 = 50_000;
/// Newest raw frames examined when a filter needs the parsed frame.
const RAW_FILTER_SCAN: i64 = 50_000;

pub struct Database {
    conn: Arc<Mutex<Connection>>,
    /// Empty for in-memory databases, which only exist on one connection.
    readers: Vec<Mutex<Connection>>,
    next_reader: AtomicUsize,
    tx: mpsc::Sender<DbWrite>,
    extra_channels: Vec<ExtraChannel>,
    meshcore: MeshCoreKeys,
    dropped_frames: AtomicU64,
    dropped_raw_frames: AtomicU64,
}

impl Database {
    /// Open (or create) the database and its schema.
    pub fn open(path: &str) -> Result<(Arc<Self>, DbReceiver)> {
        Self::open_with_channels(path, Vec::new())
    }

    /// Open the database with extra channel keys for opaque packet decryption.
    pub fn open_with_channels(
        path: &str,
        extra_channels: Vec<ExtraChannel>,
    ) -> Result<(Arc<Self>, DbReceiver)> {
        Self::open_with_keys(path, extra_channels, MeshCoreKeys::default())
    }

    /// Open the database with Meshtastic extra channels and MeshCore keys.
    pub fn open_with_keys(
        path: &str,
        extra_channels: Vec<ExtraChannel>,
        meshcore: MeshCoreKeys,
    ) -> Result<(Arc<Self>, DbReceiver)> {
        let path = path.trim();
        let path = if path.is_empty() { ":memory:" } else { path };
        if path != ":memory:" {
            if let Some(parent) = Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).with_context(|| {
                        format!("failed to create database directory {}", parent.display())
                    })?;
                }
            }
        }

        let connection = Connection::open(path)
            .with_context(|| format!("failed to open SQLite database {path}"))?;
        init_schema(&connection)?;
        connection.set_prepared_statement_cache_capacity(STATEMENT_CACHE);

        let mut readers = Vec::new();
        if path != ":memory:" {
            for _ in 0..READER_CONNECTIONS {
                let reader = Connection::open_with_flags(
                    path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )
                .with_context(|| format!("failed to open SQLite database {path} for reading"))?;
                reader.execute_batch("PRAGMA busy_timeout=5000; PRAGMA query_only=ON;")?;
                reader.set_prepared_statement_cache_capacity(STATEMENT_CACHE);
                readers.push(Mutex::new(reader));
            }
        }

        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        Ok((
            Arc::new(Self {
                conn: Arc::new(Mutex::new(connection)),
                readers,
                next_reader: AtomicUsize::new(0),
                tx,
                extra_channels,
                meshcore,
                dropped_frames: AtomicU64::new(0),
                dropped_raw_frames: AtomicU64::new(0),
            }),
            rx,
        ))
    }

    pub fn record_frame(
        &self,
        frame: pb::FromRadio,
        diagnostics: Option<NexusDiagnostics>,
        source: DbSource,
        receiver: Option<String>,
    ) {
        self.record_frame_on_channel(frame, diagnostics, source, receiver, None);
    }

    /// Like [`Self::record_frame`], for callers that already know the channel
    /// name (the MQTT source reads it from the topic or envelope).
    pub fn record_frame_on_channel(
        &self,
        frame: pb::FromRadio,
        diagnostics: Option<NexusDiagnostics>,
        source: DbSource,
        receiver: Option<String>,
        channel_name: Option<String>,
    ) {
        if self
            .tx
            .try_send(DbWrite::Frame {
                frame: Box::new(frame),
                diagnostics,
                source,
                receiver,
                channel_name,
            })
            .is_err()
        {
            self.note_drop(&self.dropped_frames, "frame");
        }
    }

    pub fn record_raw_frame(&self, frame: RawTunnelFrame) {
        if self.tx.try_send(DbWrite::Raw(Box::new(frame))).is_err() {
            self.note_drop(&self.dropped_raw_frames, "raw frame");
        }
    }

    fn note_drop(&self, counter: &AtomicU64, kind: &str) {
        let dropped = counter.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped == 1 || dropped.is_multiple_of(1000) {
            warn!(dropped, kind, "web database queue full; dropping writes");
        }
    }

    /// A connection for read queries: an idle reader when there is one,
    /// otherwise wait for the next in round-robin order.
    fn reader(&self) -> MutexGuard<'_, Connection> {
        if self.readers.is_empty() {
            return self.conn.lock().unwrap_or_else(|error| error.into_inner());
        }
        for reader in &self.readers {
            match reader.try_lock() {
                Ok(guard) => return guard,
                Err(std::sync::TryLockError::Poisoned(error)) => return error.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {}
            }
        }
        let index = self.next_reader.fetch_add(1, Ordering::Relaxed) % self.readers.len();
        self.readers[index]
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    #[cfg(test)]
    fn apply(&self, write: DbWrite) -> Result<()> {
        let connection = self.conn.lock().unwrap_or_else(|error| error.into_inner());
        apply_write(&connection, write, &self.extra_channels, now_unix())
    }

    fn apply_batch(&self, writes: Vec<DbWrite>) -> Result<()> {
        let mut connection = self.conn.lock().unwrap_or_else(|error| error.into_inner());
        let transaction = connection.transaction()?;
        for write in writes {
            if let Err(error) = apply_write(&transaction, write, &self.extra_channels, now_unix()) {
                warn!(%error, "web database write failed");
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn query_stats(&self) -> Result<Stats> {
        let connection = self.reader();
        stats(&connection)
    }

    /// Text messages, newest first. Meshtastic messages come from the
    /// `messages` table; MeshCore group messages are decrypted from the stored
    /// frames and appear on `JC:<channel>` channels.
    ///
    /// A node may also bridge MeshCore chat into Meshtastic channels of the
    /// same `JC:` name. A decrypted message with such a twin (same channel and
    /// text, received within [`MESHCORE_TWIN_SECS`]) is not listed again.
    pub fn query_messages(&self, channel: Option<&str>, limit: usize) -> Result<Vec<Message>> {
        let connection = self.reader();
        let mut out = messages(&connection, channel, limit)?;
        if channel.is_none_or(|name| name.starts_with(MESHCORE_CHANNEL_PREFIX)) {
            // (channel, text) -> indexes of the bridged Meshtastic messages.
            let mut bridged: HashMap<(String, String), Vec<usize>> = HashMap::new();
            for (index, message) in out.iter().enumerate() {
                if message.channel_name.starts_with(MESHCORE_CHANNEL_PREFIX) {
                    bridged
                        .entry((message.channel_name.clone(), message.text.clone()))
                        .or_default()
                        .push(index);
                }
            }
            for mut message in meshcore_messages(&connection, &self.meshcore, channel)? {
                let twin = bridged
                    .get(&(message.channel_name.clone(), message.text.clone()))
                    .and_then(|indexes| {
                        indexes.iter().copied().find(|index| {
                            (out[*index].received_at - message.received_at).abs()
                                <= MESHCORE_TWIN_SECS
                        })
                    });
                match twin {
                    // The bridged copy stays; it gains the paths the MeshCore
                    // frames took, which the bridge does not carry.
                    Some(index) => out[index]
                        .meshcore_receptions
                        .append(&mut message.meshcore_receptions),
                    None => out.push(message),
                }
            }
            out.sort_by_key(|message| std::cmp::Reverse(message.received_at));
            out.truncate(limit.clamp(1, 1000));
        }
        Ok(out)
    }

    /// Activity summary of one raw feed: 1 = MeshCore, 2 = Reticulum.
    pub fn query_jraw_stats(&self, kind: i64) -> Result<JrawStats> {
        let connection = self.reader();
        jraw_stats(&connection, kind, &self.meshcore, now_unix())
    }

    pub fn query_nodes(&self) -> Result<Vec<Node>> {
        let connection = self.reader();
        nodes(&connection)
    }

    pub fn query_node_names(&self) -> Result<Vec<NodeName>> {
        let connection = self.reader();
        node_names(&connection)
    }

    pub fn query_raw_frames(&self, kind: Option<i64>, limit: usize) -> Result<Vec<RawFrame>> {
        let filter = RawFilter {
            kind,
            ..RawFilter::default()
        };
        self.query_raw_frames_filtered(&filter, limit)
    }

    pub fn query_raw_frames_filtered(
        &self,
        filter: &RawFilter,
        limit: usize,
    ) -> Result<Vec<RawFrame>> {
        let connection = self.reader();
        raw_frames(&connection, filter, limit, &self.meshcore)
    }

    /// What the raw frames of one feed can be filtered by, with frame counts.
    pub fn query_raw_filters(&self, kind: i64) -> Result<RawFilterOptions> {
        let connection = self.reader();
        raw_filter_options(&connection, kind, &self.meshcore)
    }

    /// Names (never keys) of the MeshCore channels and regions in use.
    pub fn meshcore_keys(&self) -> &MeshCoreKeys {
        &self.meshcore
    }

    pub fn query_channels(&self) -> Result<Vec<ChannelInfo>> {
        let connection = self.reader();
        let mut out = channels(&connection)?;
        // MeshCore channels we hold a key for, unless a Meshtastic channel of
        // that name is already listed; -1 marks them as not Meshtastic.
        for channel in self.meshcore.channels() {
            let name = meshcore_channel_label(&channel.name);
            if !out.iter().any(|known| known.key == name || known.name == name) {
                out.push(ChannelInfo {
                    channel: -1,
                    name: name.clone(),
                    role: 0,
                    key: name,
                });
            }
        }
        Ok(out)
    }

    pub fn query_node(&self, num: i64) -> Result<Option<Node>> {
        let connection = self.reader();
        node(&connection, num)
    }

    pub fn query_node_packets(&self, num: i64, limit: usize) -> Result<Vec<PacketRow>> {
        let connection = self.reader();
        node_packets(&connection, num, limit)
    }

    pub fn query_direct_nodes(&self, receiver: &str, limit: usize) -> Result<Vec<DirectNode>> {
        let connection = self.reader();
        direct_nodes(&connection, receiver, limit)
    }

    pub fn query_mqtt_gateways(&self, limit: usize) -> Result<Vec<MqttGateway>> {
        let connection = self.reader();
        mqtt_gateways(&connection, limit)
    }

    pub fn query_packets(&self, filter: &PacketFilter) -> Result<Vec<PacketListEntry>> {
        let connection = self.reader();
        packet_list(&connection, filter)
    }

    pub fn query_packet_filters(&self) -> Result<PacketFilterOptions> {
        let connection = self.reader();
        packet_filters(&connection)
    }

    pub fn query_jraw_nodes(&self, kind: Option<i64>, limit: usize) -> Result<Vec<JrawNode>> {
        let connection = self.reader();
        jraw_nodes(&connection, kind, limit)
    }

    /// Delete packet-derived history older than `days`; nodes/channels are kept.
    ///
    /// Rows go in small transactions so the writer and the HTTP queries are
    /// never blocked for long, even when a lot of history expires at once.
    pub fn cleanup_older_than(&self, days: u64) -> Result<usize> {
        if days == 0 {
            return Ok(0);
        }
        let seconds = days.saturating_mul(86_400).min(i64::MAX as u64) as i64;
        let cutoff = now_unix().saturating_sub(seconds);
        let mut removed = 0;
        let mut receptions_removed = false;
        for table in [
            "messages",
            "packet_receptions",
            "traceroutes",
            "raw_frames",
            "packets",
        ] {
            let sql = format!(
                "DELETE FROM {table} WHERE id IN
                 (SELECT id FROM {table} WHERE received_at < ?1 LIMIT ?2)"
            );
            loop {
                let deleted = {
                    let connection = self.conn.lock().unwrap_or_else(|error| error.into_inner());
                    execute_cached(&connection, &sql, params![cutoff, CLEANUP_CHUNK as i64])?
                };
                removed += deleted;
                receptions_removed |= deleted > 0 && table == "packet_receptions";
                if deleted < CLEANUP_CHUNK {
                    break;
                }
            }
        }
        if removed > 0 {
            let mut connection = self.conn.lock().unwrap_or_else(|error| error.into_inner());
            if receptions_removed {
                let transaction = connection.transaction()?;
                rebuild_reception_summary(&transaction)?;
                transaction.commit()?;
            }
            // Only effective on files in incremental auto-vacuum mode.
            if let Err(error) = connection.execute_batch("PRAGMA incremental_vacuum;") {
                warn!(%error, "could not release free database pages");
            }
        }
        Ok(removed)
    }

    pub fn query_traceroutes(&self, limit: usize) -> Result<Vec<Traceroute>> {
        let connection = self.reader();
        traceroutes(&connection, limit)
    }

    pub fn query_receptions(&self, from_num: i64, packet_id: i64) -> Result<Vec<Reception>> {
        let connection = self.reader();
        receptions(&connection, from_num, packet_id)
    }

    pub fn query_recent_receptions(&self, limit: usize) -> Result<Vec<Reception>> {
        let connection = self.reader();
        recent_receptions(&connection, limit)
    }

    pub fn query_node_receptions(&self, from_num: i64, limit: usize) -> Result<Vec<Reception>> {
        let connection = self.reader();
        node_receptions(&connection, from_num, limit)
    }

    pub fn query_relay_stats(&self, receiver: &str, limit: usize) -> Result<Vec<RelayStats>> {
        let connection = self.reader();
        relay_stats(&connection, receiver, limit)
    }

    pub fn query_relay_series(&self, receiver: &str, limit: usize) -> Result<Vec<RelaySample>> {
        let connection = self.reader();
        relay_series(&connection, receiver, limit)
    }
}

/// Single blocking writer; keeps SQLite work off the async runtime threads.
pub async fn run_writer(db: Weak<Database>, mut rx: DbReceiver) {
    let result = tokio::task::spawn_blocking(move || {
        while let Some(write) = rx.blocking_recv() {
            let Some(db) = db.upgrade() else {
                break;
            };
            let mut writes = Vec::with_capacity(BATCH_SIZE);
            writes.push(write);
            while writes.len() < BATCH_SIZE {
                match rx.try_recv() {
                    Ok(write) => writes.push(write),
                    Err(_) => break,
                }
            }
            if let Err(error) = db.apply_batch(writes) {
                warn!(%error, "web database batch failed");
            }
        }
    })
    .await;
    if let Err(error) = result {
        warn!(%error, "web database writer task failed");
    }
}

fn apply_write(
    connection: &Connection,
    write: DbWrite,
    extra_channels: &[ExtraChannel],
    now: i64,
) -> Result<()> {
    match write {
        DbWrite::Frame {
            frame,
            diagnostics,
            source,
            receiver,
            channel_name,
        } => apply_frame(
            connection,
            &frame,
            diagnostics,
            source,
            receiver.as_deref(),
            channel_name.as_deref().filter(|name| !name.is_empty()),
            extra_channels,
            now,
        ),
        DbWrite::Raw(frame) => apply_raw(connection, &frame, now),
    }
}

fn init_schema(connection: &Connection) -> Result<()> {
    connection
        .execute_batch(
            r#"
PRAGMA auto_vacuum=INCREMENTAL;
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;
PRAGMA journal_size_limit=67108864;

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id INTEGER NOT NULL,
    from_num INTEGER NOT NULL,
    to_num INTEGER NOT NULL,
    relay_node INTEGER NOT NULL DEFAULT 0,
    channel INTEGER NOT NULL,
    channel_name TEXT NOT NULL DEFAULT '',
    decrypted INTEGER NOT NULL DEFAULT 0,
    portnum INTEGER,
    bytes INTEGER NOT NULL DEFAULT 0,
    transport INTEGER NOT NULL,
    via_mqtt INTEGER NOT NULL,
    source TEXT NOT NULL DEFAULT 'physical',
    reception_count INTEGER NOT NULL DEFAULT 0,
    gateway_count INTEGER NOT NULL DEFAULT 0,
    best_snr REAL,
    best_rssi INTEGER,
    rx_time INTEGER NOT NULL,
    rx_snr REAL,
    rx_rssi INTEGER,
    rx_frequency_error REAL,
    rx_coding_rate INTEGER,
    hop_limit INTEGER,
    hop_start INTEGER,
    received_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_packets_received_at ON packets(received_at);
CREATE INDEX IF NOT EXISTS idx_packets_channel ON packets(channel);
CREATE INDEX IF NOT EXISTS idx_packets_from ON packets(from_num);
CREATE INDEX IF NOT EXISTS idx_packets_channel_from ON packets(channel, from_num);

CREATE TABLE IF NOT EXISTS packet_receptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id INTEGER NOT NULL,
    from_num INTEGER NOT NULL,
    to_num INTEGER NOT NULL,
    relay_node INTEGER NOT NULL DEFAULT 0,
    channel INTEGER NOT NULL,
    channel_name TEXT NOT NULL DEFAULT '',
    decrypted INTEGER NOT NULL DEFAULT 0,
    receiver TEXT NOT NULL,
    source TEXT NOT NULL,
    via_mqtt INTEGER NOT NULL,
    rx_time INTEGER NOT NULL,
    rx_snr REAL,
    rx_rssi INTEGER,
    rx_frequency_error REAL,
    rx_coding_rate INTEGER,
    hop_limit INTEGER,
    hop_start INTEGER,
    received_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_receptions_packet_receiver
    ON packet_receptions(from_num, packet_id, receiver) WHERE packet_id > 0;
CREATE INDEX IF NOT EXISTS idx_receptions_packet
    ON packet_receptions(from_num, packet_id);
CREATE INDEX IF NOT EXISTS idx_receptions_received_at
    ON packet_receptions(received_at);
CREATE INDEX IF NOT EXISTS idx_receptions_receiver
    ON packet_receptions(receiver);
CREATE INDEX IF NOT EXISTS idx_receptions_receiver_time
    ON packet_receptions(receiver, received_at, id);

-- One row per (sender, receiver, source): keeps gateway lists and per-gateway
-- totals cheap without scanning packet_receptions.
CREATE TABLE IF NOT EXISTS reception_summary (
    from_num INTEGER NOT NULL,
    receiver TEXT NOT NULL,
    source TEXT NOT NULL,
    receptions INTEGER NOT NULL DEFAULT 0,
    last_heard INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (from_num, receiver, source)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_reception_summary_receiver
    ON reception_summary(receiver, source);

CREATE TABLE IF NOT EXISTS traceroutes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id INTEGER NOT NULL,
    from_num INTEGER NOT NULL,
    to_num INTEGER NOT NULL,
    channel INTEGER NOT NULL,
    request_id INTEGER NOT NULL DEFAULT 0,
    rx_time INTEGER NOT NULL,
    route TEXT NOT NULL,
    snr_towards TEXT NOT NULL,
    route_back TEXT NOT NULL,
    snr_back TEXT NOT NULL,
    source TEXT NOT NULL,
    receiver TEXT,
    decrypted INTEGER NOT NULL DEFAULT 0,
    received_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_traceroutes_packet
    ON traceroutes(from_num, packet_id) WHERE packet_id > 0;
CREATE INDEX IF NOT EXISTS idx_traceroutes_received_at
    ON traceroutes(received_at);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id INTEGER NOT NULL,
    from_num INTEGER NOT NULL,
    to_num INTEGER NOT NULL,
    channel INTEGER NOT NULL,
    channel_name TEXT NOT NULL DEFAULT '',
    decrypted INTEGER NOT NULL DEFAULT 0,
    text TEXT NOT NULL,
    rx_time INTEGER NOT NULL,
    rx_snr REAL,
    rx_rssi INTEGER,
    rx_frequency_error REAL,
    rx_coding_rate INTEGER,
    hop_limit INTEGER,
    hop_start INTEGER,
    via_mqtt INTEGER NOT NULL,
    source TEXT NOT NULL DEFAULT 'physical',
    received_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_packet
    ON messages(from_num, packet_id) WHERE packet_id > 0;
CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel);
CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at);

CREATE TABLE IF NOT EXISTS nodes (
    num INTEGER PRIMARY KEY,
    node_id TEXT,
    long_name TEXT,
    short_name TEXT,
    hw_model INTEGER,
    role INTEGER,
    last_heard INTEGER NOT NULL DEFAULT 0,
    snr REAL,
    hops_away INTEGER,
    via_mqtt INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT 'physical',
    battery_level INTEGER,
    voltage REAL,
    channel_utilization REAL,
    air_util_tx REAL,
    latitude_i INTEGER,
    longitude_i INTEGER,
    altitude INTEGER,
    public_key BLOB,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nodes_last_heard ON nodes(last_heard);
CREATE INDEX IF NOT EXISTS idx_nodes_node_id ON nodes(node_id);

CREATE TABLE IF NOT EXISTS channels (
    idx INTEGER PRIMARY KEY,
    name TEXT,
    role INTEGER,
    uplink INTEGER NOT NULL DEFAULT 0,
    downlink INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS node_channels (
    receiver TEXT NOT NULL,
    idx INTEGER NOT NULL,
    name TEXT,
    role INTEGER,
    uplink INTEGER NOT NULL DEFAULT 0,
    downlink INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (receiver, idx)
);
CREATE INDEX IF NOT EXISTS idx_node_channels_receiver ON node_channels(receiver);

CREATE TABLE IF NOT EXISTS raw_frames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind INTEGER NOT NULL,
    source TEXT NOT NULL DEFAULT 'physical',
    decrypted INTEGER NOT NULL DEFAULT 0,
    gateway INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    channel INTEGER NOT NULL,
    rx_time INTEGER NOT NULL,
    rx_rssi INTEGER,
    rx_snr REAL,
    frequency_error REAL,
    coding_rate INTEGER,
    frame BLOB NOT NULL,
    frame_len INTEGER NOT NULL,
    route_type INTEGER,
    payload_type INTEGER,
    route_name TEXT,
    payload_name TEXT,
    path_hex TEXT,
    sender_hash TEXT,
    destination_hash TEXT,
    channel_hash INTEGER,
    node_name TEXT,
    public_key BLOB,
    received_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_raw_received_at ON raw_frames(received_at);
CREATE INDEX IF NOT EXISTS idx_raw_kind ON raw_frames(kind);
CREATE INDEX IF NOT EXISTS idx_raw_kind_sender ON raw_frames(kind, sender_hash, received_at);
CREATE INDEX IF NOT EXISTS idx_raw_kind_destination ON raw_frames(kind, destination_hash, received_at);

CREATE TABLE IF NOT EXISTS jraw_nodes (
    kind INTEGER NOT NULL,
    node_hash TEXT NOT NULL,
    name TEXT,
    public_key BLOB,
    node_type INTEGER,
    first_heard INTEGER NOT NULL,
    last_heard INTEGER NOT NULL,
    frames INTEGER NOT NULL DEFAULT 0,
    last_gateway INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (kind, node_hash)
);
CREATE INDEX IF NOT EXISTS idx_jraw_nodes_last_heard ON jraw_nodes(last_heard);
"#,
        )
        .context("failed to initialise the SQLite schema")?;

    // Version 1 databases predate the Nexus diagnostics columns.
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 2 {
        ensure_column(connection, "packets", "rx_frequency_error", "REAL")?;
        ensure_column(connection, "packets", "rx_coding_rate", "INTEGER")?;
        ensure_column(connection, "messages", "rx_frequency_error", "REAL")?;
        ensure_column(connection, "messages", "rx_coding_rate", "INTEGER")?;
        ensure_column(connection, "raw_frames", "frequency_error", "REAL")?;
        ensure_column(connection, "raw_frames", "coding_rate", "INTEGER")?;
        connection.execute_batch("PRAGMA user_version = 2;")?;
    }

    // Version 3 records where each row came from and deduplicates packets.
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 3 {
        ensure_column(
            connection,
            "packets",
            "source",
            "TEXT NOT NULL DEFAULT 'physical'",
        )?;
        ensure_column(
            connection,
            "messages",
            "source",
            "TEXT NOT NULL DEFAULT 'physical'",
        )?;
        ensure_column(
            connection,
            "nodes",
            "source",
            "TEXT NOT NULL DEFAULT 'physical'",
        )?;
        ensure_column(
            connection,
            "raw_frames",
            "source",
            "TEXT NOT NULL DEFAULT 'physical'",
        )?;
        connection.execute_batch(
            r#"
DELETE FROM packets
WHERE packet_id > 0
  AND id NOT IN (
      SELECT MIN(id) FROM packets WHERE packet_id > 0
      GROUP BY from_num, packet_id
  );
CREATE UNIQUE INDEX IF NOT EXISTS idx_packets_packet
    ON packets(from_num, packet_id) WHERE packet_id > 0;
PRAGMA user_version = 3;
"#,
        )?;
    }

    // Version 4 keeps one row per receiver/gateway that heard a packet.
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 4 {
        ensure_column(
            connection,
            "packets",
            "reception_count",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            connection,
            "packets",
            "gateway_count",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(connection, "packets", "best_snr", "REAL")?;
        ensure_column(connection, "packets", "best_rssi", "INTEGER")?;
        connection.execute_batch("PRAGMA user_version = 4;")?;
    }

    // Version 5 records payload bytes for channel/rate statistics.
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 5 {
        ensure_column(connection, "packets", "bytes", "INTEGER NOT NULL DEFAULT 0")?;
        connection.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_packets_channel_from
                 ON packets(channel, from_num);
             PRAGMA user_version = 5;",
        )?;
    }

    // Version 6 records the relay node from the packet header.
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 6 {
        ensure_column(
            connection,
            "packets",
            "relay_node",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            connection,
            "packet_receptions",
            "relay_node",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        connection.execute_batch("PRAGMA user_version = 6;")?;
    }

    // Version 7 stores traceroute responses, including the back route.
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 7 {
        connection.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS traceroutes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id INTEGER NOT NULL,
    from_num INTEGER NOT NULL,
    to_num INTEGER NOT NULL,
    channel INTEGER NOT NULL,
    request_id INTEGER NOT NULL DEFAULT 0,
    rx_time INTEGER NOT NULL,
    route TEXT NOT NULL,
    snr_towards TEXT NOT NULL,
    route_back TEXT NOT NULL,
    snr_back TEXT NOT NULL,
    source TEXT NOT NULL,
    receiver TEXT,
    received_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_traceroutes_packet
    ON traceroutes(from_num, packet_id) WHERE packet_id > 0;
CREATE INDEX IF NOT EXISTS idx_traceroutes_received_at
    ON traceroutes(received_at);
PRAGMA user_version = 7;
"#,
        )?;
    }

    // Version 8 separates configured channel indexes from opaque channel hashes.
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 8 {
        connection.execute_batch(
            r#"
UPDATE packets SET channel = 512
WHERE portnum IS NULL AND channel = 0 AND to_num <> 4294967295;
UPDATE packets SET channel = channel + 256
WHERE portnum IS NULL AND channel < 256;
UPDATE packet_receptions SET channel = 512
WHERE EXISTS (
    SELECT 1 FROM packets p
    WHERE p.from_num = packet_receptions.from_num
      AND p.packet_id = packet_receptions.packet_id
      AND p.channel = 512
);
UPDATE packet_receptions SET channel = channel + 256
WHERE channel < 256 AND EXISTS (
    SELECT 1 FROM packets p
    WHERE p.from_num = packet_receptions.from_num
      AND p.packet_id = packet_receptions.packet_id
      AND p.channel >= 256 AND p.channel < 512
);
PRAGMA user_version = 8;
"#,
        )?;
    }

    // Version 9 keeps channel indexes scoped to the receiving node.
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 9 {
        connection.execute_batch("PRAGMA user_version = 9;")?;
    }

    // Version 10 stores the resolved channel name on each packet/message/reception.
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 10 {
        ensure_column(
            connection,
            "packets",
            "channel_name",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_column(
            connection,
            "messages",
            "channel_name",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_column(
            connection,
            "packet_receptions",
            "channel_name",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        connection.execute_batch(
            r#"
UPDATE packet_receptions
SET channel_name = COALESCE(
    (SELECT NULLIF(nc.name, '') FROM node_channels nc
     WHERE nc.receiver = packet_receptions.receiver
       AND nc.idx = packet_receptions.channel),
    '')
WHERE channel_name = '';

UPDATE packets
SET channel_name = COALESCE(
    (SELECT nc.name FROM packet_receptions r
     JOIN node_channels nc
       ON nc.receiver = r.receiver AND nc.idx = r.channel
     WHERE r.from_num = packets.from_num
       AND r.packet_id = packets.packet_id
       AND r.channel = packets.channel
       AND nc.name IS NOT NULL AND nc.name <> ''
     ORDER BY COALESCE(r.rx_snr, -9999) DESC, r.id LIMIT 1),
    '')
WHERE channel_name = '';

UPDATE messages
SET channel_name = COALESCE(
    (SELECT nc.name FROM packet_receptions r
     JOIN node_channels nc
       ON nc.receiver = r.receiver AND nc.idx = r.channel
     WHERE r.from_num = messages.from_num
       AND r.packet_id = messages.packet_id
       AND r.channel = messages.channel
       AND nc.name IS NOT NULL AND nc.name <> ''
     ORDER BY COALESCE(r.rx_snr, -9999) DESC, r.id LIMIT 1),
    '')
WHERE channel_name = '';
CREATE INDEX IF NOT EXISTS idx_packets_channel_name ON packets(channel_name);
CREATE INDEX IF NOT EXISTS idx_packets_from_received ON packets(from_num, received_at, id);
CREATE INDEX IF NOT EXISTS idx_packets_channel_name_from ON packets(channel_name, from_num);
PRAGMA user_version = 10;
"#,
        )?;
    }

    // Version 11 marks packets decoded with an extra channel key.
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 11 {
        ensure_column(
            connection,
            "packets",
            "decrypted",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            connection,
            "messages",
            "decrypted",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            connection,
            "packet_receptions",
            "decrypted",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            connection,
            "traceroutes",
            "decrypted",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            connection,
            "raw_frames",
            "decrypted",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        connection.execute_batch("PRAGMA user_version = 11;")?;
    }

    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 12 {
        connection.execute_batch(
            r#"
CREATE INDEX IF NOT EXISTS idx_raw_kind_sender
    ON raw_frames(kind, sender_hash, received_at);
CREATE INDEX IF NOT EXISTS idx_raw_kind_destination
    ON raw_frames(kind, destination_hash, received_at);
DROP INDEX IF EXISTS idx_receptions_packet_receiver;
CREATE INDEX IF NOT EXISTS idx_receptions_packet_receiver
    ON packet_receptions(from_num, packet_id, receiver) WHERE packet_id > 0;

CREATE TABLE IF NOT EXISTS jraw_nodes (
    kind INTEGER NOT NULL,
    node_hash TEXT NOT NULL,
    name TEXT,
    public_key BLOB,
    node_type INTEGER,
    first_heard INTEGER NOT NULL,
    last_heard INTEGER NOT NULL,
    frames INTEGER NOT NULL DEFAULT 0,
    last_gateway INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (kind, node_hash)
);
CREATE INDEX IF NOT EXISTS idx_jraw_nodes_last_heard ON jraw_nodes(last_heard);

INSERT OR IGNORE INTO jraw_nodes
    (kind, node_hash, first_heard, last_heard, frames, last_gateway)
SELECT kind, sender_hash, MIN(received_at), MAX(received_at), COUNT(*), MAX(gateway)
FROM raw_frames
WHERE kind = 1 AND sender_hash IS NOT NULL AND sender_hash <> ''
GROUP BY sender_hash;

UPDATE jraw_nodes SET
    name = COALESCE(
        (SELECT r.node_name FROM raw_frames r
         WHERE r.kind = jraw_nodes.kind AND r.sender_hash = jraw_nodes.node_hash
           AND r.node_name IS NOT NULL
         ORDER BY r.received_at DESC LIMIT 1),
        name),
    public_key = COALESCE(
        (SELECT r.public_key FROM raw_frames r
         WHERE r.kind = jraw_nodes.kind AND r.sender_hash = jraw_nodes.node_hash
           AND r.public_key IS NOT NULL
         ORDER BY r.received_at DESC LIMIT 1),
        public_key)
WHERE kind = 1;

INSERT OR IGNORE INTO jraw_nodes
    (kind, node_hash, first_heard, last_heard, frames, last_gateway)
SELECT kind, destination_hash, MIN(received_at), MAX(received_at), COUNT(*), MAX(gateway)
FROM raw_frames
WHERE kind = 2 AND destination_hash IS NOT NULL AND destination_hash <> ''
GROUP BY destination_hash;
PRAGMA user_version = 12;
"#,
        )?;
    }

    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 13 {
        connection.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_nodes_node_id ON nodes(node_id);
             CREATE INDEX IF NOT EXISTS idx_packets_from_received
                 ON packets(from_num, received_at, id);
             CREATE INDEX IF NOT EXISTS idx_packets_channel_name_from
                 ON packets(channel_name, from_num);
             PRAGMA user_version = 13;",
        )?;
    }

    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 14 {
        connection.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_receptions_receiver_time
                 ON packet_receptions(receiver, received_at, id);
             PRAGMA user_version = 14;",
        )?;
    }

    // Version 15 removes replayed duplicates, adds the reception summary and
    // clears positions that were stored as 0°, 0° for packets without a fix.
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 15 {
        migrate_v15(connection)?;
    }

    // Version 16 keeps the position MeshCore nodes advertise.
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 16 {
        migrate_v16(connection)?;
    }
    Ok(())
}

fn migrate_v16(connection: &Connection) -> Result<()> {
    ensure_column(connection, "jraw_nodes", "latitude", "REAL")?;
    ensure_column(connection, "jraw_nodes", "longitude", "REAL")?;

    // Advertised MeshCore nodes used to be keyed by their short path hash, so
    // nodes sharing it overwrote each other. Re-key them by full public key.
    let transaction = connection.unchecked_transaction()?;
    {
        #[allow(clippy::type_complexity)]
        let keyed: Vec<(Option<String>, Vec<u8>, Option<i64>, i64, i64, i64, i64)> = {
            let mut statement = transaction.prepare(
                "SELECT name, public_key, node_type, first_heard, last_heard, frames, last_gateway
                 FROM jraw_nodes
                 WHERE kind = 1 AND public_key IS NOT NULL AND length(public_key) = 32
                 ORDER BY last_heard",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            })?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        transaction.execute(
            "DELETE FROM jraw_nodes WHERE kind = 1 AND public_key IS NOT NULL",
            [],
        )?;
        let mut merge = transaction.prepare(
            "INSERT INTO jraw_nodes
             (kind, node_hash, name, public_key, node_type, first_heard, last_heard,
              frames, last_gateway)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(kind, node_hash) DO UPDATE SET
                name = COALESCE(excluded.name, jraw_nodes.name),
                node_type = COALESCE(excluded.node_type, jraw_nodes.node_type),
                first_heard = MIN(jraw_nodes.first_heard, excluded.first_heard),
                last_heard = MAX(jraw_nodes.last_heard, excluded.last_heard),
                frames = jraw_nodes.frames + excluded.frames,
                last_gateway = excluded.last_gateway",
        )?;
        for (name, key, node_type, first_heard, last_heard, frames, gateway) in keyed {
            merge.execute(params![
                hex(&key),
                name,
                key,
                node_type,
                first_heard,
                last_heard,
                frames,
                gateway
            ])?;
        }

        // Replay the stored adverts, oldest first: this restores nodes that a
        // collision had overwritten and fills in the advertised positions.
        let mut adverts = transaction.prepare(
            "SELECT frame, gateway, received_at FROM raw_frames
             WHERE kind = 1 AND payload_type = 4 ORDER BY id",
        )?;
        let mut replay = transaction.prepare(
            "INSERT INTO jraw_nodes
             (kind, node_hash, name, public_key, node_type, first_heard, last_heard,
              frames, last_gateway, latitude, longitude)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?5, 1, ?6, ?7, ?8)
             ON CONFLICT(kind, node_hash) DO UPDATE SET
                name = COALESCE(excluded.name, jraw_nodes.name),
                node_type = COALESCE(excluded.node_type, jraw_nodes.node_type),
                latitude = COALESCE(excluded.latitude, jraw_nodes.latitude),
                longitude = COALESCE(excluded.longitude, jraw_nodes.longitude),
                first_heard = MIN(jraw_nodes.first_heard, excluded.first_heard),
                last_heard = MAX(jraw_nodes.last_heard, excluded.last_heard)",
        )?;
        let mut rows = adverts.query([])?;
        while let Some(row) = rows.next()? {
            let frame: Vec<u8> = row.get(0)?;
            let Some(info) = parse_meshcore_frame(&frame) else {
                continue;
            };
            let Some(key) = info.public_key.as_deref() else {
                continue;
            };
            let position = advert_degrees(&info);
            replay.execute(params![
                hex(key),
                info.node_name,
                key,
                info.node_type.map(i64::from),
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(1)?,
                position.map(|(latitude, _)| latitude),
                position.map(|(_, longitude)| longitude),
            ])?;
        }
    }
    transaction.execute_batch("PRAGMA user_version = 16;")?;
    transaction.commit()?;
    Ok(())
}

/// The position a MeshCore advert carries, in degrees. `None` when the advert
/// has no position or the node left it unset (0, 0).
fn advert_degrees(info: &MeshCoreInfo) -> Option<(f64, f64)> {
    let (latitude, longitude) = info.advert_position?;
    if latitude == 0 && longitude == 0 {
        return None;
    }
    Some((f64::from(latitude) / 1e6, f64::from(longitude) / 1e6))
}

fn migrate_v15(connection: &Connection) -> Result<()> {
    let receptions: i64 =
        connection.query_row("SELECT COUNT(*) FROM packet_receptions", [], |row| {
            row.get(0)
        })?;
    if receptions > 100_000 {
        info!(
            receptions,
            "upgrading the web database (removing duplicate receptions); this can take a few minutes"
        );
    }
    connection.execute_batch(
        r#"
BEGIN IMMEDIATE;

-- Byte-identical receptions are broker redeliveries or MQTT loop copies.
DELETE FROM packet_receptions
WHERE packet_id > 0
  AND id NOT IN (
      SELECT MIN(id) FROM packet_receptions
      WHERE packet_id > 0
      GROUP BY from_num, packet_id, receiver, relay_node, hop_limit,
               rx_time, rx_snr, rx_rssi
  );

-- The Meshtastic raw feed stored one copy of the packet per reception.
DELETE FROM raw_frames
WHERE kind = 3
  AND id NOT IN (
      SELECT MIN(id) FROM raw_frames WHERE kind = 3
      GROUP BY source, gateway, frame
  );

UPDATE packets SET
    reception_count = (SELECT COUNT(*) FROM packet_receptions r
                       WHERE r.from_num = packets.from_num
                         AND r.packet_id = packets.packet_id),
    gateway_count = (SELECT COUNT(DISTINCT r.receiver) FROM packet_receptions r
                     WHERE r.from_num = packets.from_num
                       AND r.packet_id = packets.packet_id),
    best_snr = (SELECT MAX(r.rx_snr) FROM packet_receptions r
                WHERE r.from_num = packets.from_num
                  AND r.packet_id = packets.packet_id),
    best_rssi = (SELECT MAX(r.rx_rssi) FROM packet_receptions r
                 WHERE r.from_num = packets.from_num
                   AND r.packet_id = packets.packet_id)
WHERE packet_id > 0;

DELETE FROM reception_summary;
INSERT INTO reception_summary (from_num, receiver, source, receptions, last_heard)
SELECT from_num, receiver, source, COUNT(*), MAX(received_at)
FROM packet_receptions
GROUP BY from_num, receiver, source;

UPDATE nodes SET latitude_i = NULL, longitude_i = NULL
WHERE latitude_i = 0 AND longitude_i = 0;

-- Older versions stored MQTT topic names in the node channel table under a
-- hashed index, which could overwrite a real local channel slot. Local slots
-- are 0-7 and are rewritten by the next config dump.
DELETE FROM channels WHERE idx > 7;

CREATE INDEX IF NOT EXISTS idx_raw_source_gateway
    ON raw_frames(source, gateway, received_at);
PRAGMA user_version = 15;
COMMIT;
"#,
    )?;

    // Hand the freed pages back to the filesystem when a large share of the
    // file is empty, and switch existing files to incremental auto-vacuum so
    // the retention cleanup can keep doing that.
    let pages: i64 = connection.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    let free: i64 = connection.query_row("PRAGMA freelist_count", [], |row| row.get(0))?;
    let auto_vacuum: i64 = connection.query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
    if auto_vacuum != 2 || free > pages / 4 {
        if free > 25_000 {
            info!(
                free_pages = free,
                "compacting the web database after the upgrade"
            );
        }
        if let Err(error) = connection.execute_batch("PRAGMA auto_vacuum=INCREMENTAL; VACUUM;") {
            warn!(%error, "could not compact the web database; continuing without it");
        }
    }
    // The upgrade can leave a write-ahead log as large as the old database.
    if let Err(error) = connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
        warn!(%error, "could not truncate the write-ahead log after the upgrade");
    }
    Ok(())
}

/// Run one statement through the connection's prepared-statement cache.
fn execute_cached(
    connection: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> rusqlite::Result<usize> {
    connection.prepare_cached(sql)?.execute(params)
}

fn column_exists(connection: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns: Vec<String> = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(columns.iter().any(|name| name == column))
}

fn ensure_column(
    connection: &Connection,
    table: &str,
    column: &str,
    declaration: &str,
) -> Result<()> {
    if !column_exists(connection, table, column)? {
        connection.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {declaration}"
        ))?;
    }
    Ok(())
}

fn apply_frame(
    connection: &Connection,
    frame: &pb::FromRadio,
    diagnostics: Option<NexusDiagnostics>,
    source: DbSource,
    receiver: Option<&str>,
    known_channel: Option<&str>,
    extra_channels: &[ExtraChannel],
    now: i64,
) -> Result<()> {
    let Some(variant) = &frame.payload_variant else {
        return Ok(());
    };
    match variant {
        from_radio::PayloadVariant::Channel(channel) => {
            upsert_channel(connection, channel, receiver, now)
        }
        from_radio::PayloadVariant::NodeInfo(node) => upsert_node(connection, node, source, now),
        from_radio::PayloadVariant::Packet(packet) => {
            let decrypted =
                decrypt_extra_channel(connection, packet, receiver, known_channel, extra_channels);
            let (packet, channel_name, was_decrypted) = match &decrypted {
                Some((packet, name)) => (packet, Some(name.as_str()), true),
                None => (packet, known_channel, false),
            };
            let fresh = apply_packet(
                connection,
                packet,
                diagnostics,
                source,
                receiver,
                channel_name,
                was_decrypted,
                now,
            )?;
            // An identical reception already stored means this is a replayed
            // copy; storing its raw frame again would only bloat the feed.
            if !fresh {
                return Ok(());
            }
            insert_meshtastic_raw(
                connection,
                packet,
                diagnostics,
                source,
                receiver,
                was_decrypted,
                now,
            )
        }
        _ => Ok(()),
    }
}

fn decrypt_extra_channel(
    connection: &Connection,
    packet: &pb::MeshPacket,
    receiver: Option<&str>,
    known_channel: Option<&str>,
    extra_channels: &[ExtraChannel],
) -> Option<(pb::MeshPacket, String)> {
    if extra_channels.is_empty() {
        return None;
    }
    let looked_up;
    let hint = match known_channel {
        Some(name) => Some(name),
        None => {
            looked_up = channel_name_for(connection, receiver, packet.channel as i64)
                .ok()
                .filter(|name| !name.is_empty());
            looked_up.as_deref()
        }
    };
    let (data, channel_name) = channel_crypto::decrypt_packet(packet, extra_channels, hint)?;
    let mut decoded = packet.clone();
    decoded.payload_variant = Some(pb::mesh_packet::PayloadVariant::Decoded(data));
    Some((decoded, channel_name))
}

/// Record one packet. Returns false when this exact reception was already
/// stored (a replayed copy), true otherwise.
#[allow(clippy::too_many_arguments)]
fn apply_packet(
    connection: &Connection,
    packet: &pb::MeshPacket,
    diagnostics: Option<NexusDiagnostics>,
    source: DbSource,
    receiver: Option<&str>,
    channel_name_override: Option<&str>,
    decrypted: bool,
    now: i64,
) -> Result<bool> {
    // JRAW chunks are transport frames, not Meshtastic packets; they are
    // recorded by apply_raw once the assembler completes a frame.
    if let Some(pb::mesh_packet::PayloadVariant::Encrypted(bytes)) = &packet.payload_variant {
        if parse_chunk(bytes).is_some() {
            return Ok(true);
        }
    }

    let decoded = muxtastic_core::packet::decoded(packet);
    let channel_name = match channel_name_override {
        Some(name) => name.to_owned(),
        None => channel_name_for(connection, receiver, database_channel(packet))?,
    };
    insert_packet(
        connection,
        packet,
        diagnostics,
        source,
        &channel_name,
        decrypted,
        now,
    )?;
    if let Some(receiver) = receiver {
        let fresh = insert_reception(
            connection,
            packet,
            diagnostics,
            source,
            receiver,
            &channel_name,
            decrypted,
            now,
        )?;
        if !fresh {
            return Ok(false);
        }
    }

    let Some(data) = decoded else {
        return Ok(true);
    };
    if data.portnum == pb::PortNum::TextMessageApp as i32 {
        insert_message(
            connection,
            packet,
            data,
            diagnostics,
            source,
            &channel_name,
            decrypted,
            now,
        )?;
    } else if data.portnum == pb::PortNum::NodeinfoApp as i32 {
        apply_nodeinfo_packet(connection, packet, source, now)?;
    } else if data.portnum == pb::PortNum::PositionApp as i32 {
        apply_position_packet(connection, packet, source, now)?;
    } else if data.portnum == pb::PortNum::TracerouteApp as i32 {
        insert_traceroute(connection, packet, data, source, receiver, decrypted, now)?;
    }
    Ok(true)
}

const OPAQUE_CHANNEL_BASE: i64 = 256;
const PKI_CHANNEL: i64 = 512;

fn database_channel(packet: &pb::MeshPacket) -> i64 {
    let decoded = matches!(
        packet.payload_variant,
        Some(pb::mesh_packet::PayloadVariant::Decoded(_))
    );
    let raw = packet.channel as i64;
    if decoded {
        raw
    } else if raw == 0 && packet.to != 0xFFFF_FFFF {
        PKI_CHANNEL
    } else {
        OPAQUE_CHANNEL_BASE + (raw & 0xFF)
    }
}

fn channel_name_for(
    connection: &Connection,
    receiver: Option<&str>,
    channel: i64,
) -> Result<String> {
    if let Some(receiver) = receiver.filter(|receiver| !receiver.is_empty()) {
        let name = connection
            .query_row(
                "SELECT NULLIF(name, '') FROM node_channels
                 WHERE receiver = ?1 AND idx = ?2",
                params![receiver, channel],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        if let Some(name) = name {
            return Ok(name);
        }
    }
    Ok(connection
        .query_row(
            "SELECT COALESCE(name, '') FROM channels WHERE idx = ?1",
            params![channel],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or_default())
}

fn packet_bytes(packet: &pb::MeshPacket) -> i64 {
    match &packet.payload_variant {
        Some(pb::mesh_packet::PayloadVariant::Encrypted(bytes)) => bytes.len() as i64,
        Some(pb::mesh_packet::PayloadVariant::Decoded(data)) => data.payload.len() as i64,
        _ => 0,
    }
}

fn insert_packet(
    connection: &Connection,
    packet: &pb::MeshPacket,
    diagnostics: Option<NexusDiagnostics>,
    source: DbSource,
    channel_name: &str,
    decrypted: bool,
    now: i64,
) -> Result<()> {
    let decoded = muxtastic_core::packet::decoded(packet);
    let portnum = decoded.map(|data| data.portnum);
    let bytes = packet_bytes(packet);
    let (frequency_error, coding_rate) = diagnostics_values(diagnostics);
    execute_cached(
        connection,
        "INSERT OR IGNORE INTO packets
         (packet_id, from_num, to_num, relay_node, channel, channel_name, decrypted,
          portnum, bytes, transport, via_mqtt, source, rx_time, rx_snr, rx_rssi,
          rx_frequency_error, rx_coding_rate, hop_limit, hop_start, received_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                 ?17, ?18, ?19, ?20)",
        params![
            packet.id as i64,
            packet.from as i64,
            packet.to as i64,
            packet.relay_node as i64,
            database_channel(packet),
            channel_name,
            decrypted as i64,
            portnum.map(|value| value as i64),
            bytes,
            packet.transport_mechanism as i64,
            packet.via_mqtt as i64,
            source.as_str(),
            packet.rx_time as i64,
            packet.rx_snr as f64,
            packet.rx_rssi as i64,
            frequency_error,
            coding_rate,
            packet.hop_limit as i64,
            packet.hop_start as i64,
            now,
        ],
    )?;
    Ok(())
}

fn insert_meshtastic_raw(
    connection: &Connection,
    packet: &pb::MeshPacket,
    diagnostics: Option<NexusDiagnostics>,
    source: DbSource,
    receiver: Option<&str>,
    decrypted: bool,
    now: i64,
) -> Result<()> {
    if source == DbSource::Client {
        return Ok(());
    }
    if let Some(pb::mesh_packet::PayloadVariant::Encrypted(bytes)) = &packet.payload_variant {
        if parse_chunk(bytes).is_some() {
            return Ok(());
        }
    }

    let gateway = receiver
        .and_then(|receiver| receiver.strip_prefix('!'))
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .unwrap_or(packet.from);
    let frame = packet.encode_to_vec();
    let frame_len = frame.len() as i64;
    let payload_name =
        muxtastic_core::packet::portnum(packet).map(|value| portnum_label(value as i64));
    let (frequency_error, coding_rate) = diagnostics_values(diagnostics);

    execute_cached(
        connection,
        "INSERT INTO raw_frames
         (kind, source, decrypted, gateway, sequence, channel, rx_time, rx_rssi, rx_snr,
          frequency_error, coding_rate, frame, frame_len, route_type, payload_type,
          route_name, payload_name, path_hex, sender_hash, destination_hash,
          channel_hash, node_name, public_key, received_at)
         VALUES (3, ?1, ?2, ?3, 0, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                 NULL, NULL, NULL, ?12, NULL, NULL, NULL, NULL, NULL, NULL, ?13)",
        params![
            source.as_str(),
            decrypted as i64,
            gateway as i64,
            database_channel(packet),
            packet.rx_time as i64,
            packet.rx_rssi as i64,
            packet.rx_snr as f64,
            frequency_error,
            coding_rate,
            frame,
            frame_len,
            payload_name,
            now,
        ],
    )?;
    Ok(())
}

/// Record one reception. Returns false when an identical row already exists.
///
/// The same receiver may legitimately hear a packet more than once (direct,
/// then through a relay), so repeats are kept. A byte-identical repeat — same
/// receiver, relay, hop limit, receive time and signal values — is a broker
/// redelivery or an MQTT loop and is dropped.
#[allow(clippy::too_many_arguments)]
fn insert_reception(
    connection: &Connection,
    packet: &pb::MeshPacket,
    diagnostics: Option<NexusDiagnostics>,
    source: DbSource,
    receiver: &str,
    channel_name: &str,
    decrypted: bool,
    now: i64,
) -> Result<bool> {
    if packet.id == 0 {
        return Ok(true);
    }
    let (frequency_error, coding_rate) = diagnostics_values(diagnostics);
    let (heard_before, identical): (i64, i64) = connection
        .prepare_cached(
            "SELECT COUNT(*),
                    COALESCE(SUM(relay_node = ?4 AND hop_limit = ?5 AND rx_time = ?6
                                 AND rx_snr = ?7 AND rx_rssi = ?8), 0)
             FROM packet_receptions
             WHERE from_num = ?1 AND packet_id = ?2 AND receiver = ?3",
        )?
        .query_row(
            params![
                packet.from as i64,
                packet.id as i64,
                receiver,
                packet.relay_node as i64,
                packet.hop_limit as i64,
                packet.rx_time as i64,
                packet.rx_snr as f64,
                packet.rx_rssi as i64,
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
    if identical > 0 {
        return Ok(false);
    }

    execute_cached(
        connection,
        "INSERT INTO packet_receptions
         (packet_id, from_num, to_num, relay_node, channel, channel_name, decrypted,
          receiver, source, via_mqtt, rx_time, rx_snr, rx_rssi, rx_frequency_error,
          rx_coding_rate, hop_limit, hop_start, received_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                 ?17, ?18)",
        params![
            packet.id as i64,
            packet.from as i64,
            packet.to as i64,
            packet.relay_node as i64,
            database_channel(packet),
            channel_name,
            decrypted as i64,
            receiver,
            source.as_str(),
            packet.via_mqtt as i64,
            packet.rx_time as i64,
            packet.rx_snr as f64,
            packet.rx_rssi as i64,
            frequency_error,
            coding_rate,
            packet.hop_limit as i64,
            packet.hop_start as i64,
            now,
        ],
    )?;

    // Keep the per-packet aggregates current without rescanning every
    // reception of the packet.
    execute_cached(
        connection,
        "UPDATE packets SET
            reception_count = reception_count + 1,
            gateway_count = gateway_count + ?3,
            best_snr = CASE WHEN best_snr IS NULL OR ?4 > best_snr THEN ?4 ELSE best_snr END,
            best_rssi = CASE WHEN best_rssi IS NULL OR ?5 > best_rssi THEN ?5 ELSE best_rssi END
         WHERE from_num = ?1 AND packet_id = ?2",
        params![
            packet.from as i64,
            packet.id as i64,
            (heard_before == 0) as i64,
            packet.rx_snr as f64,
            packet.rx_rssi as i64,
        ],
    )?;
    execute_cached(
        connection,
        "INSERT INTO reception_summary (from_num, receiver, source, receptions, last_heard)
         VALUES (?1, ?2, ?3, 1, ?4)
         ON CONFLICT(from_num, receiver, source) DO UPDATE SET
            receptions = receptions + 1,
            last_heard = MAX(last_heard, excluded.last_heard)",
        params![packet.from as i64, receiver, source.as_str(), now],
    )?;

    // If the row was created by a local client echo first, replace the
    // placeholder RF/source values with the real reception.
    for sql in [
        "UPDATE packets SET
            source = ?1, rx_time = ?2, rx_snr = ?3, rx_rssi = ?4,
            rx_frequency_error = ?5, rx_coding_rate = ?6,
            hop_limit = ?7, hop_start = ?8, via_mqtt = ?9,
            channel_name = ?12, decrypted = ?13
         WHERE from_num = ?10 AND packet_id = ?11 AND source = 'client'",
        "UPDATE messages SET
            source = ?1, rx_time = ?2, rx_snr = ?3, rx_rssi = ?4,
            rx_frequency_error = ?5, rx_coding_rate = ?6,
            hop_limit = ?7, hop_start = ?8, via_mqtt = ?9,
            channel_name = ?12, decrypted = ?13
         WHERE from_num = ?10 AND packet_id = ?11 AND source = 'client'",
    ] {
        execute_cached(
            connection,
            sql,
            params![
                source.as_str(),
                packet.rx_time as i64,
                packet.rx_snr as f64,
                packet.rx_rssi as i64,
                frequency_error,
                coding_rate,
                packet.hop_limit as i64,
                packet.hop_start as i64,
                packet.via_mqtt as i64,
                packet.from as i64,
                packet.id as i64,
                channel_name,
                decrypted as i64,
            ],
        )?;
    }
    Ok(true)
}

/// Recompute `reception_summary` from the reception rows.
fn rebuild_reception_summary(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "DELETE FROM reception_summary;
         INSERT INTO reception_summary (from_num, receiver, source, receptions, last_heard)
         SELECT from_num, receiver, source, COUNT(*), MAX(received_at)
         FROM packet_receptions
         GROUP BY from_num, receiver, source;",
    )
}

fn insert_traceroute(
    connection: &Connection,
    packet: &pb::MeshPacket,
    data: &pb::Data,
    source: DbSource,
    receiver: Option<&str>,
    decrypted: bool,
    now: i64,
) -> Result<()> {
    let Ok(discovery) = pb::RouteDiscovery::decode(data.payload.as_slice()) else {
        return Ok(());
    };
    execute_cached(
        connection,
        "INSERT OR IGNORE INTO traceroutes
         (packet_id, from_num, to_num, channel, request_id, rx_time,
          route, snr_towards, route_back, snr_back, source, receiver, decrypted,
          received_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            packet.id as i64,
            packet.from as i64,
            packet.to as i64,
            database_channel(packet),
            data.request_id as i64,
            packet.rx_time as i64,
            serde_json::to_string(&discovery.route)?,
            serde_json::to_string(&discovery.snr_towards)?,
            serde_json::to_string(&discovery.route_back)?,
            serde_json::to_string(&discovery.snr_back)?,
            source.as_str(),
            receiver,
            decrypted as i64,
            now,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_message(
    connection: &Connection,
    packet: &pb::MeshPacket,
    data: &pb::Data,
    diagnostics: Option<NexusDiagnostics>,
    source: DbSource,
    channel_name: &str,
    decrypted: bool,
    now: i64,
) -> Result<()> {
    let text = String::from_utf8_lossy(&data.payload);
    let (frequency_error, coding_rate) = diagnostics_values(diagnostics);
    execute_cached(
        connection,
        "INSERT OR IGNORE INTO messages
         (packet_id, from_num, to_num, channel, channel_name, decrypted, text, rx_time,
          rx_snr, rx_rssi, rx_frequency_error, rx_coding_rate, hop_limit, hop_start,
          via_mqtt, source, received_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                 ?17)",
        params![
            packet.id as i64,
            packet.from as i64,
            packet.to as i64,
            database_channel(packet),
            channel_name,
            decrypted as i64,
            text.as_ref(),
            packet.rx_time as i64,
            packet.rx_snr as f64,
            packet.rx_rssi as i64,
            frequency_error,
            coding_rate,
            packet.hop_limit as i64,
            packet.hop_start as i64,
            packet.via_mqtt as i64,
            source.as_str(),
            now,
        ],
    )?;
    Ok(())
}

fn diagnostics_values(diagnostics: Option<NexusDiagnostics>) -> (Option<f64>, Option<i64>) {
    diagnostics
        .map(|diagnostics| {
            (
                diagnostics.frequency_error.map(f64::from),
                diagnostics.coding_rate.map(i64::from),
            )
        })
        .unwrap_or((None, None))
}

fn apply_nodeinfo_packet(
    connection: &Connection,
    packet: &pb::MeshPacket,
    source: DbSource,
    now: i64,
) -> Result<()> {
    let Some(user) = muxtastic_core::packet::nodeinfo(packet) else {
        return Ok(());
    };
    let node = pb::NodeInfo {
        num: packet.from,
        user: Some(user),
        snr: packet.rx_snr,
        last_heard: packet.rx_time,
        hops_away: Some(muxtastic_core::packet::hops_away(packet)),
        via_mqtt: packet.via_mqtt,
        ..Default::default()
    };
    upsert_node(connection, &node, source, now)
}

fn apply_position_packet(
    connection: &Connection,
    packet: &pb::MeshPacket,
    source: DbSource,
    now: i64,
) -> Result<()> {
    let Some(position) = muxtastic_core::packet::position(packet) else {
        return Ok(());
    };
    // `packet::position` already rejects 0°, 0°. A packet carrying only one
    // coordinate is not a position either: keep what is stored and only note
    // the contact, instead of storing 0 for the missing half.
    let (latitude, longitude) = match (position.latitude_i, position.longitude_i) {
        (Some(latitude), Some(longitude)) if latitude != 0 || longitude != 0 => {
            (latitude, longitude)
        }
        _ => {
            execute_cached(
                connection,
                "INSERT INTO nodes (num, last_heard, via_mqtt, source, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(num) DO UPDATE SET
                    last_heard = MAX(nodes.last_heard, excluded.last_heard),
                    via_mqtt = excluded.via_mqtt,
                    source = excluded.source,
                    updated_at = excluded.updated_at",
                params![
                    packet.from as i64,
                    packet.rx_time as i64,
                    packet.via_mqtt as i64,
                    source.as_str(),
                    now,
                ],
            )?;
            return Ok(());
        }
    };
    execute_cached(
        connection,
        "INSERT INTO nodes
         (num, last_heard, via_mqtt, source, latitude_i, longitude_i, altitude, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(num) DO UPDATE SET
            last_heard = MAX(nodes.last_heard, excluded.last_heard),
            via_mqtt = excluded.via_mqtt,
            source = excluded.source,
            latitude_i = excluded.latitude_i,
            longitude_i = excluded.longitude_i,
            altitude = COALESCE(excluded.altitude, nodes.altitude),
            updated_at = excluded.updated_at",
        params![
            packet.from as i64,
            packet.rx_time as i64,
            packet.via_mqtt as i64,
            source.as_str(),
            latitude as i64,
            longitude as i64,
            position.altitude.map(|value| value as i64),
            now,
        ],
    )?;
    Ok(())
}

fn upsert_node(
    connection: &Connection,
    node: &pb::NodeInfo,
    source: DbSource,
    now: i64,
) -> Result<()> {
    let user = node.user.as_ref();
    let node_id = user.map(|user| user.id.clone()).filter(|id| !id.is_empty());
    let long_name = user
        .map(|user| user.long_name.clone())
        .filter(|name| !name.is_empty());
    let short_name = user
        .map(|user| user.short_name.clone())
        .filter(|name| !name.is_empty());
    let hw_model = user.map(|user| user.hw_model as i64);
    let role = user.map(|user| user.role as i64);
    let public_key = user
        .map(|user| user.public_key.clone())
        .filter(|key| !key.is_empty());

    let metrics = node.device_metrics.as_ref();
    let position = node.position.as_ref();
    let coordinates = position
        .and_then(|position| Some((position.latitude_i?, position.longitude_i?)))
        .filter(|(latitude, longitude)| *latitude != 0 || *longitude != 0);

    execute_cached(
        connection,
        "INSERT INTO nodes
         (num, node_id, long_name, short_name, hw_model, role, last_heard, snr,
          hops_away, via_mqtt, source, battery_level, voltage, channel_utilization,
          air_util_tx, latitude_i, longitude_i, altitude, public_key, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16, ?17, ?18, ?19, ?20)
         ON CONFLICT(num) DO UPDATE SET
            node_id = COALESCE(excluded.node_id, nodes.node_id),
            long_name = COALESCE(excluded.long_name, nodes.long_name),
            short_name = COALESCE(excluded.short_name, nodes.short_name),
            hw_model = COALESCE(excluded.hw_model, nodes.hw_model),
            role = COALESCE(excluded.role, nodes.role),
            last_heard = MAX(nodes.last_heard, excluded.last_heard),
            snr = COALESCE(excluded.snr, nodes.snr),
            hops_away = COALESCE(excluded.hops_away, nodes.hops_away),
            via_mqtt = excluded.via_mqtt,
            source = excluded.source,
            battery_level = COALESCE(excluded.battery_level, nodes.battery_level),
            voltage = COALESCE(excluded.voltage, nodes.voltage),
            channel_utilization = COALESCE(excluded.channel_utilization, nodes.channel_utilization),
            air_util_tx = COALESCE(excluded.air_util_tx, nodes.air_util_tx),
            latitude_i = COALESCE(excluded.latitude_i, nodes.latitude_i),
            longitude_i = COALESCE(excluded.longitude_i, nodes.longitude_i),
            altitude = COALESCE(excluded.altitude, nodes.altitude),
            public_key = COALESCE(excluded.public_key, nodes.public_key),
            updated_at = excluded.updated_at",
        params![
            node.num as i64,
            node_id,
            long_name,
            short_name,
            hw_model,
            role,
            node.last_heard as i64,
            (node.snr != 0.0).then_some(node.snr as f64),
            node.hops_away.map(|value| value as i64),
            node.via_mqtt as i64,
            source.as_str(),
            metrics
                .and_then(|metrics| metrics.battery_level)
                .map(|value| value as i64),
            metrics
                .and_then(|metrics| metrics.voltage)
                .map(|value| value as f64),
            metrics
                .and_then(|metrics| metrics.channel_utilization)
                .map(|value| value as f64),
            metrics
                .and_then(|metrics| metrics.air_util_tx)
                .map(|value| value as f64),
            coordinates.map(|(latitude, _)| latitude as i64),
            coordinates.map(|(_, longitude)| longitude as i64),
            position
                .and_then(|position| position.altitude)
                .map(|value| value as i64),
            public_key,
            now,
        ],
    )?;
    Ok(())
}

fn upsert_channel(
    connection: &Connection,
    channel: &pb::Channel,
    receiver: Option<&str>,
    now: i64,
) -> Result<()> {
    let settings = channel.settings.as_ref();
    let name = settings.map(|settings| settings.name.clone());
    let uplink = settings
        .map(|settings| settings.uplink_enabled as i64)
        .unwrap_or(0);
    let downlink = settings
        .map(|settings| settings.downlink_enabled as i64)
        .unwrap_or(0);
    execute_cached(
        connection,
        "INSERT INTO channels (idx, name, role, uplink, downlink, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(idx) DO UPDATE SET
            name = excluded.name,
            role = excluded.role,
            uplink = excluded.uplink,
            downlink = excluded.downlink,
            updated_at = excluded.updated_at",
        params![
            channel.index as i64,
            name.clone(),
            channel.role as i64,
            uplink,
            downlink,
            now,
        ],
    )?;
    if let Some(receiver) = receiver.filter(|receiver| !receiver.is_empty()) {
        execute_cached(
            connection,
            "INSERT INTO node_channels (receiver, idx, name, role, uplink, downlink, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(receiver, idx) DO UPDATE SET
                name = excluded.name,
                role = excluded.role,
                uplink = excluded.uplink,
                downlink = excluded.downlink,
                updated_at = excluded.updated_at",
            params![
                receiver,
                channel.index as i64,
                name,
                channel.role as i64,
                uplink,
                downlink,
                now,
            ],
        )?;
    }
    Ok(())
}

fn apply_raw(connection: &Connection, raw: &RawTunnelFrame, now: i64) -> Result<()> {
    let meshcore = if raw.kind == RawTunnelKind::MeshCore {
        parse_meshcore_frame(&raw.frame)
    } else {
        None
    };
    let reticulum = if raw.kind == RawTunnelKind::RNode {
        parse_reticulum_frame(&raw.frame)
    } else {
        None
    };

    let (
        route_type,
        payload_type,
        route_name,
        payload_name,
        path_hex,
        sender_hash,
        destination_hash,
        channel_hash,
        node_name,
        public_key,
    ) = if let Some(info) = &meshcore {
        (
            Some(info.route_type as i64),
            Some(info.payload_type as i64),
            Some(meshcore_route_name(info.route_type).to_owned()),
            Some(meshcore_payload_name(info.payload_type).to_owned()),
            Some(info.path_hex.clone()),
            info.sender_hash.clone(),
            info.destination_hash.clone(),
            info.channel_hash.map(i64::from),
            info.node_name.clone(),
            info.public_key.clone(),
        )
    } else if let Some(info) = &reticulum {
        (
            Some(i64::from(info.packet_type)),
            Some(i64::from(info.context)),
            Some(reticulum_packet_type_name(info.packet_type).to_owned()),
            Some(reticulum_context_name(info.context).to_owned()),
            None,
            None,
            Some(info.destination_hash.clone()),
            None,
            info.node_name.clone(),
            info.public_key.clone(),
        )
    } else {
        (None, None, None, None, None, None, None, None, None, None)
    };

    execute_cached(
        connection,
        "INSERT INTO raw_frames
         (kind, source, gateway, sequence, channel, rx_time, rx_rssi, rx_snr,
          frequency_error, coding_rate, frame, frame_len, route_type, payload_type,
          route_name, payload_name, path_hex, sender_hash, destination_hash,
          channel_hash, node_name, public_key, received_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
        params![
            raw.kind.wire_value() as i64,
            raw.source.as_str(),
            raw.gateway as i64,
            raw.sequence as i64,
            raw.channel as i64,
            raw.rx_time as i64,
            raw.rssi.map(|value| value as i64),
            raw.snr.map(f64::from),
            raw.frequency_error.map(f64::from),
            raw.coding_rate.map(i64::from),
            raw.frame,
            raw.frame.len() as i64,
            route_type,
            payload_type,
            route_name,
            payload_name,
            path_hex,
            sender_hash,
            destination_hash,
            channel_hash,
            node_name,
            public_key,
            now,
        ],
    )?;

    if let Some(info) = &meshcore {
        let advert = info.payload_type == 0x04;
        // An advert identifies its node by full public key. Other frames only
        // carry a one-byte hash, which many nodes share.
        let node_key = match (&info.public_key, advert) {
            (Some(key), true) => Some(hex(key)),
            _ => info.sender_hash.clone(),
        };
        if let Some(hash) = &node_key {
            upsert_jraw_node(
                connection,
                RawTunnelKind::MeshCore,
                hash,
                advert.then_some(info.node_name.as_deref()).flatten(),
                advert.then_some(info.public_key.as_deref()).flatten(),
                advert.then_some(info.node_type.map(i64::from)).flatten(),
                advert_degrees(info),
                raw.gateway,
                now,
            )?;
        }
    } else if let Some(info) = &reticulum {
        if info.packet_type == 1 {
            upsert_jraw_node(
                connection,
                RawTunnelKind::RNode,
                &info.destination_hash,
                info.node_name.as_deref(),
                info.public_key.as_deref(),
                None,
                None,
                raw.gateway,
                now,
            )?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn upsert_jraw_node(
    connection: &Connection,
    kind: RawTunnelKind,
    node_hash: &str,
    name: Option<&str>,
    public_key: Option<&[u8]>,
    node_type: Option<i64>,
    position: Option<(f64, f64)>,
    gateway: u32,
    now: i64,
) -> Result<()> {
    execute_cached(
        connection,
        "INSERT INTO jraw_nodes
         (kind, node_hash, name, public_key, node_type, first_heard, last_heard,
          frames, last_gateway, latitude, longitude)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 1, ?7, ?8, ?9)
         ON CONFLICT(kind, node_hash) DO UPDATE SET
            name = COALESCE(excluded.name, jraw_nodes.name),
            public_key = COALESCE(excluded.public_key, jraw_nodes.public_key),
            node_type = COALESCE(excluded.node_type, jraw_nodes.node_type),
            latitude = COALESCE(excluded.latitude, jraw_nodes.latitude),
            longitude = COALESCE(excluded.longitude, jraw_nodes.longitude),
            last_heard = excluded.last_heard,
            frames = jraw_nodes.frames + 1,
            last_gateway = excluded.last_gateway",
        params![
            kind.wire_value() as i64,
            node_hash,
            name,
            public_key,
            node_type,
            now,
            gateway as i64,
            position.map(|(latitude, _)| latitude),
            position.map(|(_, longitude)| longitude),
        ],
    )?;
    Ok(())
}

fn percent(part: i64, total: i64) -> f64 {
    if total > 0 {
        part as f64 / total as f64 * 100.0
    } else {
        0.0
    }
}

fn stats(connection: &Connection) -> Result<Stats> {
    let now = now_unix();
    let since = now - 86_400;
    let rate_since = now - HOURLY_WINDOW_SECS;
    // One pass over `packets` instead of one query per figure.
    #[allow(clippy::type_complexity)]
    let (
        packets,
        packets_24h,
        via_mqtt,
        mqtt_source,
        receptions,
        multi_heard,
        bytes,
        decoded_packets,
        pki_packets,
        decrypted,
    ): (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) = connection.query_row(
        "SELECT COUNT(*),
                COALESCE(SUM(received_at >= ?1), 0),
                COALESCE(SUM(via_mqtt = 1), 0),
                COALESCE(SUM(source = 'mqtt'), 0),
                COALESCE(SUM(reception_count), 0),
                COALESCE(SUM(gateway_count > 1), 0),
                COALESCE(SUM(bytes), 0),
                COUNT(portnum),
                COALESCE(SUM(channel = 512), 0),
                COALESCE(SUM(decrypted = 1), 0)
         FROM packets WHERE transport <> 0",
        params![since],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
            ))
        },
    )?;
    let (messages, messages_24h): (i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(SUM(m.received_at >= ?1), 0) FROM messages m
         JOIN packets p ON p.from_num = m.from_num AND p.packet_id = m.packet_id
         WHERE p.transport <> 0",
        params![since],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut raw_by_kind: HashMap<i64, i64> = HashMap::new();
    {
        let mut statement =
            connection.prepare_cached("SELECT kind, COUNT(*) FROM raw_frames GROUP BY kind")?;
        let rows =
            statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
        for row in rows {
            let (kind, frames) = row?;
            raw_by_kind.insert(kind, frames);
        }
    }
    let raw_kind = |kind: i64| raw_by_kind.get(&kind).copied().unwrap_or(0);
    let totals = Totals {
        packets,
        packets_24h,
        messages,
        messages_24h,
        nodes: count(connection, "SELECT COUNT(*) FROM nodes", params![])?,
        raw_frames: raw_by_kind.values().sum(),
        jencore_frames: raw_kind(1),
        jenrnode_frames: raw_kind(2),
        meshtastic_frames: raw_kind(3),
        via_mqtt,
        mqtt_source,
        receptions,
        multi_heard,
        bytes,
        decoded_packets,
        opaque_packets: packets - decoded_packets,
        pki_packets,
        decrypted,
    };

    let (window_packets, window_bytes): (i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM packets
         WHERE transport <> 0 AND received_at >= ?1",
        params![rate_since],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let packets_per_hour = window_packets as f64;
    let bytes_per_hour = window_bytes as f64;

    let mut hourly_map: HashMap<i64, i64> = HashMap::new();
    {
        let mut statement = connection.prepare(
            "SELECT (received_at / 3600) * 3600 AS hour, COUNT(*)
             FROM packets WHERE transport <> 0 AND received_at >= ?1 GROUP BY hour",
        )?;
        let rows = statement.query_map(params![since], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (hour, count) = row?;
            hourly_map.insert(hour, count);
        }
    }
    let current_hour = (now / 3600) * 3600;
    let hourly = (0..24)
        .map(|offset| {
            let hour = current_hour - (23 - offset) * 3600;
            HourBucket {
                hour_start: hour,
                count: *hourly_map.get(&hour).unwrap_or(&0),
            }
        })
        .collect();

    let mut portnums = Vec::new();
    {
        let mut statement = connection.prepare(
            "SELECT portnum, COUNT(*) FROM packets
             WHERE portnum IS NOT NULL AND transport <> 0
             GROUP BY portnum ORDER BY COUNT(*) DESC LIMIT 12",
        )?;
        let rows =
            statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
        for row in rows {
            let (portnum, count) = row?;
            portnums.push(CountBucket {
                key: portnum,
                label: portnum_label(portnum),
                count,
                percent: percent(count, totals.packets),
            });
        }
    }

    let mut channel_counts = Vec::new();
    {
        let mut window_map: HashMap<String, (i64, i64)> = HashMap::new();
        {
            let mut statement = connection.prepare(
                "SELECT CASE WHEN channel_name <> '' THEN channel_name
                              ELSE '#' || channel END AS channel_key,
                        COUNT(*), COALESCE(SUM(bytes), 0)
                 FROM packets
                 WHERE transport <> 0 AND received_at >= ?1
                 GROUP BY channel_key",
            )?;
            let rows = statement.query_map(params![rate_since], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (row.get::<_, i64>(1)?, row.get::<_, i64>(2)?),
                ))
            })?;
            for row in rows {
                let (key, values) = row?;
                window_map.insert(key, values);
            }
        }

        let mut node_statement = connection.prepare(
            "SELECT p.from_num,
                    COALESCE(NULLIF(n.long_name, ''), NULLIF(n.short_name, ''),
                             printf('!%08x', p.from_num)),
                    COUNT(*), COALESCE(SUM(p.bytes), 0)
             FROM packets p LEFT JOIN nodes n ON n.num = p.from_num
             WHERE p.transport <> 0
               AND ((?2 <> '' AND p.channel_name = ?2)
                    OR (?2 = '' AND p.channel = ?1))
             GROUP BY p.from_num ORDER BY COUNT(*) DESC, p.from_num",
        )?;
        let mut statement = connection.prepare(
            "SELECT MIN(p.channel) AS channel,
                    CASE WHEN p.channel_name <> '' THEN p.channel_name ELSE '' END AS name,
                    CASE WHEN p.channel_name <> '' THEN p.channel_name
                         ELSE '#' || p.channel END AS channel_key,
                    COUNT(*), COALESCE(SUM(p.bytes), 0)
             FROM packets p
             WHERE p.transport <> 0
             GROUP BY channel_key
             ORDER BY COUNT(*) DESC, name, channel",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        for row in rows {
            let (channel, name, key, count, bytes) = row?;
            let mut nodes = Vec::new();
            for row in node_statement.query_map(params![channel, name], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })? {
                let (num, name, node_count, node_bytes) = row?;
                nodes.push(ChannelNodeCount {
                    num,
                    name,
                    count: node_count,
                    bytes: node_bytes,
                    percent: percent(node_count, count),
                });
            }
            let (window_count, window_bytes) = window_map.get(&key).copied().unwrap_or((0, 0));
            channel_counts.push(ChannelCount {
                channel,
                name,
                count,
                bytes,
                packets_per_hour: window_count as f64,
                bytes_per_hour: window_bytes as f64,
                percent: percent(count, totals.packets),
                nodes,
            });
        }
    }

    let mut transports = Vec::new();
    {
        let mut statement = connection.prepare(
            "SELECT transport, COUNT(*) FROM packets
             GROUP BY transport ORDER BY COUNT(*) DESC",
        )?;
        let rows =
            statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
        for row in rows {
            let (transport, count) = row?;
            transports.push(CountBucket {
                key: transport,
                label: transport_label(transport),
                count,
                percent: percent(count, totals.packets),
            });
        }
    }

    let mut top_nodes = Vec::new();
    {
        let mut statement = connection.prepare(
            "SELECT p.from_num,
                    COALESCE(NULLIF(n.long_name, ''), NULLIF(n.short_name, ''),
                             printf('!%08x', p.from_num)),
                    COUNT(*)
             FROM packets p LEFT JOIN nodes n ON n.num = p.from_num
             WHERE p.transport <> 0
             GROUP BY p.from_num ORDER BY COUNT(*) DESC LIMIT 10",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(NodeCount {
                num: row.get(0)?,
                name: row.get(1)?,
                count: row.get(2)?,
                percent: 0.0,
            })
        })?;
        for row in rows {
            let mut node = row?;
            node.percent = percent(node.count, totals.packets);
            top_nodes.push(node);
        }
    }

    Ok(Stats {
        totals,
        packets_per_hour,
        bytes_per_hour,
        window_secs: HOURLY_WINDOW_SECS,
        hourly,
        portnums,
        channels: channel_counts,
        transports,
        top_nodes,
        channel_list: channels(connection)?,
    })
}

fn messages(connection: &Connection, channel: Option<&str>, limit: usize) -> Result<Vec<Message>> {
    let limit = limit.clamp(1, 1000) as i64;
    let mut statement = connection.prepare(
        "SELECT m.id, m.packet_id, m.from_num,
                COALESCE(NULLIF(n.long_name, ''), NULLIF(n.short_name, ''), ''),
                m.channel, m.channel_name,
                m.text, m.rx_time, m.rx_snr,
                m.rx_rssi, m.rx_frequency_error, m.rx_coding_rate, m.hop_limit,
                m.hop_start, m.via_mqtt, m.source, m.received_at,
                COALESCE(p.reception_count, 0), COALESCE(p.gateway_count, 0),
                p.best_snr, p.best_rssi, COALESCE(p.relay_node, 0),
                COALESCE(m.decrypted, 0)
         FROM messages m
         LEFT JOIN nodes n ON n.num = m.from_num
         LEFT JOIN packets p ON p.from_num = m.from_num AND p.packet_id = m.packet_id
         WHERE (?1 IS NULL
                OR (?1 GLOB '#*' AND m.channel = CAST(SUBSTR(?1, 2) AS INTEGER))
                OR m.channel_name = ?1)
         ORDER BY m.id DESC LIMIT ?2",
    )?;
    let rows = statement.query_map(params![channel, limit], |row| {
        Ok(Message {
            id: row.get(0)?,
            packet_id: row.get(1)?,
            from_num: row.get(2)?,
            sender: row.get(3)?,
            channel: row.get(4)?,
            channel_name: row.get(5)?,
            text: row.get(6)?,
            rx_time: row.get(7)?,
            rx_snr: row.get(8)?,
            rx_rssi: row.get(9)?,
            rx_frequency_error: row.get(10)?,
            rx_coding_rate: row.get(11)?,
            hop_limit: row.get(12)?,
            hop_start: row.get(13)?,
            via_mqtt: row.get::<_, i64>(14)? != 0,
            source: row.get(15)?,
            received_at: row.get(16)?,
            reception_count: row.get(17)?,
            gateway_count: row.get(18)?,
            best_snr: row.get(19)?,
            best_rssi: row.get(20)?,
            relay_node: row.get(21)?,
            decrypted: row.get::<_, i64>(22)? != 0,
            network: "meshtastic",
            sent_at: None,
            meshcore_receptions: Vec::new(),
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn meshcore_channel_label(name: &str) -> String {
    format!("{MESHCORE_CHANNEL_PREFIX}{name}")
}

/// MeshCore group text we can decrypt, one entry per message. A flooded
/// message is heard several times over different paths; the copies share
/// their payload and are folded into one message with a reception count.
fn meshcore_messages(
    connection: &Connection,
    keys: &MeshCoreKeys,
    channel: Option<&str>,
) -> Result<Vec<Message>> {
    let mut statement = connection.prepare_cached(
        "SELECT id, gateway, rx_time, rx_rssi, rx_snr, frequency_error, coding_rate,
                frame, source, received_at
         FROM raw_frames WHERE kind = 1 AND payload_type = 5
         ORDER BY id DESC LIMIT ?1",
    )?;
    let directory = MeshCoreDirectory::load(connection)?;
    let mut rows = statement.query(params![MESHCORE_CHAT_SCAN])?;
    let mut by_payload: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut gateways: Vec<HashSet<i64>> = Vec::new();
    let mut out: Vec<Message> = Vec::new();
    while let Some(row) = rows.next()? {
        let frame: Vec<u8> = row.get(7)?;
        let Some(info) = parse_meshcore_frame(&frame) else {
            continue;
        };
        let payload = info.payload(&frame);
        let gateway: i64 = row.get(1)?;
        let rssi: Option<i64> = row.get(3)?;
        let snr: Option<f64> = row.get(4)?;
        let hops = info.path_hashes().len() as i64;
        let received_at: i64 = row.get(9)?;
        let reception = |info: &MeshCoreInfo| MeshCoreReception {
            received_at,
            gateway_id: format!("!{:08x}", gateway as u32),
            rx_snr: snr,
            rx_rssi: rssi,
            route_name: meshcore_route_name(info.route_type),
            path_hash_size: i64::from(info.path_hash_size),
            path: info
                .path_hashes()
                .iter()
                .map(|hash| directory.resolve(hash, true))
                .collect(),
        };

        if let Some(&index) = by_payload.get(payload) {
            // An older copy of a message already seen: rows arrive newest
            // first, so this one becomes the reception the message shows.
            let message = &mut out[index];
            message.id = -row.get::<_, i64>(0)?;
            message.rx_time = row.get(2)?;
            message.rx_rssi = rssi;
            message.rx_snr = snr;
            message.rx_frequency_error = row.get(5)?;
            message.rx_coding_rate = row.get(6)?;
            message.source = row.get(8)?;
            message.received_at = received_at;
            message.hop_start = Some(hops);
            message.reception_count += 1;
            // Kept oldest first.
            message.meshcore_receptions.insert(0, reception(&info));
            gateways[index].insert(gateway);
            message.gateway_count = gateways[index].len() as i64;
            message.best_snr = match (message.best_snr, snr) {
                (Some(best), Some(snr)) => Some(best.max(snr)),
                (best, snr) => best.or(snr),
            };
            message.best_rssi = match (message.best_rssi, rssi) {
                (Some(best), Some(rssi)) => Some(best.max(rssi)),
                (best, rssi) => best.or(rssi),
            };
            continue;
        }

        let Some(group) = keys.decrypt_group(info.payload_type, payload) else {
            continue;
        };
        let channel_name = meshcore_channel_label(&group.channel);
        if channel.is_some_and(|wanted| wanted != channel_name) {
            continue;
        }
        // Group text is "sender name: message".
        let (sender, text) = match group.text.split_once(": ") {
            Some((sender, text)) => (sender.to_owned(), text.to_owned()),
            None => (String::new(), group.text),
        };
        by_payload.insert(payload.to_vec(), out.len());
        gateways.push(HashSet::from([gateway]));
        out.push(Message {
            id: -row.get::<_, i64>(0)?,
            packet_id: 0,
            from_num: 0,
            sender,
            channel: -1,
            channel_name,
            text,
            rx_time: row.get(2)?,
            rx_snr: snr,
            rx_rssi: rssi,
            rx_frequency_error: row.get(5)?,
            rx_coding_rate: row.get(6)?,
            // MeshCore has no hop limit; the path length is the hops used.
            hop_limit: Some(0),
            hop_start: Some(hops),
            via_mqtt: false,
            source: row.get(8)?,
            received_at,
            reception_count: 1,
            gateway_count: 1,
            best_snr: snr,
            best_rssi: rssi,
            relay_node: 0,
            decrypted: true,
            network: "meshcore",
            sent_at: group.timestamp.map(i64::from),
            meshcore_receptions: vec![reception(&info)],
        });
    }
    Ok(out)
}

/// The largest groups of a breakdown plus the total over all of its groups.
struct Counted {
    rows: Vec<CountBucket>,
    total: i64,
}

fn count_buckets(counts: HashMap<String, i64>, limit: usize) -> Counted {
    let total: i64 = counts.values().sum();
    let mut rows: Vec<(String, i64)> = counts.into_iter().collect();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    rows.truncate(limit);
    let rows = rows
        .into_iter()
        .enumerate()
        .map(|(index, (label, count))| CountBucket {
            key: index as i64,
            label,
            count,
            percent: percent(count, total),
        })
        .collect();
    Counted { rows, total }
}

fn grouped_counts(
    connection: &Connection,
    sql: &str,
    kind: i64,
    limit: usize,
) -> Result<Counted> {
    let mut statement = connection.prepare_cached(sql)?;
    let rows = statement.query_map(params![kind], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut counts = HashMap::new();
    for row in rows {
        let (label, count) = row?;
        counts.insert(label, count);
    }
    Ok(count_buckets(counts, limit))
}

fn jraw_stats(
    connection: &Connection,
    kind: i64,
    keys: &MeshCoreKeys,
    now: i64,
) -> Result<JrawStats> {
    let since = now - 86_400;
    let (frames, frames_24h, bytes): (i64, i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(SUM(received_at >= ?2), 0), COALESCE(SUM(frame_len), 0)
         FROM raw_frames WHERE kind = ?1",
        params![kind, since],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let (nodes, nodes_24h, named): (i64, i64, i64) = connection.query_row(
        "SELECT COUNT(*), COALESCE(SUM(last_heard >= ?2), 0),
                COALESCE(SUM(name IS NOT NULL AND name <> ''), 0)
         FROM jraw_nodes WHERE kind = ?1 AND public_key IS NOT NULL",
        params![kind, since],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;

    let mut hourly_map: HashMap<i64, i64> = HashMap::new();
    {
        let mut statement = connection.prepare_cached(
            "SELECT (received_at / 3600) * 3600 AS hour, COUNT(*)
             FROM raw_frames WHERE kind = ?1 AND received_at >= ?2 GROUP BY hour",
        )?;
        let rows = statement.query_map(params![kind, since], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (hour, count) = row?;
            hourly_map.insert(hour, count);
        }
    }
    let current_hour = (now / 3600) * 3600;
    let hourly = (0..24)
        .map(|offset| {
            let hour = current_hour - (23 - offset) * 3600;
            HourBucket {
                hour_start: hour,
                count: *hourly_map.get(&hour).unwrap_or(&0),
            }
        })
        .collect();

    let first_grouping = grouped_counts(
        connection,
        "SELECT COALESCE(route_name, 'unparsed'), COUNT(*) FROM raw_frames
         WHERE kind = ?1 GROUP BY 1",
        kind,
        20,
    )?;
    let second_grouping = grouped_counts(
        connection,
        "SELECT COALESCE(payload_name, 'unparsed'), COUNT(*) FROM raw_frames
         WHERE kind = ?1 GROUP BY 1",
        kind,
        30,
    )?;
    let gateways = grouped_counts(
        connection,
        "SELECT COALESCE(NULLIF(n.long_name, ''), NULLIF(n.short_name, ''),
                         printf('!%08x', r.gateway)), COUNT(*)
         FROM raw_frames r LEFT JOIN nodes n ON n.num = r.gateway
         WHERE r.kind = ?1 GROUP BY r.gateway",
        kind,
        20,
    )?;

    let card = |label: &str, value: i64, sub: String| StatCard {
        label: label.to_owned(),
        value: value as f64,
        unit: "count",
        sub,
    };
    let mut cards = vec![
        card("Frames", frames, format!("{frames_24h} in 24h")),
        StatCard {
            label: "Data".to_owned(),
            value: bytes as f64,
            unit: "bytes",
            sub: "frame bytes stored".to_owned(),
        },
    ];
    let mut tables = Vec::new();
    let build = |title: &str, note: &str, counted: Counted, pie: bool| StatTable {
        title: title.to_owned(),
        note: note.to_owned(),
        rows: counted.rows,
        total: counted.total,
        pie,
    };
    let table = |title: &str, note: &str, counted: Counted| build(title, note, counted, false);
    let pie = |title: &str, note: &str, counted: Counted| build(title, note, counted, true);

    if kind == 1 {
        let (repeaters, rooms, positioned): (i64, i64, i64) = connection.query_row(
            "SELECT COALESCE(SUM(node_type = 2), 0), COALESCE(SUM(node_type = 3), 0),
                    COALESCE(SUM(latitude IS NOT NULL), 0)
             FROM jraw_nodes WHERE kind = 1 AND public_key IS NOT NULL",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        cards.push(card("Nodes", nodes, format!("{nodes_24h} heard in 24h · {named} named")));
        cards.push(card("Repeaters", repeaters, format!("{rooms} room servers")));
        cards.push(card("With position", positioned, "advertised a location".to_owned()));

        // Everything below needs the frames themselves: decrypt group
        // messages and resolve path hashes for the last 24 hours.
        let directory = MeshCoreDirectory::load(connection)?;
        let mut statement = connection.prepare_cached(
            "SELECT frame FROM raw_frames WHERE kind = 1 AND received_at >= ?1
             ORDER BY id DESC LIMIT ?2",
        )?;
        let mut rows = statement.query(params![since, JRAW_STATS_SCAN])?;
        let mut seen_messages: HashSet<Vec<u8>> = HashSet::new();
        let mut channels: HashMap<String, i64> = HashMap::new();
        let mut senders: HashMap<String, i64> = HashMap::new();
        let mut relays: HashMap<String, i64> = HashMap::new();
        let mut regions: HashMap<String, i64> = HashMap::new();
        let (mut group_messages, mut decrypted, mut scoped, mut hops, mut with_path) =
            (0i64, 0i64, 0i64, 0i64, 0i64);
        while let Some(row) = rows.next()? {
            let frame: Vec<u8> = row.get(0)?;
            let Some(info) = parse_meshcore_frame(&frame) else {
                continue;
            };
            let payload = info.payload(&frame);
            let path = info.path_hashes();
            if info.trace.is_none() && info.route_type <= 1 {
                with_path += 1;
                hops += path.len() as i64;
            }
            for hash in &path {
                let found = directory.resolve(hash, true);
                let label = match found.candidates {
                    0 => format!("{hash} (unknown)"),
                    1 => found.names[0].clone(),
                    count => format!("{hash} ({count} candidates)"),
                };
                *relays.entry(label).or_default() += 1;
            }
            if let Some([scope, _]) = info.transport_codes {
                scoped += 1;
                let label = keys
                    .region_for(info.payload_type, payload, scope)
                    .map_or_else(|| format!("0x{scope:04x} (unknown)"), str::to_owned);
                *regions.entry(label).or_default() += 1;
            }
            if info.payload_type == 0x05 && seen_messages.insert(payload.to_vec()) {
                group_messages += 1;
                let label = match keys.decrypt_group(info.payload_type, payload) {
                    Some(group) => {
                        decrypted += 1;
                        if let Some((sender, _)) = group.text.split_once(": ") {
                            *senders.entry(sender.to_owned()).or_default() += 1;
                        }
                        meshcore_channel_label(&group.channel)
                    }
                    None => format!(
                        "hash 0x{:02x} (no key)",
                        info.channel_hash.unwrap_or_default()
                    ),
                };
                *channels.entry(label).or_default() += 1;
            }
        }
        cards.push(card(
            "Group messages",
            group_messages,
            format!("distinct, in 24h · {decrypted} decrypted"),
        ));
        cards.push(card(
            "Region-scoped",
            scoped,
            "frames with a region code, in 24h".to_owned(),
        ));
        if with_path > 0 {
            cards.push(StatCard {
                label: "Average hops".to_owned(),
                value: hops as f64 / with_path as f64,
                unit: "decimal",
                sub: format!("per flood frame as heard, {with_path} frames in 24h"),
            });
        }

        tables.push(pie("Payload types", "all stored frames", second_grouping));
        tables.push(pie("Routes", "all stored frames", first_grouping));
        tables.push(pie(
            "Channels",
            "distinct group messages, last 24 hours",
            count_buckets(channels, 30),
        ));
        tables.push(table(
            "Top chat senders",
            "decrypted group messages, last 24 hours",
            count_buckets(senders, 15),
        ));
        tables.push(table(
            "Busiest repeaters",
            "appearances in frame paths, last 24 hours",
            count_buckets(relays, 20),
        ));
        tables.push(table(
            "Regions",
            "region-scoped frames, last 24 hours",
            count_buckets(regions, 15),
        ));
    } else {
        cards.push(card(
            "Destinations",
            nodes,
            format!("announced · {nodes_24h} heard in 24h · {named} named"),
        ));
        tables.push(pie("Packet types", "all stored frames", first_grouping));
        tables.push(pie("Contexts", "all stored frames", second_grouping));
    }
    tables.push(table("Heard by", "all stored frames", gateways));

    Ok(JrawStats {
        kind,
        cards,
        hourly,
        tables,
    })
}

const RECEPTION_COLUMNS: &str = "id, packet_id, from_num, to_num, relay_node, channel,
    receiver, source, via_mqtt, rx_time, rx_snr, rx_rssi, rx_frequency_error,
    rx_coding_rate, hop_limit, hop_start, received_at, channel_name, decrypted";

fn reception_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Reception> {
    Ok(Reception {
        id: row.get(0)?,
        packet_id: row.get(1)?,
        from_num: row.get(2)?,
        to_num: row.get(3)?,
        relay_node: row.get(4)?,
        channel: row.get(5)?,
        receiver: row.get(6)?,
        source: row.get(7)?,
        via_mqtt: row.get::<_, i64>(8)? != 0,
        rx_time: row.get(9)?,
        rx_snr: row.get(10)?,
        rx_rssi: row.get(11)?,
        rx_frequency_error: row.get(12)?,
        rx_coding_rate: row.get(13)?,
        hop_limit: row.get(14)?,
        hop_start: row.get(15)?,
        received_at: row.get(16)?,
        channel_name: row.get(17)?,
        decrypted: row.get::<_, i64>(18)? != 0,
    })
}

fn receptions(connection: &Connection, from_num: i64, packet_id: i64) -> Result<Vec<Reception>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {RECEPTION_COLUMNS}
         FROM packet_receptions
         WHERE from_num = ?1 AND packet_id = ?2
         ORDER BY rx_snr DESC, id"
    ))?;
    let rows = statement.query_map(params![from_num, packet_id], reception_from_row)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn recent_receptions(connection: &Connection, limit: usize) -> Result<Vec<Reception>> {
    let limit = limit.clamp(1, 500) as i64;
    let mut statement = connection.prepare(&format!(
        "SELECT {RECEPTION_COLUMNS}
         FROM packet_receptions
         ORDER BY id DESC LIMIT ?1"
    ))?;
    let rows = statement.query_map(params![limit], reception_from_row)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn node_receptions(connection: &Connection, from_num: i64, limit: usize) -> Result<Vec<Reception>> {
    let limit = limit.clamp(1, 2000) as i64;
    let mut statement = connection.prepare(&format!(
        "SELECT {RECEPTION_COLUMNS}
         FROM packet_receptions
         WHERE from_num = ?1
         ORDER BY received_at DESC, id DESC LIMIT ?2"
    ))?;
    let rows = statement.query_map(params![from_num, limit], reception_from_row)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn metric_stats(
    min: Option<f64>,
    max: Option<f64>,
    sum: Option<f64>,
    sum_squares: Option<f64>,
    count: i64,
) -> MetricStats {
    if count <= 0 {
        return MetricStats {
            min: None,
            max: None,
            avg: None,
            stddev: None,
            count: 0,
        };
    }
    let count_f = count as f64;
    let sum = sum.unwrap_or(0.0);
    let avg = sum / count_f;
    let variance = (sum_squares.unwrap_or(0.0) / count_f - avg * avg).max(0.0);
    MetricStats {
        min,
        max,
        avg: Some(avg),
        stddev: Some(variance.sqrt()),
        count,
    }
}

fn relay_series(connection: &Connection, receiver: &str, limit: usize) -> Result<Vec<RelaySample>> {
    let limit = limit.clamp(1, 2000) as i64;
    let mut statement = connection.prepare(
        "SELECT relay_node & 255, received_at, rx_rssi, rx_snr, rx_frequency_error
         FROM packet_receptions
         WHERE receiver = ?1
         ORDER BY received_at DESC, id DESC LIMIT ?2",
    )?;
    let rows = statement.query_map(params![receiver, limit], |row| {
        Ok(RelaySample {
            relay_node: row.get(0)?,
            received_at: row.get(1)?,
            rx_rssi: row.get(2)?,
            rx_snr: row.get(3)?,
            rx_frequency_error: row.get(4)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn relay_stats(connection: &Connection, receiver: &str, limit: usize) -> Result<Vec<RelayStats>> {
    let limit = limit.clamp(1, 200) as i64;
    let mut statement = connection.prepare(
        "SELECT relay_node & 255 AS relay, COUNT(*),
                MIN(rx_rssi), MAX(rx_rssi), SUM(rx_rssi), SUM(rx_rssi * rx_rssi), COUNT(rx_rssi),
                MIN(rx_snr), MAX(rx_snr), SUM(rx_snr), SUM(rx_snr * rx_snr), COUNT(rx_snr),
                MIN(rx_frequency_error), MAX(rx_frequency_error),
                SUM(rx_frequency_error), SUM(rx_frequency_error * rx_frequency_error),
                COUNT(rx_frequency_error)
         FROM packet_receptions
         WHERE receiver = ?1
         GROUP BY relay
         ORDER BY COUNT(*) DESC, relay
         LIMIT ?2",
    )?;
    let rows = statement.query_map(params![receiver, limit], |row| {
        let packets: i64 = row.get(1)?;
        Ok(RelayStats {
            relay_node: row.get(0)?,
            packets,
            rssi: metric_stats(
                row.get::<_, Option<f64>>(2)?,
                row.get::<_, Option<f64>>(3)?,
                row.get::<_, Option<f64>>(4)?,
                row.get::<_, Option<f64>>(5)?,
                row.get::<_, i64>(6)?,
            ),
            snr: metric_stats(
                row.get::<_, Option<f64>>(7)?,
                row.get::<_, Option<f64>>(8)?,
                row.get::<_, Option<f64>>(9)?,
                row.get::<_, Option<f64>>(10)?,
                row.get::<_, i64>(11)?,
            ),
            frequency_error: metric_stats(
                row.get::<_, Option<f64>>(12)?,
                row.get::<_, Option<f64>>(13)?,
                row.get::<_, Option<f64>>(14)?,
                row.get::<_, Option<f64>>(15)?,
                row.get::<_, i64>(16)?,
            ),
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

const NODE_COLUMNS: &str = "n.num, n.node_id, n.long_name, n.short_name, n.hw_model, n.role,
    n.last_heard, n.snr, n.hops_away, n.via_mqtt, n.battery_level, n.voltage,
    n.channel_utilization, n.air_util_tx, n.latitude_i, n.longitude_i, n.altitude,
    n.public_key, n.updated_at, n.source,
    lp.channel AS last_channel,
    COALESCE(lp.channel_name, '') AS last_channel_name,
    lp.hop_start AS last_hop_start,
    lp.hop_limit AS last_hop_limit,
    COALESCE((SELECT GROUP_CONCAT(DISTINCT s.receiver) FROM reception_summary s
              WHERE s.from_num = n.num), '') AS gateways";

/// Nodes joined with their most recent packet (one index probe per node).
const NODE_FROM: &str = "nodes n
    LEFT JOIN packets lp ON lp.id = (
        SELECT p.id FROM packets p WHERE p.from_num = n.num
        ORDER BY p.received_at DESC, p.id DESC LIMIT 1)";

fn node_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Node> {
    let hw_model: Option<i64> = row.get(4)?;
    Ok(Node {
        num: row.get(0)?,
        node_id: row.get(1)?,
        long_name: row.get(2)?,
        short_name: row.get(3)?,
        hw_model,
        hardware: hardware_name(hw_model),
        role: row.get(5)?,
        last_heard: row.get(6)?,
        snr: row.get(7)?,
        hops_away: row.get(8)?,
        via_mqtt: row.get::<_, i64>(9)? != 0,
        battery_level: row.get(10)?,
        voltage: row.get(11)?,
        channel_utilization: row.get(12)?,
        air_util_tx: row.get(13)?,
        latitude_i: row.get(14)?,
        longitude_i: row.get(15)?,
        altitude: row.get(16)?,
        public_key: row.get::<_, Option<Vec<u8>>>(17)?.map(|key| hex(&key)),
        updated_at: row.get(18)?,
        source: row.get(19)?,
        channel: row.get(20)?,
        channel_name: row.get(21)?,
        hop_start: row.get(22)?,
        hop_limit: row.get(23)?,
        gateways: row.get(24)?,
    })
}

fn node_names(connection: &Connection) -> Result<Vec<NodeName>> {
    let mut statement = connection.prepare(
        "SELECT num, node_id, long_name, short_name FROM nodes
         ORDER BY last_heard DESC, num",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(NodeName {
            num: row.get(0)?,
            node_id: row.get(1)?,
            long_name: row.get(2)?,
            short_name: row.get(3)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn mqtt_gateways(connection: &Connection, limit: usize) -> Result<Vec<MqttGateway>> {
    let limit = limit.clamp(1, 1000) as i64;
    let mut statement = connection.prepare(
        "WITH packet_gateways(receiver, packets, last_heard) AS (
             SELECT receiver, SUM(receptions), MAX(last_heard)
             FROM reception_summary
             WHERE source = 'mqtt' AND receiver <> ''
             GROUP BY receiver
         ),
         raw_gateways(receiver, packets, last_heard) AS (
             SELECT printf('!%08x', gateway), COUNT(*), MAX(received_at)
             FROM raw_frames r
             WHERE source = 'mqtt' AND gateway <> 0
               AND NOT EXISTS (
                   SELECT 1 FROM packet_gateways g
                   WHERE g.receiver = printf('!%08x', r.gateway)
               )
             GROUP BY gateway
         ),
         gateways AS (
             SELECT * FROM packet_gateways
             UNION ALL
             SELECT * FROM raw_gateways
         )
         SELECT g.receiver, g.packets, g.last_heard,
                n.num, n.node_id, n.long_name, n.short_name, n.hw_model
         FROM gateways g
         LEFT JOIN nodes n ON n.node_id = g.receiver
         ORDER BY g.last_heard DESC, g.receiver
         LIMIT ?1",
    )?;
    let rows = statement.query_map(params![limit], |row| {
        let hw_model: Option<i64> = row.get(7)?;
        Ok(MqttGateway {
            receiver: row.get(0)?,
            packets: row.get(1)?,
            last_heard: row.get(2)?,
            num: row.get(3)?,
            node_id: row.get(4)?,
            long_name: row.get(5)?,
            short_name: row.get(6)?,
            hardware: hardware_name(hw_model),
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn packet_list(connection: &Connection, filter: &PacketFilter) -> Result<Vec<PacketListEntry>> {
    let limit = filter.limit.clamp(1, 2000) as i64;
    let decrypted = filter.decrypted.map(i64::from);
    let mut statement = connection.prepare(
        "SELECT p.id, p.packet_id, p.from_num,
                COALESCE(NULLIF(fn.long_name, ''), NULLIF(fn.short_name, ''),
                         printf('!%08x', p.from_num)),
                p.to_num,
                CASE WHEN p.to_num = 4294967295 THEN 'broadcast'
                     ELSE COALESCE(NULLIF(tn.long_name, ''), NULLIF(tn.short_name, ''),
                                   printf('!%08x', p.to_num)) END,
                p.relay_node, p.channel, p.channel_name, p.portnum, p.bytes,
                p.transport, p.via_mqtt, p.source, p.decrypted, p.rx_time,
                p.rx_snr, p.rx_rssi, p.received_at, COALESCE(p.reception_count, 0),
                COALESCE(p.gateway_count, 0),
                COALESCE((SELECT GROUP_CONCAT(DISTINCT r.receiver)
                          FROM packet_receptions r
                          WHERE r.from_num = p.from_num AND r.packet_id = p.packet_id), ''),
                COALESCE((SELECT m.text FROM messages m
                          WHERE m.from_num = p.from_num AND m.packet_id = p.packet_id
                          LIMIT 1), '')
         FROM packets p
         LEFT JOIN nodes fn ON fn.num = p.from_num
         LEFT JOIN nodes tn ON tn.num = p.to_num
         WHERE p.transport <> 0
           AND (?1 IS NULL OR p.portnum = ?1)
           AND (?2 IS NULL OR EXISTS (
               SELECT 1 FROM packet_receptions gr
               WHERE gr.from_num = p.from_num AND gr.packet_id = p.packet_id
                 AND gr.receiver = ?2))
           AND (?3 IS NULL OR ((?3 GLOB '#*' AND p.channel = CAST(SUBSTR(?3, 2) AS INTEGER))
                               OR p.channel_name = ?3))
           AND (?4 IS NULL OR p.source = ?4)
           AND (?5 IS NULL OR p.decrypted = ?5)
         ORDER BY p.received_at DESC, p.id DESC
         LIMIT ?6",
    )?;
    let rows = statement.query_map(
        params![
            filter.portnum,
            filter.gateway.as_deref(),
            filter.channel.as_deref(),
            filter.source.as_deref(),
            decrypted,
            limit
        ],
        |row| {
            let portnum: Option<i64> = row.get(9)?;
            let transport: i64 = row.get(11)?;
            Ok(PacketListEntry {
                id: row.get(0)?,
                packet_id: row.get(1)?,
                from_num: row.get(2)?,
                from_name: row.get(3)?,
                to_num: row.get(4)?,
                to_name: row.get(5)?,
                relay_node: row.get(6)?,
                channel: row.get(7)?,
                channel_name: row.get(8)?,
                portnum,
                portnum_name: portnum
                    .map(portnum_label)
                    .unwrap_or_else(|| "Encrypted".to_owned()),
                contents: row.get(22)?,
                bytes: row.get(10)?,
                transport,
                transport_name: transport_label(transport),
                via_mqtt: row.get::<_, i64>(12)? != 0,
                source: row.get(13)?,
                decrypted: row.get::<_, i64>(14)? != 0,
                rx_time: row.get(15)?,
                rx_snr: row.get(16)?,
                rx_rssi: row.get(17)?,
                received_at: row.get(18)?,
                reception_count: row.get(19)?,
                gateway_count: row.get(20)?,
                gateways: row.get(21)?,
            })
        },
    )?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn jraw_nodes(connection: &Connection, kind: Option<i64>, limit: usize) -> Result<Vec<JrawNode>> {
    let limit = limit.clamp(1, 2000) as i64;
    let mut statement = connection.prepare(
        "SELECT j.kind, j.node_hash, j.name, j.node_type, j.public_key,
                j.first_heard, j.last_heard, j.frames, j.last_gateway,
                COALESCE(NULLIF(n.long_name, ''), NULLIF(n.short_name, ''),
                         printf('!%08x', j.last_gateway)),
                j.latitude, j.longitude
         FROM jraw_nodes j
         LEFT JOIN nodes n ON n.num = j.last_gateway
         WHERE (?1 IS NULL OR j.kind = ?1)
         ORDER BY j.last_heard DESC, j.kind, j.node_hash LIMIT ?2",
    )?;
    let rows = statement.query_map(params![kind, limit], |row| {
        let kind: i64 = row.get(0)?;
        let gateway: i64 = row.get(8)?;
        Ok(JrawNode {
            kind,
            kind_name: if kind == 1 { "MeshCore" } else { "Reticulum" }.to_owned(),
            node_hash: row.get(1)?,
            name: row.get(2)?,
            node_type: row.get(3)?,
            public_key: row.get::<_, Option<Vec<u8>>>(4)?.map(|key| hex(&key)),
            first_heard: row.get(5)?,
            last_heard: row.get(6)?,
            frames: row.get(7)?,
            gateway,
            gateway_id: format!("!{:08x}", gateway as u32),
            gateway_name: row.get(9)?,
            latitude: row.get(10)?,
            longitude: row.get(11)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn packet_filters(connection: &Connection) -> Result<PacketFilterOptions> {
    let mut portnums = Vec::new();
    let mut statement = connection.prepare(
        "SELECT portnum, COUNT(*) FROM packets
         WHERE transport <> 0 AND portnum IS NOT NULL
         GROUP BY portnum ORDER BY COUNT(*) DESC, portnum",
    )?;
    let rows = statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
    for row in rows {
        let (portnum, count) = row?;
        portnums.push(PacketFilterOption {
            value: portnum.to_string(),
            label: portnum_label(portnum),
            count,
        });
    }

    let mut gateways = Vec::new();
    let mut statement = connection.prepare(
        "SELECT r.receiver,
                COALESCE(NULLIF(n.long_name, ''), NULLIF(n.short_name, ''), r.receiver),
                r.receptions
         FROM (SELECT receiver, SUM(receptions) AS receptions
               FROM reception_summary WHERE receiver <> ''
               GROUP BY receiver) r
         LEFT JOIN nodes n ON n.node_id = r.receiver
         ORDER BY r.receptions DESC, r.receiver",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;
    for row in rows {
        let (receiver, label, count) = row?;
        gateways.push(PacketFilterOption {
            value: receiver,
            label,
            count,
        });
    }

    Ok(PacketFilterOptions { portnums, gateways })
}

fn direct_nodes(connection: &Connection, receiver: &str, limit: usize) -> Result<Vec<DirectNode>> {
    let limit = limit.clamp(1, 500) as i64;
    let mut statement = connection.prepare(
        "SELECT n.num, n.node_id, n.long_name, n.short_name, n.hw_model, n.role,
                MAX(r.rx_snr), MAX(r.rx_rssi), COUNT(*), n.last_heard
         FROM packet_receptions r
         JOIN packets p ON p.from_num = r.from_num AND p.packet_id = r.packet_id
         JOIN nodes n ON n.num = r.from_num
         WHERE r.receiver = ?1 AND p.transport <> 0
           AND r.hop_start IS NOT NULL AND r.hop_start = r.hop_limit
         GROUP BY n.num
         ORDER BY n.last_heard DESC, n.num
         LIMIT ?2",
    )?;
    let rows = statement.query_map(params![receiver, limit], |row| {
        let hw_model: Option<i64> = row.get(4)?;
        Ok(DirectNode {
            num: row.get(0)?,
            node_id: row.get(1)?,
            long_name: row.get(2)?,
            short_name: row.get(3)?,
            hardware: hardware_name(hw_model),
            role: row.get(5)?,
            snr: row.get(6)?,
            rssi: row.get(7)?,
            packets: row.get(8)?,
            last_heard: row.get(9)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn traceroutes(connection: &Connection, limit: usize) -> Result<Vec<Traceroute>> {
    let limit = limit.clamp(1, 500) as i64;
    let mut statement = connection.prepare(
        "SELECT id, packet_id, from_num, to_num, channel, request_id, rx_time,
                route, snr_towards, route_back, snr_back, source, receiver, received_at,
                COALESCE(decrypted, 0)
         FROM traceroutes ORDER BY received_at DESC, id DESC LIMIT ?1",
    )?;
    let rows = statement.query_map(params![limit], |row| {
        Ok(Traceroute {
            id: row.get(0)?,
            packet_id: row.get(1)?,
            from_num: row.get(2)?,
            to_num: row.get(3)?,
            channel: row.get(4)?,
            request_id: row.get(5)?,
            rx_time: row.get(6)?,
            route: serde_json::from_str(&row.get::<_, String>(7)?).unwrap_or_default(),
            snr_towards: serde_json::from_str(&row.get::<_, String>(8)?).unwrap_or_default(),
            route_back: serde_json::from_str(&row.get::<_, String>(9)?).unwrap_or_default(),
            snr_back: serde_json::from_str(&row.get::<_, String>(10)?).unwrap_or_default(),
            source: row.get(11)?,
            receiver: row.get(12)?,
            received_at: row.get(13)?,
            decrypted: row.get::<_, i64>(14)? != 0,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn node_packets(connection: &Connection, num: i64, limit: usize) -> Result<Vec<PacketRow>> {
    let limit = limit.clamp(1, 1000) as i64;
    let mut statement = connection.prepare(
        "SELECT p.id, p.packet_id, p.from_num, p.to_num, p.relay_node, p.channel,
                p.channel_name, p.portnum, p.bytes, p.transport, p.rx_time,
                p.rx_snr, p.rx_rssi, p.via_mqtt, p.source, p.received_at,
                COALESCE(p.decrypted, 0), p.hop_start, p.hop_limit,
                COALESCE((SELECT m.text FROM messages m
                          WHERE m.from_num = p.from_num AND m.packet_id = p.packet_id
                          LIMIT 1), '')
         FROM packets p
         WHERE p.from_num = ?1
         ORDER BY p.received_at DESC, p.id DESC LIMIT ?2",
    )?;
    let rows = statement.query_map(params![num, limit], |row| {
        let portnum: Option<i64> = row.get(7)?;
        let transport: i64 = row.get(9)?;
        Ok(PacketRow {
            id: row.get(0)?,
            packet_id: row.get(1)?,
            from_num: row.get(2)?,
            to_num: row.get(3)?,
            relay_node: row.get(4)?,
            channel: row.get(5)?,
            channel_name: row.get(6)?,
            portnum,
            portnum_name: portnum.map(portnum_label).unwrap_or_else(|| "—".to_owned()),
            bytes: row.get(8)?,
            transport,
            transport_name: transport_label(transport),
            rx_time: row.get(10)?,
            rx_snr: row.get(11)?,
            rx_rssi: row.get(12)?,
            via_mqtt: row.get::<_, i64>(13)? != 0,
            source: row.get(14)?,
            received_at: row.get(15)?,
            decrypted: row.get::<_, i64>(16)? != 0,
            hop_start: row.get(17)?,
            hop_limit: row.get(18)?,
            contents: row.get(19)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn nodes(connection: &Connection) -> Result<Vec<Node>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {NODE_COLUMNS} FROM {NODE_FROM} ORDER BY n.last_heard DESC, n.num"
    ))?;
    let rows = statement.query_map([], node_from_row)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn node(connection: &Connection, num: i64) -> Result<Option<Node>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {NODE_COLUMNS} FROM {NODE_FROM} WHERE n.num = ?1"
    ))?;
    let mut rows = statement.query_map(params![num], node_from_row)?;
    Ok(rows.next().transpose()?)
}

/// Known MeshCore nodes, for turning the short hashes in frames into names.
struct MeshCoreDirectory {
    /// (public key hex, name, forwards packets).
    nodes: Vec<(String, String, bool)>,
}

impl MeshCoreDirectory {
    fn load(connection: &Connection) -> Result<Self> {
        let mut statement = connection.prepare_cached(
            "SELECT public_key, name, node_type FROM jraw_nodes
             WHERE kind = 1 AND public_key IS NOT NULL AND name IS NOT NULL AND name <> ''
             ORDER BY last_heard DESC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                hex(&row.get::<_, Vec<u8>>(0)?),
                row.get::<_, String>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        })?;
        // One node can have several rows (one per hash size it was heard with).
        let mut seen = HashSet::new();
        let mut nodes = Vec::new();
        for row in rows {
            let (key, name, node_type) = row?;
            if seen.insert(key.clone()) {
                // Repeaters (2) and room servers (3) forward packets.
                nodes.push((key, name, matches!(node_type, Some(2 | 3))));
            }
        }
        Ok(Self { nodes })
    }

    /// Nodes whose public key starts with `hash`. Short hashes collide, so
    /// every candidate is reported rather than a guess.
    fn resolve(&self, hash: &str, forwarders_only: bool) -> HashMatch {
        let mut names = Vec::new();
        let mut candidates = 0;
        for (key, name, forwards) in &self.nodes {
            if (*forwards || !forwarders_only) && !hash.is_empty() && key.starts_with(hash) {
                candidates += 1;
                if names.len() < MAX_HASH_NAMES {
                    names.push(name.clone());
                }
            }
        }
        HashMatch {
            hash: hash.to_owned(),
            names,
            candidates,
        }
    }
}

/// What can be read from a MeshCore frame with the keys and nodes we know.
#[derive(Default)]
struct MeshCoreView {
    path: Vec<HashMatch>,
    sender: Option<HashMatch>,
    destination: Option<HashMatch>,
    region_code: Option<i64>,
    region: Option<String>,
    channel_name: Option<String>,
    channel_candidates: Vec<String>,
    text: Option<String>,
    sent_at: Option<i64>,
    decrypted: bool,
    trace_tag: Option<i64>,
    trace: Vec<TraceHop>,
    latitude: Option<f64>,
    longitude: Option<f64>,
}

fn meshcore_view(
    info: &MeshCoreInfo,
    frame: &[u8],
    keys: &MeshCoreKeys,
    directory: &MeshCoreDirectory,
) -> MeshCoreView {
    let payload = info.payload(frame);
    let mut view = MeshCoreView {
        path: info
            .path_hashes()
            .iter()
            .map(|hash| directory.resolve(hash, true))
            .collect(),
        sent_at: info.advert_timestamp.map(i64::from),
        ..MeshCoreView::default()
    };
    // An advert names its own sender; other frames only carry a short hash.
    if info.payload_type != 0x04 {
        view.sender = info
            .sender_hash
            .as_deref()
            .map(|hash| directory.resolve(hash, false));
    }
    view.destination = info
        .destination_hash
        .as_deref()
        .map(|hash| directory.resolve(hash, false));

    if let Some([scope, _]) = info.transport_codes {
        view.region_code = Some(i64::from(scope));
        view.region = keys
            .region_for(info.payload_type, payload, scope)
            .map(str::to_owned);
    }

    if matches!(info.payload_type, 0x05 | 0x06) {
        if let Some(message) = keys.decrypt_group(info.payload_type, payload) {
            view.channel_name = Some(message.channel);
            view.text = Some(message.text);
            view.sent_at = message.timestamp.map(i64::from);
            view.decrypted = true;
        } else if let Some(hash) = info.channel_hash {
            view.channel_candidates = keys.channel_names(hash);
        }
    }

    if let Some(trace) = &info.trace {
        view.trace_tag = Some(i64::from(trace.tag));
        view.trace = trace
            .route
            .iter()
            .enumerate()
            .map(|(index, hash)| TraceHop {
                node: directory.resolve(hash, true),
                snr: trace
                    .snr_quarters
                    .get(index)
                    .map(|quarters| f64::from(*quarters) / 4.0),
            })
            .collect();
    }

    if let Some((latitude, longitude)) = info.advert_position {
        view.latitude = Some(f64::from(latitude) / 1e6);
        view.longitude = Some(f64::from(longitude) / 1e6);
    }
    view
}

/// Which raw frames to list. Everything unset matches all frames.
#[derive(Debug, Clone, Default)]
pub struct RawFilter {
    pub kind: Option<i64>,
    pub payload_type: Option<i64>,
    pub route_type: Option<i64>,
    /// MeshCore channel hash (group frames).
    pub channel_hash: Option<i64>,
    /// MeshCore group frames that were (`true`) or were not (`false`) decrypted.
    pub decrypted: Option<bool>,
    /// MeshCore region: `any` scoped frame, `unknown` code, or a region name.
    pub region: Option<String>,
    /// Text to find in contents, names, channels, regions and hashes.
    pub search: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct RawFilterOptions {
    pub payloads: Vec<PacketFilterOption>,
    pub routes: Vec<PacketFilterOption>,
    pub channels: Vec<PacketFilterOption>,
    pub regions: Vec<PacketFilterOption>,
}

fn raw_filter_options(
    connection: &Connection,
    kind: i64,
    keys: &MeshCoreKeys,
) -> Result<RawFilterOptions> {
    let grouped = |sql: &str| -> Result<Vec<(i64, String, i64)>> {
        let mut statement = connection.prepare_cached(sql)?;
        let rows = statement.query_map(params![kind], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    };
    let option = |(value, label, count): (i64, String, i64)| PacketFilterOption {
        value: value.to_string(),
        label,
        count,
    };
    let mut out = RawFilterOptions {
        payloads: grouped(
            "SELECT payload_type, COALESCE(MAX(payload_name), 'unknown'), COUNT(*)
             FROM raw_frames WHERE kind = ?1 AND payload_type IS NOT NULL
             GROUP BY payload_type ORDER BY 3 DESC",
        )?
        .into_iter()
        .map(option)
        .collect(),
        routes: grouped(
            "SELECT route_type, COALESCE(MAX(route_name), 'unknown'), COUNT(*)
             FROM raw_frames WHERE kind = ?1 AND route_type IS NOT NULL
             GROUP BY route_type ORDER BY 3 DESC",
        )?
        .into_iter()
        .map(option)
        .collect(),
        ..RawFilterOptions::default()
    };
    if kind == 1 {
        out.channels = grouped(
            "SELECT channel_hash, '', COUNT(*) FROM raw_frames
             WHERE kind = ?1 AND channel_hash IS NOT NULL
             GROUP BY channel_hash ORDER BY 3 DESC",
        )?
        .into_iter()
        .map(|(hash, _, count)| {
            let names: Vec<String> = keys
                .channel_names(hash as u8)
                .iter()
                .map(|name| meshcore_channel_label(name))
                .collect();
            let label = if names.is_empty() {
                format!("0x{hash:02x} (no key)")
            } else {
                format!("{} · 0x{hash:02x}", names.join(" | "))
            };
            option((hash, label, count))
        })
        .collect();
        // Named channels first, then unknown hashes, each by frame count.
        out.channels
            .sort_by_key(|channel| (channel.label.ends_with("(no key)"), -channel.count));

        let scoped: i64 = connection.query_row(
            "SELECT COUNT(*) FROM raw_frames WHERE kind = 1 AND route_type IN (0, 3)",
            [],
            |row| row.get(0),
        )?;
        let region = |value: &str, label: &str, count: i64| PacketFilterOption {
            value: value.to_owned(),
            label: label.to_owned(),
            count,
        };
        out.regions.push(region("any", "Any region-scoped", scoped));
        for known in keys.regions() {
            // Counting per region would mean checking every frame's code.
            out.regions.push(region(&known.name, &known.name, -1));
        }
        out.regions.push(region("unknown", "Unknown region code", -1));
    }
    Ok(out)
}

fn contains_folded(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(needle)
}

/// `needle` is already lowercase.
fn raw_frame_matches(frame: &RawFrame, needle: &str) -> bool {
    let text = |value: &Option<String>| value.as_deref().is_some_and(|v| contains_folded(v, needle));
    let hash = |found: &HashMatch| {
        contains_folded(&found.hash, needle)
            || found.names.iter().any(|name| contains_folded(name, needle))
    };
    text(&frame.payload_text)
        || text(&frame.node_name)
        || text(&frame.payload_name)
        || text(&frame.region)
        || text(&frame.sender_hash)
        || text(&frame.destination_hash)
        || text(&frame.public_key)
        || frame
            .channel_name
            .as_deref()
            .is_some_and(|name| contains_folded(&meshcore_channel_label(name), needle))
        || contains_folded(&frame.gateway_id, needle)
        || frame.path.iter().any(hash)
        || frame.trace.iter().any(|hop| hash(&hop.node))
        || frame.sender.as_ref().is_some_and(hash)
        || frame.destination.as_ref().is_some_and(hash)
}

fn raw_frames(
    connection: &Connection,
    filter: &RawFilter,
    limit: usize,
    keys: &MeshCoreKeys,
) -> Result<Vec<RawFrame>> {
    let limit = limit.clamp(1, 500);
    let kind = filter.kind;
    let search = filter
        .search
        .as_deref()
        .map(|text| text.trim().to_lowercase())
        .filter(|text| !text.is_empty());
    let region = filter.region.as_deref().filter(|name| !name.is_empty());
    // Decryption state, region names and text are only known after parsing a
    // frame, so those filters read further back than `limit` rows.
    let parsed_filters = filter.decrypted.is_some() || region.is_some() || search.is_some();
    let scan = if parsed_filters {
        RAW_FILTER_SCAN
    } else {
        limit as i64
    };
    let directory = MeshCoreDirectory::load(connection)?;
    let mut statement = connection.prepare(
        "SELECT id, kind, source, gateway, sequence, channel, rx_time, rx_rssi, rx_snr,
                frequency_error, coding_rate, frame, frame_len, route_type,
                payload_type, route_name, payload_name, path_hex, sender_hash,
                destination_hash, channel_hash, node_name, public_key, received_at,
                COALESCE(decrypted, 0)
         FROM raw_frames
         WHERE (?1 IS NULL OR kind = ?1)
           AND (?3 IS NULL OR payload_type = ?3)
           AND (?4 IS NULL OR route_type = ?4)
           AND (?5 IS NULL OR channel_hash = ?5)
           AND (?6 = 0 OR payload_type IN (5, 6))
           AND (?7 = 0 OR route_type IN (0, 3))
         ORDER BY id DESC LIMIT ?2",
    )?;
    let build = |row: &rusqlite::Row<'_>| -> rusqlite::Result<RawFrame> {
        let kind: i64 = row.get(1)?;
        let frame_bytes = row.get::<_, Vec<u8>>(11)?;
        let meshcore = if kind == 1 {
            parse_meshcore_frame(&frame_bytes)
        } else {
            None
        };
        let view = meshcore
            .as_ref()
            .map(|info| meshcore_view(info, &frame_bytes, keys, &directory))
            .unwrap_or_default();
        Ok(RawFrame {
            id: row.get(0)?,
            kind,
            kind_name: match kind {
                1 => "jencore",
                2 => "jenrnode",
                3 => "meshtastic",
                _ => "unknown",
            }
            .to_owned(),
            source: row.get(2)?,
            gateway: row.get(3)?,
            gateway_id: format!("!{:08x}", row.get::<_, i64>(3)? as u32),
            sequence: row.get(4)?,
            channel: row.get(5)?,
            rx_time: row.get(6)?,
            rx_rssi: row.get(7)?,
            rx_snr: row.get(8)?,
            frequency_error: row.get(9)?,
            coding_rate: row.get(10)?,
            frame_len: row.get(12)?,
            frame_hex: hex(&frame_bytes),
            route_type: row.get(13)?,
            payload_type: row.get(14)?,
            route_name: row.get(15)?,
            payload_name: row.get(16)?,
            path_hex: row.get(17)?,
            path_hash_size: meshcore.as_ref().map(|info| i64::from(info.path_hash_size)),
            payload_text: view
                .text
                .or_else(|| meshcore.as_ref().and_then(|info| info.payload_text.clone())),
            node_type: meshcore
                .as_ref()
                .and_then(|info| info.node_type)
                .map(i64::from),
            // Frames stored by an older build may lack hashes the parser reads now.
            sender_hash: row.get::<_, Option<String>>(18)?.or_else(|| {
                meshcore
                    .as_ref()
                    .and_then(|info| info.sender_hash.clone())
            }),
            destination_hash: row.get::<_, Option<String>>(19)?.or_else(|| {
                meshcore
                    .as_ref()
                    .and_then(|info| info.destination_hash.clone())
            }),
            channel_hash: row.get(20)?,
            node_name: row.get(21)?,
            public_key: row.get::<_, Option<Vec<u8>>>(22)?.map(|key| hex(&key)),
            received_at: row.get(23)?,
            decrypted: row.get::<_, i64>(24)? != 0 || view.decrypted,
            path: view.path,
            sender: view.sender,
            destination: view.destination,
            region_code: view.region_code,
            region: view.region,
            channel_name: view.channel_name,
            channel_candidates: view.channel_candidates,
            sent_at: view.sent_at,
            trace_tag: view.trace_tag,
            trace: view.trace,
            latitude: view.latitude,
            longitude: view.longitude,
        })
    };
    let mut rows = statement.query(params![
        kind,
        scan,
        filter.payload_type,
        filter.route_type,
        filter.channel_hash,
        filter.decrypted.is_some(),
        region.is_some(),
    ])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let frame = build(row)?;
        if filter
            .decrypted
            .is_some_and(|wanted| frame.decrypted != wanted)
        {
            continue;
        }
        let region_matches = match region {
            None | Some("any") => true,
            Some("unknown") => frame.region.is_none(),
            Some(name) => frame.region.as_deref() == Some(name),
        };
        if !region_matches {
            continue;
        }
        if search
            .as_deref()
            .is_some_and(|needle| !raw_frame_matches(&frame, needle))
        {
            continue;
        }
        out.push(frame);
        if out.len() >= limit {
            break;
        }
    }
    Ok(out)
}

fn channels(connection: &Connection) -> Result<Vec<ChannelInfo>> {
    let mut statement = connection.prepare(
        "SELECT MIN(p.channel) AS channel,
                CASE WHEN p.channel_name <> '' THEN p.channel_name ELSE '' END AS name,
                CASE WHEN p.channel_name <> '' THEN p.channel_name
                     ELSE '#' || p.channel END AS channel_key
         FROM packets p
         GROUP BY channel_key
         ORDER BY name, channel",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(ChannelInfo {
            channel: row.get(0)?,
            name: row.get(1)?,
            role: 0,
            key: row.get(2)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    if out.is_empty() {
        let mut fallback = connection.prepare(
            "SELECT idx, COALESCE(name, ''), COALESCE(role, 0) FROM channels ORDER BY idx",
        )?;
        let rows = fallback.query_map([], |row| {
            let channel: i64 = row.get(0)?;
            let name: String = row.get(1)?;
            let key = if name.is_empty() {
                format!("#{channel}")
            } else {
                name.clone()
            };
            Ok(ChannelInfo {
                channel,
                name,
                role: row.get(2)?,
                key,
            })
        })?;
        for row in rows {
            out.push(row?);
        }
    }
    Ok(out)
}

fn count(connection: &Connection, sql: &str, params: impl rusqlite::Params) -> Result<i64> {
    Ok(connection.query_row(sql, params, |row| row.get(0))?)
}

fn hardware_name(value: Option<i64>) -> String {
    value
        .and_then(|value| i32::try_from(value).ok())
        .and_then(|value| pb::HardwareModel::try_from(value).ok())
        .map(|model| model.as_str_name().to_owned())
        .unwrap_or_else(|| "UNKNOWN".to_owned())
}

fn portnum_label(value: i64) -> String {
    let Ok(value) = i32::try_from(value) else {
        return format!("UNKNOWN[{value}]");
    };
    pb::PortNum::try_from(value)
        .map(|portnum| portnum.as_str_name().to_owned())
        .unwrap_or_else(|_| format!("UNKNOWN[{value}]"))
}

fn transport_label(value: i64) -> String {
    let Ok(value) = i32::try_from(value) else {
        return value.to_string();
    };
    pb::mesh_packet::TransportMechanism::try_from(value)
        .map(|transport| transport.as_str_name().to_owned())
        .unwrap_or_else(|_| format!("UNKNOWN[{value}]"))
}

const HOURLY_WINDOW_SECS: i64 = 3_600;

#[derive(Debug, Clone, Serialize)]
pub struct Stats {
    pub totals: Totals,
    pub packets_per_hour: f64,
    pub bytes_per_hour: f64,
    pub window_secs: i64,
    pub hourly: Vec<HourBucket>,
    pub portnums: Vec<CountBucket>,
    pub channels: Vec<ChannelCount>,
    pub transports: Vec<CountBucket>,
    pub top_nodes: Vec<NodeCount>,
    pub channel_list: Vec<ChannelInfo>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Totals {
    pub packets: i64,
    pub packets_24h: i64,
    pub messages: i64,
    pub messages_24h: i64,
    pub nodes: i64,
    pub raw_frames: i64,
    pub jencore_frames: i64,
    pub jenrnode_frames: i64,
    pub meshtastic_frames: i64,
    pub via_mqtt: i64,
    pub mqtt_source: i64,
    pub receptions: i64,
    pub multi_heard: i64,
    pub bytes: i64,
    pub decoded_packets: i64,
    pub opaque_packets: i64,
    pub pki_packets: i64,
    pub decrypted: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HourBucket {
    pub hour_start: i64,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CountBucket {
    pub key: i64,
    pub label: String,
    pub count: i64,
    pub percent: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChannelCount {
    pub channel: i64,
    pub name: String,
    pub count: i64,
    pub bytes: i64,
    pub packets_per_hour: f64,
    pub bytes_per_hour: f64,
    pub percent: f64,
    pub nodes: Vec<ChannelNodeCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChannelNodeCount {
    pub num: i64,
    pub name: String,
    pub count: i64,
    pub bytes: i64,
    pub percent: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeCount {
    pub num: i64,
    pub name: String,
    pub count: i64,
    pub percent: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChannelInfo {
    pub channel: i64,
    pub name: String,
    pub role: i64,
    pub key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Message {
    pub id: i64,
    pub packet_id: i64,
    pub from_num: i64,
    pub sender: String,
    pub channel: i64,
    pub channel_name: String,
    pub text: String,
    pub rx_time: i64,
    pub rx_snr: Option<f64>,
    pub rx_rssi: Option<i64>,
    pub rx_frequency_error: Option<f64>,
    pub rx_coding_rate: Option<i64>,
    pub hop_limit: Option<i64>,
    pub hop_start: Option<i64>,
    pub via_mqtt: bool,
    pub source: String,
    pub received_at: i64,
    pub reception_count: i64,
    pub gateway_count: i64,
    pub best_snr: Option<f64>,
    pub best_rssi: Option<i64>,
    pub relay_node: i64,
    pub decrypted: bool,
    /// `meshtastic` or `meshcore`.
    pub network: &'static str,
    /// Sender's own clock (MeshCore group text only).
    pub sent_at: Option<i64>,
    /// Every time the message was heard as a MeshCore frame, oldest first,
    /// with the path each copy took. Also set on a bridged Meshtastic copy.
    pub meshcore_receptions: Vec<MeshCoreReception>,
}

/// One MeshCore frame carrying a chat message.
#[derive(Debug, Clone, Serialize)]
pub struct MeshCoreReception {
    pub received_at: i64,
    pub gateway_id: String,
    pub rx_snr: Option<f64>,
    pub rx_rssi: Option<i64>,
    pub route_name: &'static str,
    pub path_hash_size: i64,
    /// Repeaters the frame passed, in order, with the nodes they match.
    pub path: Vec<HashMatch>,
}

/// Activity summary of one raw feed (MeshCore or Reticulum).
#[derive(Debug, Clone, Serialize)]
pub struct JrawStats {
    pub kind: i64,
    pub cards: Vec<StatCard>,
    pub hourly: Vec<HourBucket>,
    pub tables: Vec<StatTable>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatCard {
    pub label: String,
    pub value: f64,
    /// How to format `value`: `count`, `bytes` or `decimal`.
    pub unit: &'static str,
    pub sub: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatTable {
    pub title: String,
    /// What the counts cover (period, unit).
    pub note: String,
    pub rows: Vec<CountBucket>,
    /// Sum over every group, including those beyond `rows`.
    pub total: i64,
    /// Whether the breakdown is a share of a whole worth drawing as a pie.
    pub pie: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricStats {
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub avg: Option<f64>,
    pub stddev: Option<f64>,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayStats {
    pub relay_node: i64,
    pub packets: i64,
    pub rssi: MetricStats,
    pub snr: MetricStats,
    pub frequency_error: MetricStats,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelaySample {
    pub relay_node: i64,
    pub received_at: i64,
    pub rx_rssi: Option<f64>,
    pub rx_snr: Option<f64>,
    pub rx_frequency_error: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Reception {
    pub id: i64,
    pub packet_id: i64,
    pub from_num: i64,
    pub to_num: i64,
    pub relay_node: i64,
    pub channel: i64,
    pub receiver: String,
    pub source: String,
    pub via_mqtt: bool,
    pub rx_time: i64,
    pub rx_snr: Option<f64>,
    pub rx_rssi: Option<i64>,
    pub rx_frequency_error: Option<f64>,
    pub rx_coding_rate: Option<i64>,
    pub hop_limit: Option<i64>,
    pub hop_start: Option<i64>,
    pub received_at: i64,
    pub channel_name: String,
    pub decrypted: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MqttGateway {
    pub receiver: String,
    pub num: Option<i64>,
    pub node_id: Option<String>,
    pub long_name: Option<String>,
    pub short_name: Option<String>,
    pub hardware: String,
    pub packets: i64,
    pub last_heard: i64,
}

#[derive(Debug, Clone, Default)]
pub struct PacketFilter {
    pub portnum: Option<i64>,
    pub gateway: Option<String>,
    pub channel: Option<String>,
    pub source: Option<String>,
    pub decrypted: Option<bool>,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketListEntry {
    pub id: i64,
    pub packet_id: i64,
    pub from_num: i64,
    pub from_name: String,
    pub to_num: i64,
    pub to_name: String,
    pub relay_node: i64,
    pub channel: i64,
    pub channel_name: String,
    pub portnum: Option<i64>,
    pub portnum_name: String,
    pub contents: String,
    pub bytes: i64,
    pub transport: i64,
    pub transport_name: String,
    pub via_mqtt: bool,
    pub source: String,
    pub decrypted: bool,
    pub rx_time: i64,
    pub rx_snr: Option<f64>,
    pub rx_rssi: Option<i64>,
    pub received_at: i64,
    pub reception_count: i64,
    pub gateway_count: i64,
    pub gateways: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeName {
    pub num: i64,
    pub node_id: Option<String>,
    pub long_name: Option<String>,
    pub short_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JrawNode {
    pub kind: i64,
    pub kind_name: String,
    pub node_hash: String,
    pub name: Option<String>,
    pub node_type: Option<i64>,
    pub public_key: Option<String>,
    pub first_heard: i64,
    pub last_heard: i64,
    pub frames: i64,
    pub gateway: i64,
    pub gateway_id: String,
    pub gateway_name: String,
    /// Advertised position in degrees (MeshCore adverts only).
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketFilterOption {
    pub value: String,
    pub label: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PacketFilterOptions {
    pub portnums: Vec<PacketFilterOption>,
    pub gateways: Vec<PacketFilterOption>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectNode {
    pub num: i64,
    pub node_id: Option<String>,
    pub long_name: Option<String>,
    pub short_name: Option<String>,
    pub hardware: String,
    pub role: Option<i64>,
    pub snr: Option<f64>,
    pub rssi: Option<i64>,
    pub packets: i64,
    pub last_heard: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Traceroute {
    pub id: i64,
    pub packet_id: i64,
    pub from_num: i64,
    pub to_num: i64,
    pub channel: i64,
    pub request_id: i64,
    pub rx_time: i64,
    pub route: Vec<u32>,
    pub snr_towards: Vec<i32>,
    pub route_back: Vec<u32>,
    pub snr_back: Vec<i32>,
    pub source: String,
    pub receiver: Option<String>,
    pub received_at: i64,
    pub decrypted: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketRow {
    pub id: i64,
    pub packet_id: i64,
    pub from_num: i64,
    pub to_num: i64,
    pub relay_node: i64,
    pub channel: i64,
    pub channel_name: String,
    pub portnum: Option<i64>,
    pub portnum_name: String,
    pub bytes: i64,
    pub transport: i64,
    pub transport_name: String,
    pub rx_time: i64,
    pub rx_snr: Option<f64>,
    pub rx_rssi: Option<i64>,
    pub via_mqtt: bool,
    pub source: String,
    pub received_at: i64,
    pub decrypted: bool,
    pub hop_start: Option<i64>,
    pub hop_limit: Option<i64>,
    /// Message text for text packets, empty otherwise.
    pub contents: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Node {
    pub num: i64,
    pub node_id: Option<String>,
    pub long_name: Option<String>,
    pub short_name: Option<String>,
    pub hw_model: Option<i64>,
    pub hardware: String,
    pub role: Option<i64>,
    pub last_heard: i64,
    pub snr: Option<f64>,
    pub hops_away: Option<i64>,
    pub via_mqtt: bool,
    pub battery_level: Option<i64>,
    pub voltage: Option<f64>,
    pub channel_utilization: Option<f64>,
    pub air_util_tx: Option<f64>,
    pub latitude_i: Option<i64>,
    pub longitude_i: Option<i64>,
    pub altitude: Option<i64>,
    pub public_key: Option<String>,
    pub updated_at: i64,
    pub source: String,
    pub channel: Option<i64>,
    pub channel_name: String,
    pub hop_start: Option<i64>,
    pub hop_limit: Option<i64>,
    pub gateways: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RawFrame {
    pub id: i64,
    pub kind: i64,
    pub kind_name: String,
    pub source: String,
    pub gateway: i64,
    pub gateway_id: String,
    pub sequence: i64,
    pub channel: i64,
    pub rx_time: i64,
    pub rx_rssi: Option<i64>,
    pub rx_snr: Option<f64>,
    pub frequency_error: Option<f64>,
    pub coding_rate: Option<i64>,
    pub frame_len: i64,
    pub frame_hex: String,
    pub route_type: Option<i64>,
    pub route_name: Option<String>,
    pub payload_type: Option<i64>,
    pub payload_name: Option<String>,
    pub path_hex: Option<String>,
    pub path_hash_size: Option<i64>,
    pub payload_text: Option<String>,
    pub node_type: Option<i64>,
    pub sender_hash: Option<String>,
    pub destination_hash: Option<String>,
    pub channel_hash: Option<i64>,
    pub node_name: Option<String>,
    pub public_key: Option<String>,
    pub received_at: i64,
    pub decrypted: bool,
    /// MeshCore path entries in on-air order, with the repeaters they match.
    pub path: Vec<HashMatch>,
    pub sender: Option<HashMatch>,
    pub destination: Option<HashMatch>,
    /// Scope code of a region-scoped (transport) frame.
    pub region_code: Option<i64>,
    /// The configured region whose key produces `region_code`.
    pub region: Option<String>,
    /// Channel whose key decrypted this frame.
    pub channel_name: Option<String>,
    /// Known channels sharing the frame's hash when none of them decrypted it.
    pub channel_candidates: Vec<String>,
    /// Sender's own clock for adverts and decrypted group text.
    pub sent_at: Option<i64>,
    pub trace_tag: Option<i64>,
    /// Requested route of a TRACE frame with the SNR each hop recorded.
    pub trace: Vec<TraceHop>,
    /// Position carried by an advert, in degrees, exactly as sent.
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

/// A short node hash and the known nodes it could belong to.
#[derive(Debug, Clone, Serialize)]
pub struct HashMatch {
    pub hash: String,
    /// Up to four matching node names, most recently heard first.
    pub names: Vec<String>,
    /// How many known nodes match; above one the hash is ambiguous.
    pub candidates: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceHop {
    pub node: HashMatch,
    /// SNR in dB this hop measured; absent while the trace has not reached it.
    pub snr: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use muxtastic_core::raw_tunnel::RawTunnelSource;

    fn database() -> Arc<Database> {
        let (db, _rx) = Database::open(":memory:").expect("open in-memory db");
        db
    }

    fn text_packet(id: u32, from: u32, channel: u32, text: &str) -> pb::FromRadio {
        let data = pb::Data {
            portnum: pb::PortNum::TextMessageApp as i32,
            payload: text.as_bytes().to_vec(),
            ..Default::default()
        };
        let packet = pb::MeshPacket {
            id,
            from,
            to: 0xFFFF_FFFF,
            relay_node: 0xABCD_0002,
            channel,
            rx_time: 100,
            rx_snr: 6.5,
            rx_rssi: -70,
            hop_limit: 2,
            hop_start: 3,
            transport_mechanism: pb::mesh_packet::TransportMechanism::TransportLora as i32,
            payload_variant: Some(pb::mesh_packet::PayloadVariant::Decoded(data)),
            ..Default::default()
        };
        pb::FromRadio {
            id: 0,
            payload_variant: Some(from_radio::PayloadVariant::Packet(packet)),
        }
    }

    fn write(frame: pb::FromRadio, source: DbSource) -> DbWrite {
        DbWrite::Frame {
            frame: Box::new(frame),
            diagnostics: None,
            source,
            receiver: None,
            channel_name: None,
        }
    }

    fn write_with_diagnostics(
        frame: pb::FromRadio,
        diagnostics: NexusDiagnostics,
        source: DbSource,
    ) -> DbWrite {
        DbWrite::Frame {
            frame: Box::new(frame),
            diagnostics: Some(diagnostics),
            source,
            receiver: None,
            channel_name: None,
        }
    }

    fn write_reception(
        frame: pb::FromRadio,
        diagnostics: Option<NexusDiagnostics>,
        source: DbSource,
        receiver: &str,
    ) -> DbWrite {
        DbWrite::Frame {
            frame: Box::new(frame),
            diagnostics,
            source,
            receiver: Some(receiver.to_owned()),
            channel_name: None,
        }
    }

    #[test]
    fn records_messages_nodes_and_channels() {
        let db = database();
        let channel = pb::Channel {
            index: 0,
            role: pb::channel::Role::Primary as i32,
            settings: Some(pb::ChannelSettings {
                name: "LongFast".into(),
                uplink_enabled: true,
                ..Default::default()
            }),
        };
        db.apply(write(
            pb::FromRadio {
                id: 0,
                payload_variant: Some(from_radio::PayloadVariant::Channel(channel)),
            },
            DbSource::Physical,
        ))
        .unwrap();

        let user = pb::User {
            id: "!0000002a".into(),
            long_name: "Alice".into(),
            short_name: "ALI".into(),
            hw_model: 4,
            role: pb::config::device_config::Role::Client as i32,
            ..Default::default()
        };
        let node = pb::NodeInfo {
            num: 42,
            user: Some(user),
            last_heard: 99,
            snr: 7.0,
            hops_away: Some(1),
            ..Default::default()
        };
        db.apply(write(
            pb::FromRadio {
                id: 0,
                payload_variant: Some(from_radio::PayloadVariant::NodeInfo(node)),
            },
            DbSource::Physical,
        ))
        .unwrap();

        db.apply(write(text_packet(10, 42, 0, "hello"), DbSource::Physical))
            .unwrap();
        db.apply(write(text_packet(10, 42, 0, "hello"), DbSource::Physical))
            .unwrap();

        let stats = db.query_stats().unwrap();
        assert_eq!(stats.totals.packets, 1);
        assert_eq!(stats.totals.messages, 1); // duplicate packet deduped
        assert_eq!(stats.totals.nodes, 1);
        assert_eq!(stats.totals.bytes, 5);
        assert!(stats.packets_per_hour > 0.0);
        assert!(stats.bytes_per_hour > 0.0);
        assert_eq!(stats.channels[0].bytes, 5);
        assert_eq!(stats.channels[0].percent, 100.0);
        assert_eq!(stats.channels[0].nodes[0].name, "Alice");
        assert_eq!(stats.channels[0].nodes[0].percent, 100.0);
        assert_eq!(stats.top_nodes[0].percent, 100.0);
        assert_eq!(stats.channel_list[0].name, "LongFast");

        let messages = db.query_messages(None, 50).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].text, "hello");
        assert_eq!(messages[0].sender, "Alice");
        assert_eq!(messages[0].channel_name, "LongFast");
        assert_eq!(messages[0].source, "physical");
        assert_eq!(messages[0].relay_node, 0xABCD_0002);
        assert_eq!(stats.totals.mqtt_source, 0);
        assert!(db.query_messages(Some("#1"), 50).unwrap().is_empty());

        let nodes = db.query_nodes().unwrap();
        assert_eq!(nodes[0].long_name.as_deref(), Some("Alice"));
        assert_eq!(nodes[0].hops_away, Some(1));
    }

    #[test]
    fn decrypts_an_extra_channel_packet_before_storing_it() {
        let channel = ExtraChannel::parse("*", "AQ==").expect("extra channel");
        let (db, _rx) =
            Database::open_with_channels(":memory:", vec![channel]).expect("open in-memory db");
        let packet = pb::MeshPacket {
            id: 0x0506_0708,
            from: 0x1122_3344,
            to: 0xFFFF_FFFF,
            channel: 0x99,
            transport_mechanism: pb::mesh_packet::TransportMechanism::TransportLora as i32,
            payload_variant: Some(pb::mesh_packet::PayloadVariant::Encrypted(vec![
                0x4f, 0x19, 0xcd, 0xee, 0x8d, 0x6f,
            ])),
            ..Default::default()
        };
        db.apply(write_reception(
            pb::FromRadio {
                id: 0,
                payload_variant: Some(from_radio::PayloadVariant::Packet(packet)),
            },
            None,
            DbSource::Physical,
            "!00000001",
        ))
        .unwrap();

        let messages = db.query_messages(None, 10).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].text, "hi");
        assert_eq!(messages[0].channel_name, "*-0x01");
        assert!(messages[0].decrypted);

        let receptions = db.query_receptions(0x1122_3344, 0x0506_0708).unwrap();
        assert_eq!(receptions.len(), 1);
        assert!(receptions[0].decrypted);

        let raw = db.query_raw_frames(Some(3), 10).unwrap();
        assert_eq!(raw.len(), 1);
        assert!(raw[0].decrypted);
        assert_eq!(db.query_stats().unwrap().totals.decrypted, 1);
    }

    #[test]
    fn records_ingestion_source_without_touching_via_mqtt() {
        let db = database();
        db.apply(write(text_packet(21, 42, 0, "from broker"), DbSource::Mqtt))
            .unwrap();

        let messages = db.query_messages(None, 10).unwrap();
        assert_eq!(messages[0].source, "mqtt");
        assert!(!messages[0].via_mqtt);
        let stats = db.query_stats().unwrap();
        assert_eq!(stats.totals.mqtt_source, 1);
        assert_eq!(stats.totals.via_mqtt, 0);
    }

    fn with_snr(mut frame: pb::FromRadio, snr: f32) -> pb::FromRadio {
        if let Some(from_radio::PayloadVariant::Packet(packet)) = &mut frame.payload_variant {
            packet.rx_snr = snr;
        }
        frame
    }

    fn with_transport(
        mut frame: pb::FromRadio,
        transport: pb::mesh_packet::TransportMechanism,
    ) -> pb::FromRadio {
        if let Some(from_radio::PayloadVariant::Packet(packet)) = &mut frame.payload_variant {
            packet.transport_mechanism = transport as i32;
        }
        frame
    }

    #[test]
    fn aggregates_receptions_across_gateways() {
        let db = database();
        db.apply(write_reception(
            with_snr(text_packet(30, 42, 0, "multi"), 4.0),
            Some(NexusDiagnostics {
                frequency_error: Some(-100.0),
                coding_rate: Some(2),
            }),
            DbSource::Physical,
            "!00000001",
        ))
        .unwrap();
        db.apply(write_reception(
            with_snr(text_packet(30, 42, 0, "multi"), 9.0),
            Some(NexusDiagnostics {
                frequency_error: Some(-50.0),
                coding_rate: Some(3),
            }),
            DbSource::Mqtt,
            "!00000002",
        ))
        .unwrap();
        // A repeat from the same receiver is another reception.
        db.apply(write_reception(
            with_snr(text_packet(30, 42, 0, "multi"), 1.0),
            None,
            DbSource::Physical,
            "!00000001",
        ))
        .unwrap();

        let stats = db.query_stats().unwrap();
        assert_eq!(stats.totals.packets, 1);
        assert_eq!(stats.totals.receptions, 3);
        assert_eq!(stats.totals.multi_heard, 1);

        let messages = db.query_messages(None, 10).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].reception_count, 3);
        assert_eq!(messages[0].gateway_count, 2);
        assert_eq!(messages[0].best_snr, Some(9.0));
        assert_eq!(messages[0].relay_node, 0xABCD_0002);

        let receptions = db.query_receptions(42, 30).unwrap();
        assert_eq!(receptions.len(), 3);
        assert_eq!(receptions[0].receiver, "!00000002");
        assert_eq!(receptions[0].relay_node, 0xABCD_0002);
        assert_eq!(receptions[0].rx_snr, Some(9.0));
        assert_eq!(receptions[0].rx_frequency_error, Some(-50.0));
        assert_eq!(receptions[0].rx_coding_rate, Some(3));
        assert_eq!(receptions[1].receiver, "!00000001");
        assert_eq!(receptions[1].rx_snr, Some(4.0));
        assert_eq!(receptions[1].rx_frequency_error, Some(-100.0));
        assert_eq!(receptions[1].rx_coding_rate, Some(2));
        assert_eq!(receptions[2].receiver, "!00000001");
        assert_eq!(receptions[2].rx_snr, Some(1.0));
        assert!(receptions[2].rx_frequency_error.is_none());

        let by_node = db.query_node_receptions(42, 10).unwrap();
        assert_eq!(by_node.len(), 3);

        let relays = db.query_relay_stats("!00000001", 10).unwrap();
        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0].relay_node, 2);
        assert_eq!(relays[0].packets, 2);
        assert_eq!(relays[0].rssi.min, Some(-70.0));
        assert_eq!(relays[0].rssi.max, Some(-70.0));
        assert_eq!(relays[0].rssi.avg, Some(-70.0));
        assert_eq!(relays[0].snr.count, 2);
        assert_eq!(relays[0].snr.avg, Some(2.5));
        assert_eq!(relays[0].snr.stddev, Some(1.5));
        assert_eq!(relays[0].frequency_error.count, 1);

        let series = db.query_relay_series("!00000001", 10).unwrap();
        assert_eq!(series.len(), 2);
        assert!(series.iter().all(|sample| sample.relay_node == 2));
    }

    fn channel_frame(index: i32, name: &str) -> pb::FromRadio {
        pb::FromRadio {
            id: 0,
            payload_variant: Some(from_radio::PayloadVariant::Channel(pb::Channel {
                index,
                role: pb::channel::Role::Secondary as i32,
                settings: Some(pb::ChannelSettings {
                    name: name.into(),
                    ..Default::default()
                }),
            })),
        }
    }

    #[test]
    fn resolves_channel_names_per_receiving_gateway() {
        let db = database();
        db.apply(write_reception(
            channel_frame(0, "Alpha"),
            None,
            DbSource::Physical,
            "!000000a1",
        ))
        .unwrap();
        db.apply(write_reception(
            channel_frame(0, "Beta"),
            None,
            DbSource::Physical,
            "!000000b2",
        ))
        .unwrap();

        db.apply(write_reception(
            text_packet(70, 42, 0, "from alpha"),
            None,
            DbSource::Physical,
            "!000000a1",
        ))
        .unwrap();
        db.apply(write_reception(
            text_packet(71, 43, 0, "from beta"),
            None,
            DbSource::Physical,
            "!000000b2",
        ))
        .unwrap();

        let messages = db.query_messages(None, 10).unwrap();
        assert_eq!(messages[0].text, "from beta");
        assert_eq!(messages[0].channel_name, "Beta");
        assert_eq!(messages[1].text, "from alpha");
        assert_eq!(messages[1].channel_name, "Alpha");
        let alpha = db.query_messages(Some("Alpha"), 10).unwrap();
        assert_eq!(alpha.len(), 1);
        assert_eq!(alpha[0].text, "from alpha");

        let packets = db.query_node_packets(42, 10).unwrap();
        assert_eq!(packets[0].channel_name, "Alpha");
        assert_eq!(packets[0].contents, "from alpha");
        assert_eq!(packets[0].hop_start, Some(3));
        assert_eq!(packets[0].hop_limit, Some(2));

        let receptions = db.query_receptions(43, 71).unwrap();
        assert_eq!(receptions[0].channel_name, "Beta");

        let stats = db.query_stats().unwrap();
        assert_eq!(stats.channels.len(), 2);
        assert!(stats
            .channels
            .iter()
            .any(|channel| channel.name == "Alpha" && channel.count == 1));
        assert!(stats
            .channels
            .iter()
            .any(|channel| channel.name == "Beta" && channel.count == 1));
        assert!(stats
            .channel_list
            .iter()
            .any(|channel| channel.key == "Alpha"));
        assert!(stats
            .channel_list
            .iter()
            .any(|channel| channel.key == "Beta"));
    }

    #[test]
    fn merges_the_same_channel_name_across_gateway_indexes() {
        let db = database();
        db.apply(write_reception(
            channel_frame(0, "Alpha"),
            None,
            DbSource::Physical,
            "!000000a1",
        ))
        .unwrap();
        db.apply(write_reception(
            channel_frame(1, "Alpha"),
            None,
            DbSource::Physical,
            "!000000b2",
        ))
        .unwrap();
        db.apply(write_reception(
            text_packet(73, 42, 0, "index zero"),
            None,
            DbSource::Physical,
            "!000000a1",
        ))
        .unwrap();
        db.apply(write_reception(
            text_packet(74, 43, 1, "index one"),
            None,
            DbSource::Physical,
            "!000000b2",
        ))
        .unwrap();

        let stats = db.query_stats().unwrap();
        assert_eq!(stats.channels.len(), 1);
        assert_eq!(stats.channels[0].name, "Alpha");
        assert_eq!(stats.channels[0].count, 2);
        assert_eq!(stats.channel_list.len(), 1);
        assert_eq!(stats.channel_list[0].key, "Alpha");
    }

    #[test]
    fn lists_packets_with_filters_and_contents() {
        let db = database();
        let user = pb::User {
            id: "!0000002a".into(),
            long_name: "Alice".into(),
            short_name: "ALI".into(),
            ..Default::default()
        };
        db.apply(write(
            pb::FromRadio {
                id: 0,
                payload_variant: Some(from_radio::PayloadVariant::NodeInfo(pb::NodeInfo {
                    num: 42,
                    user: Some(user),
                    last_heard: 99,
                    ..Default::default()
                })),
            },
            DbSource::Physical,
        ))
        .unwrap();
        db.apply(write_reception(
            channel_frame(0, "Alpha"),
            None,
            DbSource::Physical,
            "!0000002a",
        ))
        .unwrap();
        db.apply(write_reception(
            text_packet(75, 42, 0, "hello packets"),
            None,
            DbSource::Physical,
            "!0000002a",
        ))
        .unwrap();

        let filter = PacketFilter {
            limit: 10,
            ..Default::default()
        };
        let packets = db.query_packets(&filter).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].from_name, "Alice");
        assert_eq!(packets[0].to_name, "broadcast");
        assert_eq!(packets[0].channel_name, "Alpha");
        assert_eq!(packets[0].portnum_name, "TEXT_MESSAGE_APP");
        assert_eq!(packets[0].contents, "hello packets");
        assert_eq!(packets[0].gateways, "!0000002a");
        assert!(!packets[0].decrypted);

        let by_gateway = db
            .query_packets(&PacketFilter {
                gateway: Some("!0000002a".into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_gateway.len(), 1);
        let by_channel = db
            .query_packets(&PacketFilter {
                channel: Some("Alpha".into()),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_channel.len(), 1);
        let by_port = db
            .query_packets(&PacketFilter {
                portnum: Some(pb::PortNum::TextMessageApp as i64),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_port.len(), 1);

        let filters = db.query_packet_filters().unwrap();
        assert!(filters
            .portnums
            .iter()
            .any(|option| option.label == "TEXT_MESSAGE_APP" && option.count == 1));
        assert!(filters
            .gateways
            .iter()
            .any(|option| option.value == "!0000002a" && option.label == "Alice"));
    }

    #[test]
    fn lists_mqtt_gateways_from_received_packets() {
        let db = database();
        let user = pb::User {
            id: "!0000002a".into(),
            long_name: "Alice".into(),
            short_name: "ALI".into(),
            ..Default::default()
        };
        db.apply(write(
            pb::FromRadio {
                id: 0,
                payload_variant: Some(from_radio::PayloadVariant::NodeInfo(pb::NodeInfo {
                    num: 42,
                    user: Some(user),
                    last_heard: 99,
                    ..Default::default()
                })),
            },
            DbSource::Mqtt,
        ))
        .unwrap();
        db.apply(write_reception(
            text_packet(72, 42, 0, "over mqtt"),
            None,
            DbSource::Mqtt,
            "!0000002a",
        ))
        .unwrap();

        let gateways = db.query_mqtt_gateways(10).unwrap();
        assert_eq!(gateways.len(), 1);
        assert_eq!(gateways[0].receiver, "!0000002a");
        assert_eq!(gateways[0].num, Some(42));
        assert_eq!(gateways[0].long_name.as_deref(), Some("Alice"));
        assert_eq!(gateways[0].packets, 1);
    }

    #[test]
    fn channel_stats_group_by_channel_and_node() {
        let db = database();
        for (id, from, channel, text) in [(40, 42, 0, "a"), (41, 43, 0, "bb"), (42, 44, 1, "ccc")] {
            db.apply(write_reception(
                text_packet(id, from, channel, text),
                None,
                DbSource::Physical,
                "!00000001",
            ))
            .unwrap();
        }

        let stats = db.query_stats().unwrap();
        assert_eq!(stats.totals.bytes, 6);
        assert_eq!(stats.channels.len(), 2);
        assert_eq!(stats.channels[0].channel, 0);
        assert_eq!(stats.channels[0].count, 2);
        assert_eq!(stats.channels[0].bytes, 3);
        assert_eq!(stats.channels[0].nodes.len(), 2);
        assert_eq!(stats.channels[0].nodes[1].count, 1);
        assert_eq!(stats.channels[1].channel, 1);
        assert_eq!(stats.channels[1].nodes[0].num, 44);
        assert_eq!(stats.channels[1].nodes[0].percent, 100.0);
    }

    #[test]
    fn physical_reception_replaces_a_client_echo() {
        let db = database();
        db.apply(write(text_packet(31, 42, 0, "echo"), DbSource::Client))
            .unwrap();
        db.apply(write_reception(
            with_snr(text_packet(31, 42, 0, "echo"), 7.5),
            None,
            DbSource::Physical,
            "!00000001",
        ))
        .unwrap();

        let messages = db.query_messages(None, 10).unwrap();
        assert_eq!(messages[0].source, "physical");
        assert_eq!(messages[0].rx_snr, Some(7.5));
        assert_eq!(messages[0].reception_count, 1);
    }

    #[test]
    fn internal_transport_is_excluded_from_stats_except_transports() {
        let db = database();
        db.apply(write_reception(
            with_transport(
                text_packet(50, 42, 0, "internal"),
                pb::mesh_packet::TransportMechanism::TransportInternal,
            ),
            None,
            DbSource::Physical,
            "!00000001",
        ))
        .unwrap();
        db.apply(write_reception(
            text_packet(51, 42, 0, "lora"),
            None,
            DbSource::Physical,
            "!00000001",
        ))
        .unwrap();

        let stats = db.query_stats().unwrap();
        assert_eq!(stats.totals.packets, 1);
        assert_eq!(stats.totals.messages, 1);
        assert_eq!(stats.totals.bytes, 4);
        assert_eq!(stats.channels[0].nodes[0].count, 1);
        let transports: Vec<(String, i64)> = stats
            .transports
            .iter()
            .map(|bucket| (bucket.label.clone(), bucket.count))
            .collect();
        assert!(transports.contains(&("TRANSPORT_INTERNAL".into(), 1)));
        assert!(transports.contains(&("TRANSPORT_LORA".into(), 1)));
    }

    #[test]
    fn records_traceroutes_and_meshtastic_raw_feed() {
        let db = database();
        let discovery = pb::RouteDiscovery {
            route: vec![0xABCD_0002, 0xABCD_0003],
            snr_towards: vec![24, 28],
            route_back: vec![0xABCD_0003, 0xABCD_0002],
            snr_back: vec![20, 16],
        };
        let packet = pb::MeshPacket {
            id: 60,
            from: 0xABCD_0001,
            to: 0xABCD_0004,
            channel: 0,
            rx_time: 100,
            transport_mechanism: pb::mesh_packet::TransportMechanism::TransportLora as i32,
            payload_variant: Some(pb::mesh_packet::PayloadVariant::Decoded(pb::Data {
                portnum: pb::PortNum::TracerouteApp as i32,
                payload: discovery.encode_to_vec(),
                request_id: 60,
                ..Default::default()
            })),
            ..Default::default()
        };
        db.apply(write_reception(
            pb::FromRadio {
                id: 0,
                payload_variant: Some(from_radio::PayloadVariant::Packet(packet)),
            },
            None,
            DbSource::Physical,
            "!00000001",
        ))
        .unwrap();

        let traces = db.query_traceroutes(10).unwrap();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].route, vec![0xABCD_0002, 0xABCD_0003]);
        assert_eq!(traces[0].route_back, vec![0xABCD_0003, 0xABCD_0002]);
        assert_eq!(traces[0].snr_towards, vec![24, 28]);

        let raw = db.query_raw_frames(Some(3), 10).unwrap();
        assert_eq!(raw.len(), 1);
        assert_eq!(raw[0].kind_name, "meshtastic");
        assert_eq!(raw[0].payload_name.as_deref(), Some("TRACEROUTE_APP"));
    }

    #[test]
    fn node_detail_includes_hardware_and_packets() {
        let db = database();
        db.apply(write(
            pb::FromRadio {
                id: 0,
                payload_variant: Some(from_radio::PayloadVariant::NodeInfo(pb::NodeInfo {
                    num: 42,
                    user: Some(pb::User {
                        id: "!0000002a".into(),
                        long_name: "Alice".into(),
                        short_name: "ALI".into(),
                        hw_model: pb::HardwareModel::HeltecV3 as i32,
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
            },
            DbSource::Physical,
        ))
        .unwrap();
        db.apply(write_reception(
            text_packet(70, 42, 0, "hello"),
            None,
            DbSource::Physical,
            "!00000001",
        ))
        .unwrap();
        let node = db.query_node(42).unwrap().expect("node row");
        assert!(!node.hardware.is_empty());
        let packets = db.query_node_packets(42, 10).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].portnum_name, "TEXT_MESSAGE_APP");
        assert_eq!(packets[0].transport_name, "TRANSPORT_LORA");
    }

    #[test]
    fn classifies_opaque_and_pki_channels() {
        let db = database();
        db.apply(write_reception(
            text_packet(80, 42, 2, "decoded"),
            None,
            DbSource::Physical,
            "!00000001",
        ))
        .unwrap();
        for (id, to, channel) in [(81, 0xFFFF_FFFF, 0), (82, 77, 0)] {
            let packet = pb::MeshPacket {
                id,
                from: 43,
                to,
                channel,
                transport_mechanism: pb::mesh_packet::TransportMechanism::TransportLora as i32,
                payload_variant: Some(pb::mesh_packet::PayloadVariant::Encrypted(vec![1, 2])),
                ..Default::default()
            };
            db.apply(write_reception(
                pb::FromRadio {
                    id: 0,
                    payload_variant: Some(from_radio::PayloadVariant::Packet(packet)),
                },
                None,
                DbSource::Physical,
                "!00000001",
            ))
            .unwrap();
        }

        let stats = db.query_stats().unwrap();
        assert_eq!(stats.totals.decoded_packets, 1);
        assert_eq!(stats.totals.opaque_packets, 2);
        assert_eq!(stats.totals.pki_packets, 1);
        let channels: Vec<(i64, i64)> = stats
            .channels
            .iter()
            .map(|channel| (channel.channel, channel.count))
            .collect();
        assert!(channels.contains(&(2, 1)));
        assert!(channels.contains(&(256, 1)));
        assert!(channels.contains(&(512, 1)));
    }

    #[test]
    fn cleanup_removes_old_packets_but_keeps_nodes() {
        let db = database();
        db.apply(write(
            pb::FromRadio {
                id: 0,
                payload_variant: Some(from_radio::PayloadVariant::NodeInfo(pb::NodeInfo {
                    num: 42,
                    user: Some(pb::User {
                        id: "!0000002a".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
            },
            DbSource::Physical,
        ))
        .unwrap();
        db.apply(write(text_packet(90, 42, 0, "old"), DbSource::Physical))
            .unwrap();
        db.apply(write(text_packet(91, 42, 0, "new"), DbSource::Physical))
            .unwrap();

        let old = 100_i64;
        {
            let connection = db.conn.lock().unwrap();
            connection
                .execute(
                    "UPDATE packets SET received_at = ?1 WHERE packet_id = 90",
                    params![old],
                )
                .unwrap();
            connection
                .execute(
                    "UPDATE messages SET received_at = ?1 WHERE packet_id = 90",
                    params![old],
                )
                .unwrap();
        }
        let removed = db.cleanup_older_than(7).unwrap();
        assert!(removed >= 2);
        assert_eq!(db.query_stats().unwrap().totals.packets, 1);
        assert_eq!(db.query_stats().unwrap().totals.messages, 1);
        assert_eq!(db.query_nodes().unwrap().len(), 1);
    }

    #[test]
    fn records_reassembled_raw_frames() {
        let db = database();
        let frame = vec![0x09, 0x00, 0xAA, 0xBB, b'h', b'i'];
        db.apply(DbWrite::Raw(Box::new(RawTunnelFrame {
            kind: RawTunnelKind::MeshCore,
            source: RawTunnelSource::Physical,
            sequence: 3,
            frame,
            gateway: 0x1122_3344,
            channel: 0,
            rx_time: 100,
            rssi: Some(-60),
            snr: Some(5.0),
            frequency_error: None,
            coding_rate: None,
        })))
        .unwrap();

        let raw = db.query_raw_frames(Some(1), 50).unwrap();
        assert_eq!(raw.len(), 1);
        assert_eq!(raw[0].gateway_id, "!11223344");
        assert_eq!(raw[0].kind_name, "jencore");
        assert_eq!(raw[0].source, "physical");
        assert_eq!(raw[0].rx_rssi, Some(-60));
        assert_eq!(raw[0].payload_name.as_deref(), Some("TXT_MSG"));
        assert_eq!(raw[0].frame_hex, "0900aabb6869");
        assert!(db.query_raw_frames(Some(2), 50).unwrap().is_empty());
        assert_eq!(db.query_stats().unwrap().totals.jencore_frames, 1);
    }

    fn meshcore_raw(frame: Vec<u8>) -> DbWrite {
        DbWrite::Raw(Box::new(RawTunnelFrame {
            kind: RawTunnelKind::MeshCore,
            source: RawTunnelSource::Physical,
            sequence: 1,
            frame,
            gateway: 0x1122_3344,
            channel: 0,
            rx_time: 100,
            rssi: Some(-60),
            snr: Some(5.0),
            frequency_error: None,
            coding_rate: None,
        }))
    }

    /// A flood advert: public key, timestamp, signature, then app data.
    fn meshcore_advert(key_prefix: [u8; 2], node_type: u8, name: &str) -> Vec<u8> {
        let mut frame = vec![(4 << 2) | 1, 0x00];
        let mut key = [0x55u8; 32];
        key[..2].copy_from_slice(&key_prefix);
        frame.extend_from_slice(&key);
        frame.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        frame.extend_from_slice(&[0u8; 64]);
        frame.push(0x80 | 0x10 | node_type);
        frame.extend_from_slice(&40_500_000i32.to_le_bytes());
        frame.extend_from_slice(&(-3_700_000i32).to_le_bytes());
        frame.extend_from_slice(name.as_bytes());
        frame
    }

    #[test]
    fn meshcore_frames_show_names_channels_and_regions() {
        use muxtastic_core::meshcore::{MeshCoreChannel, MeshCoreKeys, MeshCoreRegion};

        let keys = MeshCoreKeys::new(
            vec![MeshCoreChannel::hashtag("#test")],
            vec![MeshCoreRegion::named("es")],
        );
        let (db, _rx) = Database::open_with_keys(":memory:", Vec::new(), keys).unwrap();
        db.apply(meshcore_raw(meshcore_advert([0x20, 0x0f], 2, "Rep One")))
            .unwrap();
        db.apply(meshcore_raw(meshcore_advert([0x20, 0xaa], 2, "Rep Two")))
            .unwrap();
        db.apply(meshcore_raw(meshcore_advert([0x20, 0x0b], 1, "Phone")))
            .unwrap();

        // Three nodes share the first key byte and stay three nodes.
        let nodes = db.query_jraw_nodes(Some(1), 10).unwrap();
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].latitude, Some(40.5));
        assert_eq!(nodes[0].longitude, Some(-3.7));

        // Region-scoped group text on #test, relayed by 200f then an unknown 9999.
        let mut plain = 1_700_000_123u32.to_le_bytes().to_vec();
        plain.push(0);
        plain.extend_from_slice(b"Ana: hola");
        let payload = MeshCoreChannel::hashtag("#test").seal(&plain);
        let code = MeshCoreRegion::named("es").transport_code(5, &payload);
        let mut frame = vec![5 << 2];
        frame.extend_from_slice(&code.to_le_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&[0x42, 0x20, 0x0f, 0x99, 0x99]);
        frame.extend_from_slice(&payload);
        db.apply(meshcore_raw(frame)).unwrap();

        // One-byte path hash 0x20 matches both repeaters, but not the phone.
        let mut short = vec![(5 << 2) | 1, 0x01, 0x20];
        short.extend_from_slice(&MeshCoreChannel::hashtag("#other").seal(&plain));
        db.apply(meshcore_raw(short)).unwrap();

        let frames = db.query_raw_frames(Some(1), 10).unwrap();
        let unknown = &frames[0];
        assert!(!unknown.decrypted);
        assert_eq!(unknown.channel_name, None);
        assert_eq!(unknown.region_code, None);
        assert_eq!(unknown.path.len(), 1);
        assert_eq!(unknown.path[0].candidates, 2);
        let mut names = unknown.path[0].names.clone();
        names.sort();
        assert_eq!(names, ["Rep One", "Rep Two"]);

        let text = &frames[1];
        assert!(text.decrypted);
        assert_eq!(text.channel_name.as_deref(), Some("#test"));
        assert_eq!(text.payload_text.as_deref(), Some("Ana: hola"));
        assert_eq!(text.sent_at, Some(1_700_000_123));
        assert_eq!(text.region.as_deref(), Some("#es"));
        assert_eq!(text.region_code, Some(i64::from(code)));
        assert_eq!(text.path[0].hash, "200f");
        assert_eq!(text.path[0].names, ["Rep One"]);
        assert_eq!(text.path[1].hash, "9999");
        assert_eq!(text.path[1].candidates, 0);

        let filtered = |filter: RawFilter| {
            db.query_raw_frames_filtered(
                &RawFilter {
                    kind: Some(1),
                    ..filter
                },
                10,
            )
            .unwrap()
        };
        let group_text = filtered(RawFilter {
            payload_type: Some(5),
            ..RawFilter::default()
        });
        assert_eq!(group_text.len(), 2);
        let decrypted = filtered(RawFilter {
            decrypted: Some(true),
            ..RawFilter::default()
        });
        assert_eq!(decrypted.len(), 1);
        assert_eq!(decrypted[0].channel_name.as_deref(), Some("#test"));
        let undecrypted = filtered(RawFilter {
            decrypted: Some(false),
            ..RawFilter::default()
        });
        assert_eq!(undecrypted.len(), 1);
        assert!(undecrypted[0].channel_name.is_none());
        let by_channel = filtered(RawFilter {
            channel_hash: Some(i64::from(MeshCoreChannel::hashtag("#test").hash)),
            ..RawFilter::default()
        });
        assert_eq!(by_channel.len(), 1);
        for (region, expected) in [("any", 1), ("#es", 1), ("unknown", 0), ("#other", 0)] {
            let found = filtered(RawFilter {
                region: Some(region.to_owned()),
                ..RawFilter::default()
            });
            assert_eq!(found.len(), expected, "region {region}");
        }
        for (search, expected) in [("HOLA", 1), ("rep one", 3), ("rep two", 2), ("jc:#test", 1), ("nothing", 0)] {
            let found = filtered(RawFilter {
                search: Some(search.to_owned()),
                ..RawFilter::default()
            });
            assert_eq!(found.len(), expected, "search {search}");
        }
        let options = db.query_raw_filters(1).unwrap();
        assert_eq!(options.payloads[0].label, "ADVERT");
        assert_eq!(options.payloads[0].count, 3);
        assert!(options.channels[0].label.starts_with("JC:#test"));
        assert!(options.channels[1].label.ends_with("(no key)"));
        assert_eq!(options.regions[0].count, 1);
        assert_eq!(options.regions[1].value, "#es");

        let advert = &frames[2];
        assert_eq!(advert.latitude, Some(40.5));
        assert_eq!(advert.sent_at, Some(1_700_000_000));
        assert!(advert.sender.is_none());
    }

    fn meshcore_position_is_unset(db: &Database) -> bool {
        let nodes = db.query_jraw_nodes(Some(1), 10).unwrap();
        nodes[0].latitude.is_none() && nodes[0].longitude.is_none()
    }

    #[test]
    fn meshcore_group_text_appears_in_chat_and_stats() {
        use muxtastic_core::meshcore::{MeshCoreChannel, MeshCoreKeys};

        let keys = MeshCoreKeys::new(vec![MeshCoreChannel::hashtag("#test")], Vec::new());
        let (db, _rx) = Database::open_with_keys(":memory:", Vec::new(), keys).unwrap();
        let group = |channel: MeshCoreChannel, path: &[u8], text: &str| {
            let mut plain = 1_700_000_123u32.to_le_bytes().to_vec();
            plain.push(0);
            plain.extend_from_slice(text.as_bytes());
            let mut frame = vec![(5 << 2) | 1, path.len() as u8];
            frame.extend_from_slice(path);
            frame.extend_from_slice(&channel.seal(&plain));
            meshcore_raw(frame)
        };
        // The same message heard twice over different paths, plus two others.
        db.apply(group(MeshCoreChannel::public(), &[0x20], "Ana: hola"))
            .unwrap();
        db.apply(group(MeshCoreChannel::public(), &[0x20, 0x30], "Ana: hola"))
            .unwrap();
        db.apply(group(MeshCoreChannel::hashtag("#test"), &[], "Bo: probando"))
            .unwrap();
        db.apply(group(MeshCoreChannel::hashtag("#secret"), &[], "X: hidden"))
            .unwrap();
        db.apply(write(text_packet(7, 42, 0, "meshtastic"), DbSource::Physical))
            .unwrap();

        let all = db.query_messages(None, 10).unwrap();
        assert_eq!(all.len(), 3);
        let ana = all.iter().find(|message| message.sender == "Ana").unwrap();
        assert_eq!(ana.channel_name, "JC:Public");
        assert_eq!(ana.text, "hola");
        assert_eq!(ana.network, "meshcore");
        assert_eq!(ana.reception_count, 2);
        let paths: Vec<Vec<&str>> = ana
            .meshcore_receptions
            .iter()
            .map(|heard| heard.path.iter().map(|hop| hop.hash.as_str()).collect())
            .collect();
        assert_eq!(paths, [vec!["20"], vec!["20", "30"]]);
        assert_eq!(ana.hop_start, Some(1));
        assert_eq!(ana.sent_at, Some(1_700_000_123));
        assert!(ana.decrypted);

        let test = db.query_messages(Some("JC:#test"), 10).unwrap();
        assert_eq!(test.len(), 1);
        assert_eq!(test[0].sender, "Bo");
        assert!(db.query_messages(Some("JC:#secret"), 10).unwrap().is_empty());

        // A Meshtastic copy of Ana's message bridged onto a JC:Public channel
        // replaces the decrypted one instead of doubling it.
        db.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO messages (packet_id, from_num, to_num, channel, channel_name,
                                       text, rx_time, via_mqtt, received_at)
                 VALUES (99, 42, 0, 5, 'JC:Public', 'hola', 0, 0, ?1)",
                params![ana.received_at],
            )
            .unwrap();
        let public = db.query_messages(Some("JC:Public"), 10).unwrap();
        assert_eq!(public.len(), 1);
        assert_eq!(public[0].network, "meshtastic");
        // The bridged copy carries the MeshCore paths.
        assert_eq!(public[0].meshcore_receptions.len(), 2);
        assert_eq!(db.query_messages(None, 10).unwrap().len(), 3);

        let channels = db.query_channels().unwrap();
        assert!(channels.iter().any(|channel| channel.key == "JC:Public"));
        assert!(channels.iter().any(|channel| channel.key == "JC:#test"));

        let stats = db.query_jraw_stats(1).unwrap();
        let frames = stats.cards.iter().find(|card| card.label == "Frames").unwrap();
        assert_eq!(frames.value, 4.0);
        let table = |title: &str| {
            stats
                .tables
                .iter()
                .find(|table| table.title == title)
                .unwrap()
                .rows
                .iter()
                .map(|row| (row.label.as_str(), row.count))
                .collect::<Vec<_>>()
        };
        let channels = table("Channels");
        assert!(channels.contains(&("JC:Public", 1)));
        assert!(channels.contains(&("JC:#test", 1)));
        assert_eq!(channels.len(), 3);
        assert_eq!(table("Payload types"), [("GRP_TXT", 4)]);
        let channel_table = stats
            .tables
            .iter()
            .find(|table| table.title == "Channels")
            .unwrap();
        assert!(channel_table.pie);
        assert_eq!(channel_table.total, 3);
        assert!(table("Top chat senders").contains(&("Ana", 1)));
        assert!(db.query_jraw_stats(2).unwrap().tables.len() >= 3);
    }

    #[test]
    fn records_jraw_nodes_from_adverts() {
        let db = database();
        let mut advert = vec![(4 << 2) | 2, 0x02, 0x11, 0x22];
        advert.extend_from_slice(&[0u8; 100]);
        advert.push(0x80);
        advert.extend_from_slice(b"Node");
        let raw = |kind, frame| {
            DbWrite::Raw(Box::new(RawTunnelFrame {
                kind,
                source: RawTunnelSource::Physical,
                sequence: 1,
                frame,
                gateway: 0x1122_3344,
                channel: 0,
                rx_time: 100,
                rssi: Some(-60),
                snr: Some(5.0),
                frequency_error: None,
                coding_rate: None,
            }))
        };
        db.apply(raw(RawTunnelKind::MeshCore, advert.clone()))
            .unwrap();
        db.apply(raw(RawTunnelKind::MeshCore, advert)).unwrap();

        let mut announce = vec![0x01, 3];
        announce.extend_from_slice(&[0xAB; 16]);
        announce.push(0x00);
        announce.extend_from_slice(&[0x11; 64]);
        announce.extend_from_slice(&[0x22; 10]);
        announce.extend_from_slice(&[0x33; 10]);
        announce.extend_from_slice(&[0x44; 64]);
        announce.extend_from_slice(b"Reticulum Node");
        db.apply(raw(RawTunnelKind::RNode, announce)).unwrap();

        assert!(meshcore_position_is_unset(&db));
        let meshcore = db.query_jraw_nodes(Some(1), 10).unwrap();
        assert_eq!(meshcore.len(), 1);
        assert_eq!(meshcore[0].name.as_deref(), Some("Node"));
        assert_eq!(meshcore[0].frames, 2);
        assert_eq!(meshcore[0].gateway_id, "!11223344");

        let reticulum = db.query_jraw_nodes(Some(2), 10).unwrap();
        assert_eq!(reticulum.len(), 1);
        assert_eq!(reticulum[0].name.as_deref(), Some("Reticulum Node"));
        assert_eq!(reticulum[0].node_hash, "abababababababababababababababab");
    }

    #[test]
    fn records_nexus_diagnostics() {
        let db = database();
        let diagnostics = NexusDiagnostics {
            frequency_error: Some(-123.0),
            coding_rate: Some(3),
        };
        db.apply(write_with_diagnostics(
            text_packet(12, 42, 0, "diag"),
            diagnostics,
            DbSource::Physical,
        ))
        .unwrap();

        let messages = db.query_messages(None, 10).unwrap();
        assert_eq!(messages[0].rx_frequency_error, Some(-123.0));
        assert_eq!(messages[0].rx_coding_rate, Some(3));

        db.apply(DbWrite::Raw(Box::new(RawTunnelFrame {
            kind: RawTunnelKind::MeshCore,
            source: RawTunnelSource::Physical,
            sequence: 4,
            frame: vec![0x09, 0x00, 0xAA, 0xBB, b'x'],
            gateway: 0x1122_3344,
            channel: 0,
            rx_time: 100,
            rssi: Some(-60),
            snr: Some(5.0),
            frequency_error: Some(-50.0),
            coding_rate: Some(4),
        })))
        .unwrap();

        let raw = db.query_raw_frames(Some(1), 10).unwrap();
        assert_eq!(raw[0].frequency_error, Some(-50.0));
        assert_eq!(raw[0].coding_rate, Some(4));
    }

    #[test]
    fn migrates_v1_databases() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                r#"
CREATE TABLE packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, packet_id INTEGER NOT NULL,
    from_num INTEGER NOT NULL, to_num INTEGER NOT NULL, channel INTEGER NOT NULL,
    portnum INTEGER, transport INTEGER NOT NULL, via_mqtt INTEGER NOT NULL,
    rx_time INTEGER NOT NULL, rx_snr REAL, rx_rssi INTEGER, hop_limit INTEGER,
    hop_start INTEGER, received_at INTEGER NOT NULL
);
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, packet_id INTEGER NOT NULL,
    from_num INTEGER NOT NULL, to_num INTEGER NOT NULL, channel INTEGER NOT NULL,
    text TEXT NOT NULL, rx_time INTEGER NOT NULL, rx_snr REAL, rx_rssi INTEGER,
    hop_limit INTEGER, hop_start INTEGER, via_mqtt INTEGER NOT NULL,
    received_at INTEGER NOT NULL
);
CREATE TABLE raw_frames (
    id INTEGER PRIMARY KEY AUTOINCREMENT, kind INTEGER NOT NULL,
    gateway INTEGER NOT NULL, sequence INTEGER NOT NULL, channel INTEGER NOT NULL,
    rx_time INTEGER NOT NULL, rx_rssi INTEGER, rx_snr REAL, frame BLOB NOT NULL,
    frame_len INTEGER NOT NULL, route_type INTEGER, payload_type INTEGER,
    route_name TEXT, payload_name TEXT, path_hex TEXT, sender_hash TEXT,
    destination_hash TEXT, channel_hash INTEGER, node_name TEXT, public_key BLOB,
    received_at INTEGER NOT NULL
);
INSERT INTO packets
    (packet_id, from_num, to_num, channel, transport, via_mqtt, rx_time, received_at)
    VALUES (5, 42, 0, 0, 1, 0, 100, 100);
INSERT INTO packets
    (packet_id, from_num, to_num, channel, transport, via_mqtt, rx_time, received_at)
    VALUES (5, 42, 0, 0, 1, 0, 100, 101);
PRAGMA user_version = 1;
"#,
            )
            .unwrap();

        init_schema(&connection).unwrap();
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 16);
        let packets: i64 = connection
            .query_row("SELECT COUNT(*) FROM packets", [], |row| row.get(0))
            .unwrap();
        assert_eq!(packets, 1, "migration should deduplicate packets");
        let index: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'index' AND name = 'idx_packets_packet'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(index, 1);
        let receptions: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'packet_receptions'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(receptions, 1);
        let traces: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'traceroutes'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(traces, 1);
        for (table, column) in [
            ("packets", "rx_frequency_error"),
            ("packets", "rx_coding_rate"),
            ("packets", "source"),
            ("packets", "reception_count"),
            ("packets", "gateway_count"),
            ("packets", "best_snr"),
            ("packets", "best_rssi"),
            ("packets", "bytes"),
            ("packets", "relay_node"),
            ("packet_receptions", "relay_node"),
            ("messages", "rx_frequency_error"),
            ("messages", "rx_coding_rate"),
            ("messages", "source"),
            ("nodes", "source"),
            ("raw_frames", "frequency_error"),
            ("raw_frames", "coding_rate"),
            ("raw_frames", "source"),
        ] {
            assert!(
                column_exists(&connection, table, column).unwrap(),
                "{table}.{column}"
            );
        }
    }

    #[test]
    fn jraw_chunks_do_not_pollute_packet_stats() {
        let db = database();
        let mut encrypted = b"JRAW".to_vec();
        encrypted.extend_from_slice(&[1, 1, 1, 0, 1]);
        encrypted.extend_from_slice(b"frame");
        let packet = pb::MeshPacket {
            id: 7,
            from: 42,
            payload_variant: Some(pb::mesh_packet::PayloadVariant::Encrypted(encrypted)),
            ..Default::default()
        };
        db.apply(write(
            pb::FromRadio {
                id: 0,
                payload_variant: Some(from_radio::PayloadVariant::Packet(packet)),
            },
            DbSource::Physical,
        ))
        .unwrap();
        assert_eq!(db.query_stats().unwrap().totals.packets, 0);
    }

    #[test]
    fn applies_a_batch_of_writes() {
        let db = database();
        db.apply_batch(vec![
            write(text_packet(10, 42, 0, "first"), DbSource::Physical),
            write(text_packet(11, 42, 0, "second"), DbSource::Physical),
        ])
        .unwrap();
        let stats = db.query_stats().unwrap();
        assert_eq!(stats.totals.packets, 2);
        assert_eq!(stats.totals.messages, 2);
    }

    #[test]
    fn identical_receptions_are_stored_once() {
        let db = database();
        // An MQTT loop redelivers the very same reception over and over.
        for _ in 0..5 {
            db.apply(write_reception(
                text_packet(40, 42, 0, "looped"),
                None,
                DbSource::Mqtt,
                "!00000009",
            ))
            .unwrap();
        }
        // A genuine second hearing has different signal values and is kept.
        db.apply(write_reception(
            with_snr(text_packet(40, 42, 0, "looped"), -3.0),
            None,
            DbSource::Mqtt,
            "!00000009",
        ))
        .unwrap();

        assert_eq!(db.query_receptions(42, 40).unwrap().len(), 2);
        assert_eq!(db.query_raw_frames(Some(3), 10).unwrap().len(), 2);
        let messages = db.query_messages(None, 10).unwrap();
        assert_eq!(messages[0].reception_count, 2);
        assert_eq!(messages[0].gateway_count, 1);
        assert_eq!(messages[0].best_snr, Some(6.5));
        let stats = db.query_stats().unwrap();
        assert_eq!(stats.totals.receptions, 2);
        assert_eq!(stats.totals.meshtastic_frames, 2);
        let filters = db.query_packet_filters().unwrap();
        assert_eq!(filters.gateways[0].value, "!00000009");
        assert_eq!(filters.gateways[0].count, 2);
        assert_eq!(db.query_nodes().unwrap().len(), 0);
    }

    fn position_packet(id: u32, from: u32, position: pb::Position) -> pb::FromRadio {
        let data = pb::Data {
            portnum: pb::PortNum::PositionApp as i32,
            payload: position.encode_to_vec(),
            ..Default::default()
        };
        pb::FromRadio {
            id: 0,
            payload_variant: Some(from_radio::PayloadVariant::Packet(pb::MeshPacket {
                id,
                from,
                to: 0xFFFF_FFFF,
                rx_time: 200,
                transport_mechanism: pb::mesh_packet::TransportMechanism::TransportLora as i32,
                payload_variant: Some(pb::mesh_packet::PayloadVariant::Decoded(data)),
                ..Default::default()
            })),
        }
    }

    #[test]
    fn an_incomplete_position_never_stores_zero_coordinates() {
        let db = database();
        // Half a coordinate pair is not a position: the node is noted, but no
        // 0-degree placeholder is stored for the missing half.
        db.apply(write(
            position_packet(
                50,
                42,
                pb::Position {
                    latitude_i: Some(404_168_000),
                    ..Default::default()
                },
            ),
            DbSource::Physical,
        ))
        .unwrap();
        let node = db.query_node(42).unwrap().expect("node");
        assert_eq!(node.latitude_i, None);
        assert_eq!(node.longitude_i, None);

        db.apply(write(
            position_packet(
                51,
                42,
                pb::Position {
                    latitude_i: Some(404_168_000),
                    longitude_i: Some(-37_038_000),
                    altitude: Some(650),
                    ..Default::default()
                },
            ),
            DbSource::Physical,
        ))
        .unwrap();
        // A later packet without a fix (or reporting 0, 0) changes nothing.
        db.apply(write(
            position_packet(
                52,
                42,
                pb::Position {
                    latitude_i: Some(0),
                    longitude_i: Some(0),
                    ..Default::default()
                },
            ),
            DbSource::Physical,
        ))
        .unwrap();
        let node = db.query_node(42).unwrap().expect("node");
        assert_eq!(node.latitude_i, Some(404_168_000));
        assert_eq!(node.longitude_i, Some(-37_038_000));
        assert_eq!(node.altitude, Some(650));
    }

    #[test]
    fn a_known_channel_name_is_used_for_opaque_packets() {
        let db = database();
        let packet = pb::MeshPacket {
            id: 60,
            from: 42,
            to: 0xFFFF_FFFF,
            channel: 0x1f,
            transport_mechanism: pb::mesh_packet::TransportMechanism::TransportMqtt as i32,
            payload_variant: Some(pb::mesh_packet::PayloadVariant::Encrypted(vec![1, 2, 3, 4])),
            ..Default::default()
        };
        db.apply(DbWrite::Frame {
            frame: Box::new(pb::FromRadio {
                id: 0,
                payload_variant: Some(from_radio::PayloadVariant::Packet(packet)),
            }),
            diagnostics: None,
            source: DbSource::Mqtt,
            receiver: Some("!0000002a".to_owned()),
            channel_name: Some("LongFast".to_owned()),
        })
        .unwrap();

        let packets = db
            .query_packets(&PacketFilter {
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].channel_name, "LongFast");
        // The channel hash survives, and nothing leaks into the node's own
        // channel table.
        assert_eq!(packets[0].channel, OPAQUE_CHANNEL_BASE + 0x1f);
        assert!(!packets[0].decrypted);
        let connection = db.conn.lock().unwrap();
        let rows: i64 = connection
            .query_row("SELECT COUNT(*) FROM channels", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 0);
    }
}
