//! Nexus firmware raw tunnel (`JRAW`) detection and reassembly.
//!
//! The Nexus firmware forwards raw MeshCore and RNode/Reticulum frames inside
//! a `MeshPacket.encrypted` payload with a 9-byte header:
//!
//! ```text
//! 0..3  "JRAW"
//! 4     version (1)
//! 5     type (1 = MeshCore/JenCore, 2 = RNode/Reticulum)
//! 6     sequence (1..255)
//! 7     chunk index (0..count-1)
//! 8     chunk count (1..2)
//! 9..   chunk bytes
//! ```
//!
//! Frames up to 247 bytes fit one chunk; 248..494 bytes use two. The raw frame
//! is the chunk bytes concatenated in index order.

use std::collections::HashMap;

use meshtastic::protobufs as pb;

use crate::nexus::NexusDiagnostics;
use crate::util::hex;

pub const MAGIC: [u8; 4] = *b"JRAW";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 9;
pub const MAX_CHUNKS: u8 = 2;
pub const REASSEMBLY_TIMEOUT_MS: u64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RawTunnelKind {
    /// Full Meshtastic/MeshCore frame as heard on air (type 1).
    MeshCore,
    /// Reticulum payload with the RNode 1-byte header stripped (type 2).
    RNode,
}

impl RawTunnelKind {
    pub fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::MeshCore),
            2 => Some(Self::RNode),
            _ => None,
        }
    }

    pub fn wire_value(self) -> u8 {
        match self {
            Self::MeshCore => 1,
            Self::RNode => 2,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::MeshCore => "jencore",
            Self::RNode => "jenrnode",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTunnelChunk {
    pub kind: RawTunnelKind,
    pub sequence: u8,
    pub index: u8,
    pub count: u8,
    pub bytes: Vec<u8>,
}

/// Parse the `JRAW` header. Returns `None` for ordinary encrypted packets.
pub fn parse_chunk(encrypted: &[u8]) -> Option<RawTunnelChunk> {
    if encrypted.len() < HEADER_LEN || encrypted[..4] != MAGIC {
        return None;
    }
    if encrypted[4] != VERSION {
        return None;
    }
    let kind = RawTunnelKind::from_wire(encrypted[5])?;
    let sequence = encrypted[6];
    let index = encrypted[7];
    let count = encrypted[8];
    if count == 0 || count > MAX_CHUNKS || index >= count {
        return None;
    }

    Some(RawTunnelChunk {
        kind,
        sequence,
        index,
        count,
        bytes: encrypted[HEADER_LEN..].to_vec(),
    })
}

/// Where a raw frame was ingested from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawTunnelSource {
    /// Read from the physical node's PhoneAPI stream.
    Physical,
    /// Read from a broker feed without RF metadata.
    Mqtt,
}

impl RawTunnelSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Physical => "physical",
            Self::Mqtt => "mqtt",
        }
    }
}

/// A fully reassembled raw frame plus the enclosing packet's receive metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct RawTunnelFrame {
    pub kind: RawTunnelKind,
    pub source: RawTunnelSource,
    pub sequence: u8,
    pub frame: Vec<u8>,
    pub gateway: u32,
    pub channel: u32,
    pub rx_time: u32,
    pub rssi: Option<i32>,
    pub snr: Option<f32>,
    pub frequency_error: Option<f32>,
    pub coding_rate: Option<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AssemblerResult {
    /// Not a JRAW packet; treat it as ordinary encrypted traffic.
    NotRaw,
    /// A chunk was accepted but the frame is not complete yet.
    Incomplete,
    /// The frame is complete.
    Complete(RawTunnelFrame),
}

#[derive(Debug)]
struct Partial {
    count: u8,
    chunks: Vec<Option<Vec<u8>>>,
    last_seen_ms: u64,
    gateway: u32,
    channel: u32,
    rx_time: u32,
    rssi: Option<i32>,
    snr: Option<f32>,
    frequency_error: Option<f32>,
    coding_rate: Option<u8>,
}

impl Partial {
    fn new(
        chunk: &RawTunnelChunk,
        now_ms: u64,
        packet: &pb::MeshPacket,
        diagnostics: NexusDiagnostics,
    ) -> Self {
        Self {
            count: chunk.count,
            chunks: vec![None; chunk.count as usize],
            last_seen_ms: now_ms,
            gateway: packet.from,
            channel: packet.channel,
            rx_time: packet.rx_time,
            rssi: Some(packet.rx_rssi),
            snr: Some(packet.rx_snr),
            frequency_error: diagnostics.frequency_error,
            coding_rate: diagnostics.coding_rate,
        }
    }

    fn complete(&self) -> Option<Vec<u8>> {
        let mut frame = Vec::new();
        for chunk in &self.chunks {
            frame.extend_from_slice(chunk.as_ref()?);
        }
        Some(frame)
    }
}

/// Reassembles one- and two-chunk JRAW frames, keyed by kind, sequence and
/// gateway so two senders cannot mix their chunks.
#[derive(Debug, Default)]
pub struct RawTunnelAssembler {
    partials: HashMap<(RawTunnelKind, u8, u32), Partial>,
}

impl RawTunnelAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn accept(
        &mut self,
        packet: &pb::MeshPacket,
        now_ms: u64,
        diagnostics: NexusDiagnostics,
    ) -> AssemblerResult {
        let Some(pb::mesh_packet::PayloadVariant::Encrypted(encrypted)) = &packet.payload_variant
        else {
            return AssemblerResult::NotRaw;
        };
        let Some(chunk) = parse_chunk(encrypted) else {
            return AssemblerResult::NotRaw;
        };

        self.prune(now_ms);

        if chunk.count == 1 {
            return AssemblerResult::Complete(RawTunnelFrame {
                kind: chunk.kind,
                source: RawTunnelSource::Physical,
                sequence: chunk.sequence,
                frame: chunk.bytes,
                gateway: packet.from,
                channel: packet.channel,
                rx_time: packet.rx_time,
                rssi: Some(packet.rx_rssi),
                snr: Some(packet.rx_snr),
                frequency_error: diagnostics.frequency_error,
                coding_rate: diagnostics.coding_rate,
            });
        }

        let key = (chunk.kind, chunk.sequence, packet.from);
        let needs_new = self
            .partials
            .get(&key)
            .is_none_or(|partial| partial.count != chunk.count);
        if needs_new {
            self.partials
                .insert(key, Partial::new(&chunk, now_ms, packet, diagnostics));
        }

        let Some(partial) = self.partials.get_mut(&key) else {
            return AssemblerResult::Incomplete;
        };
        partial.last_seen_ms = now_ms;
        partial.gateway = packet.from;
        partial.channel = packet.channel;
        partial.rx_time = packet.rx_time;
        partial.rssi = Some(packet.rx_rssi);
        partial.snr = Some(packet.rx_snr);
        partial.frequency_error = diagnostics.frequency_error;
        partial.coding_rate = diagnostics.coding_rate;
        partial.chunks[chunk.index as usize] = Some(chunk.bytes);

        let Some(frame) = partial.complete() else {
            return AssemblerResult::Incomplete;
        };
        let kind = chunk.kind;
        let sequence = chunk.sequence;
        let result = RawTunnelFrame {
            kind,
            source: RawTunnelSource::Physical,
            sequence,
            frame,
            gateway: partial.gateway,
            channel: partial.channel,
            rx_time: partial.rx_time,
            rssi: partial.rssi,
            snr: partial.snr,
            frequency_error: partial.frequency_error,
            coding_rate: partial.coding_rate,
        };
        self.partials.remove(&key);
        AssemblerResult::Complete(result)
    }

    fn prune(&mut self, now_ms: u64) {
        self.partials.retain(|_, partial| {
            now_ms.saturating_sub(partial.last_seen_ms) <= REASSEMBLY_TIMEOUT_MS
        });
    }
}

/// Topic for one raw feed: `{root}/{region}/!{gatewayhex}`.
pub fn feed_topic(root: &str, region: &str, gateway: u32) -> String {
    let root = root.trim_end_matches('/');
    format!("{root}/{region}/!{gateway:08x}")
}

/// The parts of a Reticulum packet that can be read without its keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReticulumInfo {
    pub packet_type: u8,
    pub context: u8,
    pub hops: u8,
    pub destination_hash: String,
    pub public_key: Option<Vec<u8>>,
    pub node_name: Option<String>,
}

pub fn reticulum_packet_type_name(packet_type: u8) -> &'static str {
    match packet_type {
        0 => "DATA",
        1 => "ANNOUNCE",
        2 => "LINKREQUEST",
        3 => "PROOF",
        _ => "UNKNOWN",
    }
}

pub fn reticulum_context_name(context: u8) -> &'static str {
    match context {
        0x00 => "NONE",
        0x01 => "RESOURCE",
        0x02 => "RESOURCE_ADV",
        0x03 => "RESOURCE_REQ",
        0x04 => "RESOURCE_HMU",
        0x05 => "RESOURCE_PRF",
        0x06 => "RESOURCE_ICL",
        0x07 => "RESOURCE_RCL",
        0x08 => "CACHE_REQUEST",
        0x09 => "REQUEST",
        0x0A => "RESPONSE",
        0x0B => "PATH_RESPONSE",
        0x0C => "COMMAND",
        0x0D => "COMMAND_STATUS",
        0x0E => "CHANNEL",
        0xFA => "KEEPALIVE",
        0xFB => "LINKIDENTIFY",
        0xFC => "LINKCLOSE",
        0xFD => "LINKPROOF",
        0xFE => "LRRTT",
        0xFF => "LRPROOF",
        _ => "UNKNOWN",
    }
}

/// Parse the fixed header of a Reticulum packet. Announce payloads expose the
/// destination hash, public key and any printable app-data name.
pub fn parse_reticulum_frame(frame: &[u8]) -> Option<ReticulumInfo> {
    const DST_LEN: usize = 16;
    if frame.len() < 2 + DST_LEN + 1 {
        return None;
    }
    let flags = frame[0];
    let header_type = (flags >> 6) & 0x03;
    if header_type > 1 {
        return None;
    }
    let packet_type = flags & 0x03;
    let hops = frame[1];
    let mut offset = 2;
    if header_type == 1 {
        offset += DST_LEN;
    }
    if frame.len() < offset + DST_LEN + 1 {
        return None;
    }
    let destination_hash = hex(&frame[offset..offset + DST_LEN]);
    offset += DST_LEN;
    let context = frame[offset];
    offset += 1;
    let data = &frame[offset..];

    let mut public_key = None;
    let mut node_name = None;
    if packet_type == 1 && data.len() >= 64 + 10 + 10 + 64 {
        public_key = Some(data[..64].to_vec());
        let with_ratchet = (flags & 0x20) != 0;
        let app_at = 64 + 10 + 10 + 64 + if with_ratchet { 32 } else { 0 };
        if let Some(app_data) = data.get(app_at..).filter(|bytes| !bytes.is_empty()) {
            if let Ok(text) = std::str::from_utf8(app_data) {
                let text = text.trim().trim_end_matches('\0');
                if !text.is_empty() && text.chars().all(|ch| !ch.is_control()) {
                    node_name = Some(text.to_owned());
                }
            }
        }
    }

    Some(ReticulumInfo {
        packet_type,
        context,
        hops,
        destination_hash,
        public_key,
        node_name,
    })
}

/// The parts of a MeshCore frame that can be read without its crypto keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshCoreInfo {
    pub route_type: u8,
    pub payload_type: u8,
    pub path_hash_size: u8,
    pub path_hex: String,
    pub payload_text: Option<String>,
    pub sender_hash: Option<String>,
    pub destination_hash: Option<String>,
    pub channel_hash: Option<u8>,
    pub public_key: Option<Vec<u8>>,
    pub node_name: Option<String>,
    pub node_type: Option<u8>,
}

pub fn meshcore_route_name(route: u8) -> &'static str {
    match route {
        0 => "transport-flood",
        1 => "flood",
        2 => "direct",
        3 => "transport-direct",
        _ => "route",
    }
}

pub fn meshcore_payload_name(payload: u8) -> &'static str {
    match payload {
        0x00 => "REQ",
        0x01 => "RESPONSE",
        0x02 => "TXT_MSG",
        0x03 => "ACK",
        0x04 => "ADVERT",
        0x05 => "GRP_TXT",
        0x06 => "GRP_DATA",
        0x07 => "ANON_REQ",
        0x08 => "PATH",
        0x09 => "TRACE",
        0x0A => "MULTIPART",
        0x0B => "CONTROL",
        0x0F => "RAW_CUSTOM",
        _ => "UNKNOWN",
    }
}

/// Parse the MeshCore frame header (same rules as the Jentastic app parser).
pub fn parse_meshcore_frame(frame: &[u8]) -> Option<MeshCoreInfo> {
    if frame.len() < 2 {
        return None;
    }
    let header = frame[0];
    if header & 0xC0 != 0 {
        return None;
    }
    let route_type = header & 0x03;
    let payload_type = (header >> 2) & 0x0F;

    let mut offset = 1;
    if route_type == 0 || route_type == 3 {
        if offset + 4 > frame.len() {
            return None;
        }
        offset += 4;
    }
    if offset >= frame.len() {
        return None;
    }
    let path_len_byte = frame[offset];
    offset += 1;
    if path_len_byte >> 6 == 3 {
        return None;
    }
    let hash_size = (path_len_byte >> 6) + 1;
    let hash_count = path_len_byte & 0x3F;
    let path_bytes = (hash_count as usize) * (hash_size as usize);
    if offset + path_bytes > frame.len() {
        return None;
    }

    let mut path_hex = String::with_capacity(path_bytes * 2);
    for chunk in frame[offset..offset + path_bytes].chunks(hash_size as usize) {
        path_hex.push_str(&hex(chunk));
    }
    offset += path_bytes;
    let payload = &frame[offset..];

    let mut sender_hash = None;
    let mut destination_hash = None;
    let mut channel_hash = None;
    let mut public_key = None;
    let mut node_name = None;
    let mut node_type = None;
    let mut payload_text = None;

    const ADVERT_APP_DATA_AT: usize = 32 + 4 + 64;
    match payload_type {
        0x02 | 0x08 if payload.len() >= 2 => {
            destination_hash = Some(hex(&payload[0..1]));
            sender_hash = Some(hex(&payload[1..2]));
            if payload_type == 0x02 {
                payload_text = printable_text(&payload[2..]);
            }
        }
        0x05 => {
            channel_hash = payload.first().copied();
            if payload.len() > 1 {
                payload_text = printable_text(&payload[1..]);
            }
        }
        0x04 if payload.len() > ADVERT_APP_DATA_AT => {
            let flags = payload[ADVERT_APP_DATA_AT];
            node_type = Some(flags & 0x0F);
            let mut at = ADVERT_APP_DATA_AT + 1;
            if flags & 0x10 != 0 {
                at += 8;
            }
            if flags & 0x20 != 0 {
                at += 2;
            }
            if flags & 0x40 != 0 {
                at += 2;
            }
            if flags & 0x80 != 0 && at < payload.len() {
                let name = String::from_utf8_lossy(&payload[at..]).trim().to_owned();
                if !name.is_empty() {
                    node_name = Some(name);
                }
            }
            if payload.len() >= 32 {
                let key = payload[..32].to_vec();
                public_key = Some(key.clone());
                sender_hash = Some(hex(&key[..(hash_size as usize).min(key.len())]));
            }
        }
        _ => {}
    }

    Some(MeshCoreInfo {
        route_type,
        payload_type,
        path_hash_size: hash_size,
        path_hex,
        payload_text,
        sender_hash,
        destination_hash,
        channel_hash,
        public_key,
        node_name,
        node_type,
    })
}

fn printable_text(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes)
        .ok()?
        .trim()
        .trim_end_matches('\0');
    if text.is_empty() || text.chars().any(|ch| ch.is_control()) {
        None
    } else {
        Some(text.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(encrypted: Vec<u8>) -> pb::MeshPacket {
        pb::MeshPacket {
            from: 0x1122_3344,
            channel: 0,
            rx_time: 123,
            rx_rssi: -50,
            rx_snr: 7.5,
            payload_variant: Some(pb::mesh_packet::PayloadVariant::Encrypted(encrypted)),
            ..Default::default()
        }
    }

    fn accept(
        assembler: &mut RawTunnelAssembler,
        packet: &pb::MeshPacket,
        now_ms: u64,
    ) -> AssemblerResult {
        assembler.accept(packet, now_ms, NexusDiagnostics::default())
    }

    fn jraw(kind: u8, sequence: u8, index: u8, count: u8, data: &[u8]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.push(VERSION);
        out.push(kind);
        out.push(sequence);
        out.push(index);
        out.push(count);
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn ordinary_encrypted_packets_are_not_raw() {
        let mut assembler = RawTunnelAssembler::new();
        assert_eq!(
            accept(&mut assembler, &packet(b"ordinary".to_vec()), 0),
            AssemblerResult::NotRaw
        );
        assert_eq!(
            accept(&mut assembler, &pb::MeshPacket::default(), 0),
            AssemblerResult::NotRaw
        );
    }

    #[test]
    fn parses_and_accepts_a_single_chunk() {
        let mut assembler = RawTunnelAssembler::new();
        let result = accept(&mut assembler, &packet(jraw(1, 9, 0, 1, b"meshcore")), 0);
        let AssemblerResult::Complete(frame) = result else {
            panic!("expected a complete frame");
        };
        assert_eq!(frame.kind, RawTunnelKind::MeshCore);
        assert_eq!(frame.sequence, 9);
        assert_eq!(frame.frame, b"meshcore");
        assert_eq!(frame.gateway, 0x1122_3344);
        assert_eq!(frame.rx_time, 123);
        assert_eq!(frame.rssi, Some(-50));
        assert_eq!(frame.snr, Some(7.5));
        assert_eq!(frame.source, RawTunnelSource::Physical);
    }

    #[test]
    fn reassembles_two_chunks_in_any_order() {
        let mut assembler = RawTunnelAssembler::new();
        let first = accept(&mut assembler, &packet(jraw(2, 3, 0, 2, b"AAAA")), 0);
        assert_eq!(first, AssemblerResult::Incomplete);
        let second = accept(&mut assembler, &packet(jraw(2, 3, 1, 2, b"BBBB")), 10);
        let AssemblerResult::Complete(frame) = second else {
            panic!("expected the frame to complete");
        };
        assert_eq!(frame.kind, RawTunnelKind::RNode);
        assert_eq!(frame.frame, b"AAAABBBB");

        // Out of order too.
        let mut assembler = RawTunnelAssembler::new();
        assert_eq!(
            accept(&mut assembler, &packet(jraw(1, 4, 1, 2, b"BB")), 0),
            AssemblerResult::Incomplete
        );
        let result = accept(&mut assembler, &packet(jraw(1, 4, 0, 2, b"AA")), 1);
        let AssemblerResult::Complete(frame) = result else {
            panic!("expected the frame to complete");
        };
        assert_eq!(frame.frame, b"AABB");
    }

    #[test]
    fn interleaved_gateways_do_not_mix_chunks() {
        let mut assembler = RawTunnelAssembler::new();
        let mut first = packet(jraw(1, 9, 0, 2, b"AA"));
        first.from = 0x1111_1111;
        let mut second = packet(jraw(1, 9, 0, 2, b"BB"));
        second.from = 0x2222_2222;

        assert_eq!(
            accept(&mut assembler, &first, 0),
            AssemblerResult::Incomplete
        );
        assert_eq!(
            accept(&mut assembler, &second, 1),
            AssemblerResult::Incomplete
        );

        let mut first_tail = packet(jraw(1, 9, 1, 2, b"11"));
        first_tail.from = 0x1111_1111;
        let result = accept(&mut assembler, &first_tail, 2);
        let AssemblerResult::Complete(frame) = result else {
            panic!("expected the first gateway frame");
        };
        assert_eq!(frame.gateway, 0x1111_1111);
        assert_eq!(frame.frame, b"AA11");

        let mut second_tail = packet(jraw(1, 9, 1, 2, b"22"));
        second_tail.from = 0x2222_2222;
        let result = accept(&mut assembler, &second_tail, 3);
        let AssemblerResult::Complete(frame) = result else {
            panic!("expected the second gateway frame");
        };
        assert_eq!(frame.gateway, 0x2222_2222);
        assert_eq!(frame.frame, b"BB22");
    }

    #[test]
    fn stale_partials_are_dropped() {
        let mut assembler = RawTunnelAssembler::new();
        assert_eq!(
            accept(&mut assembler, &packet(jraw(1, 5, 0, 2, b"AA")), 0),
            AssemblerResult::Incomplete
        );
        // A new frame after the timeout starts clean.
        let result = accept(
            &mut assembler,
            &packet(jraw(1, 5, 1, 2, b"BB")),
            REASSEMBLY_TIMEOUT_MS + 1,
        );
        assert_eq!(result, AssemblerResult::Incomplete);
    }

    #[test]
    fn rejects_malformed_headers() {
        assert!(parse_chunk(b"").is_none());
        assert!(parse_chunk(b"JRA").is_none());
        assert!(parse_chunk(b"XRAW\x01\x01\x01\x00\x01x").is_none());
        assert!(parse_chunk(b"JRAW\x02\x01\x01\x00\x01x").is_none());
        assert!(parse_chunk(b"JRAW\x01\x03\x01\x00\x01x").is_none());
        assert!(parse_chunk(b"JRAW\x01\x01\x01\x00\x00x").is_none());
        assert!(parse_chunk(b"JRAW\x01\x01\x01\x00\x03x").is_none());
        assert!(parse_chunk(b"JRAW\x01\x01\x01\x01\x01x").is_none());
    }

    #[test]
    fn carries_nexus_diagnostics_into_frames() {
        let mut assembler = RawTunnelAssembler::new();
        let diagnostics = NexusDiagnostics {
            frequency_error: Some(-123.0),
            coding_rate: Some(3),
        };
        let result = assembler.accept(&packet(jraw(1, 11, 0, 1, b"x")), 0, diagnostics);
        let AssemblerResult::Complete(frame) = result else {
            panic!("expected a complete frame");
        };
        assert_eq!(frame.frequency_error, Some(-123.0));
        assert_eq!(frame.coding_rate, Some(3));
    }

    #[test]
    fn builds_feed_topics() {
        assert_eq!(
            feed_topic("jencore/", "EU_868", 0xAB),
            "jencore/EU_868/!000000ab"
        );
        assert_eq!(feed_topic("jenrnode", "US", 0x1), "jenrnode/US/!00000001");
        assert_eq!(RawTunnelKind::MeshCore.label(), "jencore");
        assert_eq!(RawTunnelKind::RNode.label(), "jenrnode");
    }

    #[test]
    fn parses_meshcore_txt_and_group_headers() {
        // route=flood (1), payload=TXT_MSG (2), empty path, dest/sender bytes.
        let frame = [0x09, 0x00, 0xAA, 0xBB, b'h', b'i'];
        let info = parse_meshcore_frame(&frame).expect("parse meshcore");
        assert_eq!(info.route_type, 1);
        assert_eq!(info.payload_type, 2);
        assert_eq!(info.path_hex, "");
        assert_eq!(info.path_hash_size, 1);
        assert_eq!(info.destination_hash.as_deref(), Some("aa"));
        assert_eq!(info.sender_hash.as_deref(), Some("bb"));
        assert_eq!(info.payload_text.as_deref(), Some("hi"));
        assert_eq!(meshcore_route_name(1), "flood");
        assert_eq!(meshcore_payload_name(2), "TXT_MSG");

        // Group text: channel hash is the first payload byte.
        let group = [0x15, 0x00, 0x7F];
        let info = parse_meshcore_frame(&group).expect("parse group text");
        assert_eq!(info.payload_type, 5);
        assert_eq!(info.channel_hash, Some(0x7F));
        assert_eq!(meshcore_payload_name(5), "GRP_TXT");

        let text = [0x15, 0x00, 0x7F, b'h', b'i'];
        let info = parse_meshcore_frame(&text).expect("parse group text");
        assert_eq!(info.payload_text.as_deref(), Some("hi"));
    }

    #[test]
    fn parses_meshcore_path_and_rejects_bad_headers() {
        // route=direct (2), payload=ADVERT (4), path: 2 hashes of 1 byte.
        let mut frame = vec![(4 << 2) | 2, 0x02, 0x11, 0x22];
        frame.extend_from_slice(&[0u8; 100]);
        frame.push(0x80); // flags: has name
        frame.extend_from_slice(b"Node");
        let info = parse_meshcore_frame(&frame).expect("parse advert");
        assert_eq!(info.payload_type, 4);
        assert_eq!(info.path_hex, "1122");
        assert_eq!(info.path_hash_size, 1);
        assert_eq!(info.node_name.as_deref(), Some("Node"));

        assert!(parse_meshcore_frame(&[0x80, 0x00]).is_none()); // version bits set
        assert!(parse_meshcore_frame(&[0x09, 0xC0]).is_none()); // reserved path mode
        assert!(parse_meshcore_frame(&[0x09]).is_none());
    }
    #[test]
    fn parses_reticulum_announce_names() {
        let mut frame = vec![0x01, 3]; // announce, 3 hops
        frame.extend_from_slice(&[0xAB; 16]); // destination hash
        frame.push(0x00); // context
        frame.extend_from_slice(&[0x11; 64]); // public key
        frame.extend_from_slice(&[0x22; 10]); // name hash
        frame.extend_from_slice(&[0x33; 10]); // random hash
        frame.extend_from_slice(&[0x44; 64]); // signature
        frame.extend_from_slice(b"Test Node");
        let info = parse_reticulum_frame(&frame).expect("parse announce");
        assert_eq!(info.packet_type, 1);
        assert_eq!(info.hops, 3);
        assert_eq!(info.destination_hash, "abababababababababababababababab");
        assert_eq!(info.node_name.as_deref(), Some("Test Node"));
        assert_eq!(info.public_key.as_ref().map(Vec::len), Some(64));
    }
}
