use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use meshtastic::protobufs::{self as pb, from_radio};
use meshtastic::Message;
use tracing::info;

use crate::app::AppState;
use crate::physical;

/// Simulated physical node for development without hardware.
pub async fn run(state: Arc<AppState>, node_num: u32) {
    {
        let mut cache = state
            .cache
            .write()
            .unwrap_or_else(|error| error.into_inner());
        cache.my_node_num = node_num;
        cache.my_info = Some(pb::MyNodeInfo {
            my_node_num: cache.my_node_num,
            reboot_count: 42,
            pio_env: "heltec-v3".into(),
            ..Default::default()
        });
    }
    state.connected.store(true, Ordering::SeqCst);

    let channel = pb::FromRadio {
        id: 0,
        payload_variant: Some(from_radio::PayloadVariant::Channel(pb::Channel {
            index: 0,
            role: pb::channel::Role::Primary as i32,
            settings: Some(pb::ChannelSettings {
                name: "LongFast".into(),
                uplink_enabled: true,
                downlink_enabled: true,
                ..Default::default()
            }),
        })),
    };
    physical::handle_from_radio(&state, channel.encode_to_vec()).await;

    let lora = pb::FromRadio {
        id: 0,
        payload_variant: Some(from_radio::PayloadVariant::Config(pb::Config {
            payload_variant: Some(pb::config::PayloadVariant::Lora(pb::config::LoRaConfig {
                use_preset: false,
                bandwidth: 62,
                spread_factor: 7,
                coding_rate: 5,
                region: pb::config::lo_ra_config::RegionCode::Eu868 as i32,
                ..Default::default()
            })),
        })),
    };
    physical::handle_from_radio(&state, lora.encode_to_vec()).await;

    let metadata = pb::FromRadio {
        id: 0,
        payload_variant: Some(from_radio::PayloadVariant::Metadata(pb::DeviceMetadata {
            firmware_version: "2.7.0.mock".into(),
            hw_model: pb::HardwareModel::HeltecV3 as i32,
            role: pb::config::device_config::Role::Client as i32,
            ..Default::default()
        })),
    };
    physical::handle_from_radio(&state, metadata.encode_to_vec()).await;

    let own_node = pb::FromRadio {
        id: 0,
        payload_variant: Some(from_radio::PayloadVariant::NodeInfo(pb::NodeInfo {
            num: node_num,
            user: Some(pb::User {
                id: format!("!{node_num:08x}"),
                long_name: "Mock Node".into(),
                short_name: "MOCK".into(),
                hw_model: pb::HardwareModel::HeltecV3 as i32,
                role: pb::config::device_config::Role::Client as i32,
                ..Default::default()
            }),
            last_heard: now_secs(),
            snr: 8.0,
            hops_away: Some(0),
            device_metrics: Some(pb::DeviceMetrics {
                battery_level: Some(87),
                voltage: Some(4.1),
                ..Default::default()
            }),
            position: Some(pb::Position {
                latitude_i: Some(373_000_000),
                longitude_i: Some(-1_220_000_000),
                altitude: Some(12),
                ..Default::default()
            }),
            ..Default::default()
        })),
    };
    physical::handle_from_radio(&state, own_node.encode_to_vec()).await;
    let peer = fake_peer_nodeinfo_packet();
    physical::handle_from_radio(&state, peer.encode_to_vec()).await;
    info!("mock physical node ready (no hardware)");

    let mut shutdown = state.subscribe_shutdown();
    let mut first = true;
    let mut sent_raw = false;
    let mut sent_trace = false;
    loop {
        let seconds = if first {
            2
        } else {
            10 + rand::random::<u64>() % 21
        };
        first = false;
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(seconds)) => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }

        // Go through the real physical-frame path so MQTT gateway/mirror code
        // sees the same packets a hardware node would produce. The mock also
        // injects Nexus diagnostics (freq error / coding rate) into the raw
        // FromRadio bytes so the chat and raw views can show them.
        let raw = encode_from_radio_with_diagnostics(&fake_text_packet(), -123.0, 3);
        physical::handle_from_radio(&state, raw).await;

        if !sent_raw {
            sent_raw = true;
            let raw =
                encode_from_radio_with_diagnostics(&fake_raw_tunnel_packet(node_num), -42.0, 4);
            physical::handle_from_radio(&state, raw).await;
        }

        if !sent_trace {
            sent_trace = true;
            let raw = encode_from_radio_with_diagnostics(&fake_traceroute_packet(), -80.0, 3);
            physical::handle_from_radio(&state, raw).await;
        }
    }

    info!("mock physical node stopped");
}

fn now_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as u32)
        .unwrap_or(0)
}

fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn encode_from_radio_with_diagnostics(
    packet: &pb::MeshPacket,
    frequency_error: f32,
    coding_rate: u8,
) -> Vec<u8> {
    let mut packet_bytes = packet.encode_to_vec();
    packet_bytes.extend_from_slice(&varint((63 << 3) | 5));
    packet_bytes.extend_from_slice(&frequency_error.to_bits().to_le_bytes());
    packet_bytes.extend_from_slice(&varint(64 << 3));
    packet_bytes.extend_from_slice(&varint(u64::from(coding_rate)));

    let mut out = vec![(2 << 3) | 2];
    out.extend_from_slice(&varint(packet_bytes.len() as u64));
    out.extend_from_slice(&packet_bytes);
    out
}

fn fake_peer_nodeinfo_packet() -> pb::FromRadio {
    let user = pb::User {
        id: "!abcd0001".into(),
        long_name: "Mock Peer".into(),
        short_name: "PEER".into(),
        hw_model: pb::HardwareModel::HeltecV3 as i32,
        role: pb::config::device_config::Role::Client as i32,
        ..Default::default()
    };
    let data = pb::Data {
        portnum: pb::PortNum::NodeinfoApp as i32,
        payload: user.encode_to_vec(),
        ..Default::default()
    };
    pb::FromRadio {
        id: 0,
        payload_variant: Some(from_radio::PayloadVariant::Packet(pb::MeshPacket {
            id: 7001,
            from: 0xABCD_0001,
            to: 0xFFFF_FFFF,
            channel: 0,
            rx_time: now_secs(),
            rx_snr: 9.0,
            rx_rssi: -60,
            hop_start: 3,
            hop_limit: 3,
            transport_mechanism: pb::mesh_packet::TransportMechanism::TransportLora as i32,
            payload_variant: Some(pb::mesh_packet::PayloadVariant::Decoded(data)),
            ..Default::default()
        })),
    }
}

fn fake_traceroute_packet() -> pb::MeshPacket {
    let discovery = pb::RouteDiscovery {
        route: vec![0xABCD_0002, 0xABCD_0003],
        snr_towards: vec![24, 28],
        route_back: vec![0xABCD_0003, 0xABCD_0002],
        snr_back: vec![20, 16],
    };
    let data = pb::Data {
        portnum: pb::PortNum::TracerouteApp as i32,
        payload: discovery.encode_to_vec(),
        request_id: 6001,
        ..Default::default()
    };
    pb::MeshPacket {
        id: 6001,
        from: 0xABCD_0001,
        to: 0xABCD_0004,
        relay_node: 0x04,
        channel: 0,
        rx_time: now_secs(),
        rx_snr: 6.5,
        hop_start: 3,
        hop_limit: 3,
        transport_mechanism: pb::mesh_packet::TransportMechanism::TransportLora as i32,
        payload_variant: Some(pb::mesh_packet::PayloadVariant::Decoded(data)),
        ..Default::default()
    }
}

fn fake_raw_tunnel_packet(node_num: u32) -> pb::MeshPacket {
    let mut encrypted = b"JRAW".to_vec();
    encrypted.extend_from_slice(&[1, 1, 7, 0, 1]);
    encrypted.extend_from_slice(&[0x09, 0x00, 0xAB, 0xCD, b'm', b'o', b'c', b'k']);
    pb::MeshPacket {
        id: 5000,
        from: node_num,
        to: 0xFFFF_FFFF,
        rx_time: now_secs(),
        rx_snr: 6.0,
        payload_variant: Some(pb::mesh_packet::PayloadVariant::Encrypted(encrypted)),
        ..Default::default()
    }
}

fn fake_text_packet() -> pb::MeshPacket {
    let senders = [0xABCD_0001u32, 0xABCD_0002, 0xABCD_0003, 0xABCD_0004];
    let greetings = [
        b"Hello from mock!".as_slice(),
        b"Testing mesh net".as_slice(),
        b"How's the weather?".as_slice(),
        b"73 de MockNode".as_slice(),
    ];
    let from = senders[rand::random::<u32>() as usize % senders.len()];
    let text = greetings[rand::random::<u32>() as usize % greetings.len()];

    let data = pb::Data {
        portnum: pb::PortNum::TextMessageApp as i32,
        payload: text.to_vec(),
        ..Default::default()
    };
    pb::MeshPacket {
        id: 1000 + rand::random::<u32>() % 9000,
        from,
        to: 0xFFFF_FFFF,
        relay_node: 0xABCD_0004,
        rx_time: now_secs(),
        rx_snr: 5.0 + (rand::random::<f32>() * 7.0),
        rx_rssi: -70,
        hop_limit: 3,
        hop_start: 3,
        transport_mechanism: pb::mesh_packet::TransportMechanism::TransportLora as i32,
        payload_variant: Some(pb::mesh_packet::PayloadVariant::Decoded(data)),
        ..Default::default()
    }
}
