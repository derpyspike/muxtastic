//! Read-only MQTT source for the web history.
//!
//! `muxtastic --web-only` can run the dashboard without a physical node or the
//! mux server, feeding SQLite from a broker instead:
//!
//! * `msh/#` and `raw/#` — decode `ServiceEnvelope` protobufs and record the
//!   contained `MeshPacket`.
//! * `jencore/#` and `jenrnode/#` — record the reassembled raw frame bytes.
//!
//! The source never publishes, so it cannot create MQTT loops. Retained
//! messages are skipped to avoid replaying stale history.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use meshtastic::protobufs::{self as pb, from_radio};
use meshtastic::Message;
use muxtastic_core::config::WebMqttConfig;
use muxtastic_core::mqtt::{normalize_broker_host, sanitize_client_id};
use muxtastic_core::raw_tunnel::{RawTunnelFrame, RawTunnelKind, RawTunnelSource};
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS, TlsConfiguration, Transport};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::db::DbSource;
use crate::util::now_unix;
use crate::Database;

/// JRAW frames fit two 247-byte chunks; anything larger is not a feed frame.
const MAX_RAW_FRAME: usize = 512;

/// Optional predicate for ignoring packets published by one of the local
/// bridges, so the read-only source does not duplicate their history.
pub type GatewayFilter = dyn Fn(&str) -> bool + Send + Sync;

/// Connect, subscribe and feed the database until shutdown.
pub async fn run(
    db: Arc<Database>,
    config: WebMqttConfig,
    connected: Arc<AtomicBool>,
    skip_gateway: Option<Arc<GatewayFilter>>,
    mut shutdown: watch::Receiver<bool>,
) {
    if !config.enabled {
        info!("web MQTT source disabled");
        return;
    }

    let mut backoff = 1u64;
    loop {
        if *shutdown.borrow() {
            break;
        }

        let host = normalize_broker_host(&config.broker);
        let mut options = MqttOptions::new(client_id(&config), host.as_str(), config.port);
        options.set_keep_alive(Duration::from_secs(config.keepalive.max(1)));
        if !config.username.is_empty() {
            options.set_credentials(config.username.as_str(), config.password.as_str());
        }
        if config.tls {
            options.set_transport(Transport::tls_with_config(TlsConfiguration::default()));
        }

        let (client, mut eventloop) = AsyncClient::new(options, 10);
        info!(
            broker = %config.broker,
            port = config.port,
            tls = config.tls,
            "web MQTT source connecting"
        );

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        connected.store(false, Ordering::SeqCst);
                        info!("web MQTT source stopped");
                        return;
                    }
                }
                event = eventloop.poll() => {
                    match event {
                        Ok(Event::Incoming(Packet::ConnAck(_))) => {
                            connected.store(true, Ordering::SeqCst);
                            backoff = 1;
                            info!("web MQTT source connected");
                            for topic in &config.topics {
                                if let Err(error) =
                                    client.subscribe(topic.as_str(), QoS::AtMostOnce).await
                                {
                                    warn!(topic, %error, "web MQTT source subscribe failed");
                                }
                            }
                        }
                        Ok(Event::Incoming(Packet::Publish(publish))) => {
                            if publish.retain {
                                debug!(topic = %publish.topic, "skipping retained MQTT message");
                                continue;
                            }
                            ingest(
                                &db,
                                &publish.topic,
                                publish.payload.as_ref(),
                                skip_gateway.as_deref(),
                            );
                        }
                        Ok(_) => {}
                        Err(error) => {
                            warn!(%error, "web MQTT source connection lost");
                            break;
                        }
                    }
                }
            }
        }

        connected.store(false, Ordering::SeqCst);
        if *shutdown.borrow() {
            break;
        }
        info!(seconds = backoff, "web MQTT source reconnecting");
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

    connected.store(false, Ordering::SeqCst);
    info!("web MQTT source stopped");
}

fn client_id(config: &WebMqttConfig) -> String {
    let raw = if config.client_id.is_empty() {
        "muxtastic-webd"
    } else {
        config.client_id.as_str()
    };
    sanitize_client_id(raw)
}

fn ingest(db: &Database, topic: &str, payload: &[u8], skip_gateway: Option<&GatewayFilter>) {
    let topic_gateway = gateway_from_topic(topic).map(|gateway| format!("!{gateway:08x}"));
    if is_skipped(skip_gateway, topic_gateway.as_deref()) {
        debug!(%topic, "skipping a packet published by a local bridge");
        return;
    }

    if let Some(kind) = feed_kind(topic) {
        let Some(gateway) = gateway_from_topic(topic) else {
            debug!(%topic, "raw feed topic has no gateway id");
            return;
        };
        if payload.is_empty() || payload.len() > MAX_RAW_FRAME {
            warn!(
                %topic,
                bytes = payload.len(),
                "ignoring MQTT raw frame outside the JRAW size range"
            );
            return;
        }
        db.record_raw_frame(RawTunnelFrame {
            kind,
            source: RawTunnelSource::Mqtt,
            sequence: 0,
            frame: payload.to_vec(),
            gateway,
            channel: 0,
            rx_time: now_unix() as u32,
            rssi: None,
            snr: None,
            frequency_error: None,
            coding_rate: None,
        });
        return;
    }

    let Ok(envelope) = pb::ServiceEnvelope::decode(payload) else {
        debug!(%topic, "ignoring MQTT message that is not a ServiceEnvelope");
        return;
    };
    if is_skipped(skip_gateway, Some(envelope.gateway_id.as_str())) {
        debug!(%topic, "skipping a packet published by a local bridge");
        return;
    }
    let Some(mut packet) = envelope.packet else {
        return;
    };
    if packet.transport_mechanism == 0 {
        packet.transport_mechanism = pb::mesh_packet::TransportMechanism::TransportMqtt as i32;
    }

    let receiver = if envelope.gateway_id.is_empty() {
        gateway_from_topic(topic).map(|gateway| format!("!{gateway:08x}"))
    } else {
        Some(envelope.gateway_id)
    };

    if let Some(channel_name) = msh_channel_name(topic) {
        let index = channel_index(channel_name);
        packet.channel = index;

        let channel = pb::Channel {
            index: index as i32,
            role: pb::channel::Role::Secondary as i32,
            settings: Some(pb::ChannelSettings {
                name: channel_name.to_owned(),
                ..Default::default()
            }),
        };
        db.record_frame(
            pb::FromRadio {
                id: 0,
                payload_variant: Some(from_radio::PayloadVariant::Channel(channel)),
            },
            None,
            DbSource::Mqtt,
            receiver.clone(),
        );
    }

    db.record_frame(
        pb::FromRadio {
            id: 0,
            payload_variant: Some(from_radio::PayloadVariant::Packet(packet)),
        },
        None,
        DbSource::Mqtt,
        receiver,
    );
}

fn is_skipped(filter: Option<&GatewayFilter>, gateway: Option<&str>) -> bool {
    match (filter, gateway) {
        (Some(filter), Some(gateway)) if !gateway.is_empty() => filter(gateway),
        _ => false,
    }
}

fn feed_kind(topic: &str) -> Option<RawTunnelKind> {
    match topic.split('/').next()? {
        "jencore" => Some(RawTunnelKind::MeshCore),
        "jenrnode" => Some(RawTunnelKind::RNode),
        _ => None,
    }
}

fn gateway_from_topic(topic: &str) -> Option<u32> {
    let last = topic.rsplit('/').next()?;
    let hex = last.strip_prefix('!')?;
    u32::from_str_radix(hex, 16).ok()
}

fn msh_channel_name(topic: &str) -> Option<&str> {
    let mut parts = topic.split('/');
    if parts.next()? != "msh" {
        return None;
    }
    let _region = parts.next()?;
    if parts.next()? != "2" {
        return None;
    }
    if parts.next()? != "e" {
        return None;
    }
    let name = parts.next()?;
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Stable channel bucket for MQTT topic names. The real local channel index is
/// not meaningful across brokers, so the dashboard uses a deterministic name
/// bucket and records the name in the `channels` table.
fn channel_index(name: &str) -> u32 {
    let mut hash = 0x811C_9DC5u32;
    for byte in name.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash % 256
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn skips_local_gateway_ids() {
        let filter: &GatewayFilter = &|gateway: &str| gateway == "!12345678";
        assert!(is_skipped(Some(filter), Some("!12345678")));
        assert!(!is_skipped(Some(filter), Some("!12345679")));
        assert!(!is_skipped(Some(filter), Some("")));
        assert!(!is_skipped(None, Some("!12345678")));
    }

    #[test]
    fn parses_topics() {
        assert_eq!(
            feed_kind("jencore/EU_868/!11223344"),
            Some(RawTunnelKind::MeshCore)
        );
        assert_eq!(
            feed_kind("jenrnode/EU_868/!11223344"),
            Some(RawTunnelKind::RNode)
        );
        assert_eq!(feed_kind("msh/EU_868/2/e/x/!1"), None);
        assert_eq!(
            gateway_from_topic("jencore/EU_868/!11223344"),
            Some(0x1122_3344)
        );
        assert_eq!(gateway_from_topic("jencore/EU_868/11223344"), None);
        assert_eq!(
            msh_channel_name("msh/EU_868/2/e/LongFast/!11223344"),
            Some("LongFast")
        );
        assert_eq!(msh_channel_name("msh/EU_868/2/e/"), None);
        assert_eq!(msh_channel_name("raw/EU_868/!11223344"), None);
        assert_eq!(channel_index("LongFast"), channel_index("LongFast"));
        assert_ne!(channel_index("LongFast"), channel_index("MediumFast"));
    }

    #[tokio::test]
    async fn ingests_service_envelopes_and_raw_feeds() {
        let (db, receiver) = Database::open(":memory:").expect("open db");
        tokio::spawn(crate::db::run_writer(Arc::downgrade(&db), receiver));

        let data = pb::Data {
            portnum: pb::PortNum::TextMessageApp as i32,
            payload: b"mqtt hello".to_vec(),
            ..Default::default()
        };
        let packet = pb::MeshPacket {
            id: 77,
            from: 42,
            to: 0xFFFF_FFFF,
            rx_time: 123,
            payload_variant: Some(pb::mesh_packet::PayloadVariant::Decoded(data)),
            ..Default::default()
        };
        let envelope = pb::ServiceEnvelope {
            packet: Some(packet),
            channel_id: "LongFast".into(),
            gateway_id: "!0000002a".into(),
        };
        ingest(
            &db,
            "msh/EU_868/2/e/LongFast/!0000002a",
            &envelope.encode_to_vec(),
            None,
        );
        let mut second_gateway = envelope.clone();
        second_gateway.gateway_id = "!0000002b".into();
        ingest(
            &db,
            "msh/EU_868/2/e/LongFast/!0000002b",
            &second_gateway.encode_to_vec(),
            None,
        );
        ingest(
            &db,
            "jencore/EU_868/!11223344",
            &vec![0x41; MAX_RAW_FRAME + 1],
            None,
        );
        ingest(
            &db,
            "jencore/EU_868/!11223344",
            &[0x09, 0x00, 0xAA, 0xBB, b'h', b'i'],
            None,
        );

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let messages = db.query_messages(None, 10).expect("messages");
            let raw = db.query_raw_frames(Some(1), 10).expect("raw");
            if !messages.is_empty() && !raw.is_empty() {
                assert_eq!(messages[0].text, "mqtt hello");
                assert_eq!(messages[0].channel_name, "LongFast");
                assert_eq!(messages[0].source, "mqtt");
                assert!(!messages[0].via_mqtt);
                assert_eq!(messages[0].reception_count, 2);
                assert_eq!(messages[0].gateway_count, 2);
                let receptions = db.query_receptions(42, 77).expect("receptions");
                assert_eq!(receptions.len(), 2);
                assert_eq!(raw.len(), 1);
                assert_eq!(raw[0].gateway_id, "!11223344");
                assert_eq!(raw[0].source, "mqtt");
                assert_eq!(raw[0].rx_rssi, None);
                assert_eq!(raw[0].rx_snr, None);
                assert_eq!(raw[0].payload_name.as_deref(), Some("TXT_MSG"));
                let stats = db.query_stats().expect("stats");
                assert_eq!(stats.totals.mqtt_source, 1);
                assert_eq!(stats.totals.via_mqtt, 0);
                assert_eq!(stats.totals.receptions, 2);
                assert_eq!(stats.totals.multi_heard, 1);
                return;
            }
            assert!(
                Instant::now() < deadline,
                "MQTT source ingestion did not complete"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}
