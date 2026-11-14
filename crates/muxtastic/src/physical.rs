use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use meshtastic::protobufs::{self as pb, from_radio, to_radio};
use meshtastic::Message;
use muxtastic_core::config::ConnectionType;
use muxtastic_core::protocol::{encode_frame, FrameDecoder};
use muxtastic_core::router::{route_from_physical, PhysicalRoute};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::app::AppState;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
const SERIAL_WAKE: [u8; 32] = [muxtastic_core::protocol::START2; 32];

type BoxReader = Box<dyn AsyncRead + Unpin + Send>;

/// Connection supervisor: connect, run, reconnect with exponential backoff.
pub async fn run(state: Arc<AppState>) {
    let reconnect = state.config.node.reconnect.clone();
    let initial = reconnect.initial_delay_secs.max(1);
    let max = reconnect.max_delay_secs.max(initial);
    let mut delay = initial;
    let mut shutdown = state.subscribe_shutdown();

    loop {
        if *shutdown.borrow() {
            break;
        }

        match connect_once(&state).await {
            Ok(()) => delay = initial,
            Err(error) => warn!(%error, "physical node connection failed"),
        }

        state.connected.store(false, Ordering::SeqCst);
        *state.writer.lock().await = None;

        if !reconnect.enabled || *shutdown.borrow() {
            break;
        }

        info!(seconds = delay, "reconnecting to physical node");
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(delay)) => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
        delay = (delay * reconnect.multiplier.max(1) as u64).min(max);
    }

    info!("physical supervisor stopped");
}

async fn connect_once(state: &Arc<AppState>) -> Result<()> {
    let node = state.config.node.clone();

    let (reader, writer): (BoxReader, crate::app::PhysicalWriter) = match node.connection_type {
        ConnectionType::Serial => {
            let builder = tokio_serial::new(&node.serial_port, node.baud_rate);
            let stream = tokio_serial::SerialStream::open(&builder)
                .with_context(|| format!("failed to open serial port {}", node.serial_port))?;
            let (reader, writer) = tokio::io::split(stream);
            (Box::new(reader), Box::new(writer))
        }
        ConnectionType::Tcp => {
            let stream = TcpStream::connect((node.tcp_host.as_str(), node.tcp_port))
                .await
                .with_context(|| {
                    format!("failed to connect to {}:{}", node.tcp_host, node.tcp_port)
                })?;
            enable_keepalive(&stream);
            let (reader, writer) = stream.into_split();
            (Box::new(reader), Box::new(writer))
        }
    };

    *state.writer.lock().await = Some(writer);
    state.connected.store(true, Ordering::SeqCst);

    if node.connection_type == ConnectionType::Serial {
        // Firmware ignores frames until it sees a run of sync bytes.
        write_raw(state, &SERIAL_WAKE).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    send_want_config(state).await;
    info!(
        connection = ?node.connection_type,
        "connected to physical node"
    );

    read_loop(state.clone(), reader).await;

    state.connected.store(false, Ordering::SeqCst);
    *state.writer.lock().await = None;
    Ok(())
}

async fn read_loop(state: Arc<AppState>, mut reader: BoxReader) {
    let node = state.config.node.clone();
    let is_serial = node.connection_type == ConnectionType::Serial;
    let idle_timeout = if is_serial {
        node.serial_idle_timeout_secs
    } else {
        node.tcp_idle_timeout_secs
    };
    let poke_timeout = if is_serial {
        node.serial_poke_timeout_secs
    } else {
        0
    };

    let mut decoder = FrameDecoder::new();
    let mut buffer = [0u8; 4096];
    let mut last_data = Instant::now();
    let mut last_heartbeat = Instant::now();
    let mut poked = false;
    let mut shutdown = state.subscribe_shutdown();

    loop {
        let read = tokio::time::timeout(Duration::from_secs(1), reader.read(&mut buffer));

        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            result = read => {
                match result {
                    Ok(Ok(0)) => {
                        info!("physical node closed the link");
                        break;
                    }
                    Ok(Ok(n)) => {
                        last_data = Instant::now();
                        poked = false;
                        decoder.push(&buffer[..n]);
                        while let Some(payload) = decoder.next_frame() {
                            handle_from_radio(&state, payload).await;
                        }
                    }
                    Ok(Err(error)) => {
                        warn!(%error, "physical read error");
                        break;
                    }
                    Err(_) => {
                        if last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
                            last_heartbeat = Instant::now();
                            send_heartbeat(&state).await;
                        }

                        let silent = last_data.elapsed().as_secs();
                        if is_serial && poke_timeout > 0 && !poked && silent > poke_timeout {
                            info!(silent, "no serial data; poking the link with want_config");
                            if send_want_config(&state).await {
                                poked = true;
                            } else {
                                break;
                            }
                        }
                        if idle_timeout > 0 && silent > idle_timeout {
                            warn!(silent, "physical node went silent; reconnecting");
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Apply one frame from a physical node. Shared with the mock.
pub(crate) async fn handle_from_radio(state: &Arc<AppState>, payload: Vec<u8>) {
    // Provisioning and tests observe every raw frame, including config dumps.
    state.broadcast_physical(&payload);

    let diagnostics = muxtastic_core::nexus::parse_from_radio(&payload);
    let Some(frame) = pb::FromRadio::decode(payload.as_slice()).ok() else {
        // Unparseable bytes are forwarded unchanged, matching the original.
        state.broadcast_to_clients(payload);
        return;
    };

    {
        let mut cache = state
            .cache
            .write()
            .unwrap_or_else(|error| error.into_inner());
        cache.apply_message(&frame, &payload);
    }

    if let Some(database) = state.database() {
        let receiver = muxtastic_core::mqtt::gateway_id(state.node_num());
        database.record_frame(
            frame.clone(),
            diagnostics,
            muxtastic_web::DbSource::Physical,
            Some(receiver),
        );
    }

    if let Some(bridge) = state.mqtt_bridge() {
        if let Some(from_radio::PayloadVariant::Channel(channel)) = &frame.payload_variant {
            bridge.mark_channel(channel.index);
        }
    }

    match route_from_physical(&frame) {
        PhysicalRoute::Broadcast => {
            let packet = match &frame.payload_variant {
                Some(from_radio::PayloadVariant::Packet(packet)) => Some(packet.clone()),
                _ => None,
            };

            let raw_frame = packet.as_ref().and_then(|packet| {
                state.ingest_raw_tunnel(packet, diagnostics.unwrap_or_default())
            });
            if let (Some(frame), Some(database)) = (&raw_frame, state.database()) {
                database.record_raw_frame(frame.clone());
            }

            state.broadcast_to_clients(payload);

            if let (Some(packet), Some(bridge)) = (packet, state.mqtt_bridge()) {
                tokio::spawn(async move {
                    // JRAW frames are not LoRa-transport, so the normal raw
                    // gateway skips them; the assembler above handles them.
                    if let Some(frame) = raw_frame {
                        bridge.publish_raw_tunnel_frame(&frame).await;
                    }
                    bridge.publish_packet(&packet).await;
                    bridge.publish_standard(&packet).await;
                });
            }
        }
        PhysicalRoute::ConfigDump => debug!("suppressing the node config dump"),
        PhysicalRoute::Proxy {
            topic,
            payload: proxy_payload,
            retained,
        } => {
            if let Some(bridge) = state.mqtt_bridge() {
                tokio::spawn(async move {
                    bridge
                        .publish_from_physical_proxy(topic, proxy_payload, retained)
                        .await;
                });
            }
        }
    }
}

async fn send_heartbeat(state: &Arc<AppState>) {
    let to_radio = pb::ToRadio {
        payload_variant: Some(to_radio::PayloadVariant::Heartbeat(pb::Heartbeat {
            nonce: rand::random(),
        })),
    };
    let _ = send_to_writer(state, &to_radio.encode_to_vec()).await;
}

/// Ask the node to stream its config dump again.
pub async fn send_want_config(state: &Arc<AppState>) -> bool {
    let to_radio = pb::ToRadio {
        payload_variant: Some(to_radio::PayloadVariant::WantConfigId(rand::random())),
    };
    send_to_writer(state, &to_radio.encode_to_vec()).await
}

async fn send_to_writer(state: &Arc<AppState>, payload: &[u8]) -> bool {
    let Ok(frame) = encode_frame(payload) else {
        return false;
    };
    write_raw(state, &frame).await.is_ok()
}

async fn write_raw(state: &Arc<AppState>, bytes: &[u8]) -> Result<()> {
    let mut slot = state.writer.lock().await;
    let Some(writer) = slot.as_mut() else {
        bail!("physical node is not connected");
    };
    writer.write_all(bytes).await?;
    writer.flush().await?;
    Ok(())
}

fn enable_keepalive(stream: &TcpStream) {
    // Let the kernel notice a dead node instead of relying on quiet mesh gaps.
    let socket = socket2::SockRef::from(stream);
    if let Err(error) = socket.set_keepalive(true) {
        debug!(%error, "could not enable TCP keepalive");
        return;
    }

    let mut keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    #[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
    {
        keepalive = keepalive.with_retries(3);
    }
    if let Err(error) = socket.set_tcp_keepalive(&keepalive) {
        debug!(%error, "could not configure TCP keepalive");
    }
}
