use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use meshtastic::protobufs::{self as pb, from_radio, to_radio};
use meshtastic::Message;
use muxtastic_core::protocol::{encode_frame, FrameDecoder};
use muxtastic_core::replay::{build_replay, ReplayInput};
use muxtastic_core::router::{
    queue_status_reply, route_from_client_decoded, ClientAction, ClientContext,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::app::AppState;

const CLIENT_IDLE: Duration = Duration::from_secs(300);
const CONFIG_COOLDOWN: Duration = Duration::from_secs(5);

/// Serve one connected app.
pub async fn handle(state: Arc<AppState>, id: u64, socket: TcpStream, peer: SocketAddr) {
    info!(client = id, %peer, "client connected");
    state.client_connected(id, peer);

    let (mut reader, mut writer) = socket.into_split();
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);

    let write_task = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            while let Some(payload) = out_rx.recv().await {
                let Ok(frame) = encode_frame(&payload) else {
                    continue;
                };
                if writer.write_all(&frame).await.is_err() {
                    break;
                }
                if writer.flush().await.is_err() {
                    break;
                }
                state.client_tx(id, frame.len() as u64);
            }
        })
    };

    let forward_task = {
        let state = state.clone();
        let out_tx = out_tx.clone();
        tokio::spawn(async move {
            let mut rx = state.broadcast.subscribe();
            loop {
                match rx.recv().await {
                    Ok(frame) => {
                        if frame.exclude_client == Some(id) {
                            continue;
                        }
                        if out_tx.send(frame.payload.to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(client = id, skipped, "client fell behind; skipped frames");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    };

    let mut decoder = FrameDecoder::new();
    let mut buffer = [0u8; 4096];
    let mut shutdown = state.subscribe_shutdown();
    let mut last_config: Option<(u32, Instant)> = None;
    let mut config_sent = false;

    loop {
        let read = tokio::time::timeout(CLIENT_IDLE, reader.read(&mut buffer));
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            result = read => {
                match result {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        state.client_rx(id, n as u64);
                        decoder.push(&buffer[..n]);
                        while let Some(payload) = decoder.next_frame() {
                            state.client_rx_frame(id);
                            handle_to_radio(
                                &state,
                                peer,
                                id,
                                &out_tx,
                                &payload,
                                &mut last_config,
                                &mut config_sent,
                            )
                            .await;
                        }
                    }
                    Ok(Err(error)) => {
                        debug!(client = id, %error, "client read error");
                        break;
                    }
                    Err(_) => {
                        info!(client = id, "client idle timeout");
                        break;
                    }
                }
            }
        }
    }

    drop(out_tx);
    write_task.abort();
    forward_task.abort();
    state.client_disconnected(id);
    info!(client = id, %peer, "client disconnected");
}

async fn handle_to_radio(
    state: &Arc<AppState>,
    peer: SocketAddr,
    client_id: u64,
    out_tx: &mpsc::Sender<Vec<u8>>,
    payload: &[u8],
    last_config: &mut Option<(u32, Instant)>,
    config_sent: &mut bool,
) {
    let Ok(to_radio) = pb::ToRadio::decode(payload) else {
        debug!(%peer, "unparseable ToRadio frame");
        return;
    };

    match &to_radio.payload_variant {
        Some(to_radio::PayloadVariant::WantConfigId(config_id)) => {
            if let Some((last_id, sent_at)) = last_config {
                if config_id == last_id && sent_at.elapsed() < CONFIG_COOLDOWN {
                    info!(%peer, config_id, "throttled duplicate config request");
                    return;
                }
            }
            *last_config = Some((*config_id, Instant::now()));
            send_replay(state, *config_id, out_tx).await;
            *config_sent = true;
        }
        Some(to_radio::PayloadVariant::Heartbeat(_)) => {
            let _ = out_tx.send(queue_status_reply()).await;
        }
        _ => {
            // Apps must request and receive the config replay before they are
            // allowed to send mesh traffic.
            if !*config_sent {
                debug!(%peer, "ignoring message before the config replay");
                return;
            }

            let context = ClientContext {
                ip: peer.ip(),
                node_num: state.node_num(),
                allow_admin_from: &state.allow_admin_from,
                blocked_portnums: &state.blocked_portnums,
            };
            let route = route_from_client_decoded(&to_radio, &context);

            match route.action {
                ClientAction::Forward(bytes) => {
                    // Echo the outgoing packet to the other clients so their
                    // UIs show it immediately, attributing from=0 to the local
                    // node. The sender already logs its own outgoing packet, so
                    // echoing it back would create duplicate records.
                    echo_locally(state, &to_radio, client_id);
                    state.queue_to_node(bytes);
                }
                ClientAction::Reply(bytes) => {
                    let _ = out_tx.send(bytes).await;
                }
                ClientAction::Proxy {
                    topic,
                    payload,
                    retained,
                } => {
                    if let Some(bridge) = state.mqtt_bridge() {
                        if !bridge.publish_proxy(topic, payload, retained).await {
                            debug!(%peer, "proxy publish was not delivered");
                        }
                    } else {
                        debug!(%peer, "proxy message ignored: MQTT bridge disabled");
                    }
                }
                ClientAction::Ignore => {}
                ClientAction::Blocked => {
                    warn!(%peer, "blocked a client command");
                }
            }

            if route.resync {
                let _ = state.resync.try_send(());
            }
        }
    }
}

/// Broadcast a client's outgoing packet to the other clients for UI visibility.
fn echo_locally(state: &Arc<AppState>, to_radio: &pb::ToRadio, client_id: u64) {
    let Some(to_radio::PayloadVariant::Packet(mut packet)) = to_radio.payload_variant.clone()
    else {
        return;
    };

    if packet.from == 0 {
        packet.from = state.node_num();
    }
    if packet.transport_mechanism == 0 {
        packet.transport_mechanism = pb::mesh_packet::TransportMechanism::TransportApi as i32;
    }

    let from_radio = pb::FromRadio {
        id: packet.id,
        payload_variant: Some(from_radio::PayloadVariant::Packet(packet)),
    };
    if let Some(database) = state.database() {
        database.record_frame(
            from_radio.clone(),
            None,
            muxtastic_web::DbSource::Client,
            None,
        );
    }
    state.broadcast_to_other_clients(from_radio.encode_to_vec(), client_id);
}

async fn send_replay(state: &Arc<AppState>, config_id: u32, out_tx: &mpsc::Sender<Vec<u8>>) {
    let messages = {
        let cache = state
            .cache
            .read()
            .unwrap_or_else(|error| error.into_inner());
        build_replay(&ReplayInput {
            cache: &cache,
            config: &state.config,
            node_num: cache.my_node_num,
            config_id,
        })
    };

    info!(
        %config_id,
        count = messages.len(),
        "sending config replay to client"
    );

    for message in messages {
        if out_tx.send(message.encode_to_vec()).await.is_err() {
            break;
        }
    }
}
