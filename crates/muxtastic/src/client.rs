use std::net::SocketAddr;
use std::sync::atomic::Ordering;
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

/// Disconnect a client that sends nothing for this long. Well above the 300 s
/// heartbeat interval some client libraries use.
const CLIENT_IDLE: Duration = Duration::from_secs(900);
const CONFIG_COOLDOWN: Duration = Duration::from_secs(5);
/// One frame must reach the client's socket within this time.
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the handler waits for room in a client's outbound queue.
const CLIENT_SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Grace period for queued frames to flush when a client is closed.
const CLIENT_FLUSH_GRACE: Duration = Duration::from_secs(1);
/// How long a config request waits for the physical node's first config dump.
const SYNC_WAIT: Duration = Duration::from_secs(10);

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
                let write = async {
                    writer.write_all(&frame).await?;
                    writer.flush().await
                };
                match tokio::time::timeout(CLIENT_WRITE_TIMEOUT, write).await {
                    Ok(Ok(())) => state.client_tx(id, frame.len() as u64),
                    Ok(Err(_)) => break,
                    Err(_) => {
                        warn!(client = id, "client is not reading; disconnecting");
                        break;
                    }
                }
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
            // The writer task ended (write error or a client that stopped
            // reading): nothing can reach this client any more.
            _ = out_tx.closed() => {
                debug!(client = id, "client writer stopped");
                break;
            }
            result = read => {
                match result {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        state.client_rx(id, n as u64);
                        decoder.push(&buffer[..n]);
                        let mut alive = true;
                        while let Some(payload) = decoder.next_frame() {
                            state.client_rx_frame(id);
                            alive = handle_to_radio(
                                &state,
                                peer,
                                id,
                                &out_tx,
                                &payload,
                                &mut last_config,
                                &mut config_sent,
                            )
                            .await;
                            if !alive {
                                break;
                            }
                        }
                        if !alive {
                            warn!(client = id, "client is not draining its queue; disconnecting");
                            break;
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

    // Stop feeding the queue, give queued replies a moment to flush, then close.
    forward_task.abort();
    drop(out_tx);
    let mut write_task = write_task;
    if tokio::time::timeout(CLIENT_FLUSH_GRACE, &mut write_task)
        .await
        .is_err()
    {
        write_task.abort();
    }
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
) -> bool {
    let Ok(to_radio) = pb::ToRadio::decode(payload) else {
        debug!(%peer, "unparseable ToRadio frame");
        return true;
    };

    match &to_radio.payload_variant {
        Some(to_radio::PayloadVariant::WantConfigId(config_id)) => {
            if let Some((last_id, sent_at)) = last_config {
                if config_id == last_id && sent_at.elapsed() < CONFIG_COOLDOWN {
                    info!(%peer, config_id, "throttled duplicate config request");
                    return true;
                }
            }
            match send_replay(state, *config_id, out_tx).await {
                Replay::Sent => {
                    *last_config = Some((*config_id, Instant::now()));
                    *config_sent = true;
                }
                // Stay silent so the app retries; do not throttle the retry.
                Replay::NotSynced => *last_config = None,
                Replay::ClientStalled => return false,
            }
        }
        Some(to_radio::PayloadVariant::Heartbeat(_)) => {
            return send_to_client(out_tx, queue_status_reply()).await;
        }
        _ => {
            // Apps must request and receive the config replay before they are
            // allowed to send mesh traffic.
            if !*config_sent {
                debug!(%peer, "ignoring message before the config replay");
                return true;
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
                    if !send_to_client(out_tx, bytes).await {
                        return false;
                    }
                }
                ClientAction::Proxy {
                    topic,
                    payload,
                    retained: _,
                } => {
                    // A client may not leave retained messages on the broker
                    // with the bridge's credentials.
                    if let Some(bridge) = state.mqtt_bridge() {
                        if !bridge.publish_proxy(topic, payload, false).await {
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
    true
}

/// Queue one frame for the client. False when the client is gone or has not
/// drained its queue within [`CLIENT_SEND_TIMEOUT`].
async fn send_to_client(out_tx: &mpsc::Sender<Vec<u8>>, payload: Vec<u8>) -> bool {
    out_tx
        .send_timeout(payload, CLIENT_SEND_TIMEOUT)
        .await
        .is_ok()
}

enum Replay {
    Sent,
    /// The physical node has not delivered a config yet; nothing was sent.
    NotSynced,
    /// The client stopped draining its queue.
    ClientStalled,
}

/// Wait for the physical node's first config dump to complete.
async fn wait_for_sync(state: &Arc<AppState>) {
    let deadline = Instant::now() + SYNC_WAIT;
    while !state.synced.load(Ordering::SeqCst) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
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

async fn send_replay(
    state: &Arc<AppState>,
    config_id: u32,
    out_tx: &mpsc::Sender<Vec<u8>>,
) -> Replay {
    // With a real node, a replay built from an empty cache would hand the app
    // a made-up identity. Wait for the node, else say nothing so the app
    // retries. The mock fills the cache itself.
    if !state.mock && !state.synced.load(Ordering::SeqCst) {
        wait_for_sync(state).await;
        if state.node_num() == 0 {
            info!(
                %config_id,
                "physical node has not synced yet; not answering the config request"
            );
            return Replay::NotSynced;
        }
    }

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
        if !send_to_client(out_tx, message.encode_to_vec()).await {
            return Replay::ClientStalled;
        }
    }
    Replay::Sent
}
