use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::app::AppState;
use crate::client;

/// Accept clients until shutdown. Returns an error when the port cannot be
/// bound, which the caller turns into a non-zero exit.
pub async fn run(state: Arc<AppState>) -> anyhow::Result<()> {
    let server = state.config.server.clone();
    let listener = TcpListener::bind((server.host.as_str(), server.port))
        .await
        .with_context(|| {
            format!(
                "failed to bind the multiplexer port {}:{}",
                server.host, server.port
            )
        })?;

    if let Ok(address) = listener.local_addr() {
        info!(%address, "TCP server listening");
    }

    let mut shutdown = state.subscribe_shutdown();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((socket, peer)) => {
                        let active = state.active_clients.fetch_add(1, Ordering::SeqCst);
                        if active >= server.max_clients {
                            state.active_clients.fetch_sub(1, Ordering::SeqCst);
                            warn!(%peer, max = server.max_clients, "rejecting client: too many connections");
                            drop(socket);
                            continue;
                        }

                        let id = state.next_client_id.fetch_add(1, Ordering::SeqCst);
                        let state = state.clone();
                        tokio::spawn(async move {
                            client::handle(state.clone(), id, socket, peer).await;
                            state.active_clients.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                    Err(error) => {
                        warn!(%error, "TCP accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    info!("TCP server stopped");
    Ok(())
}
