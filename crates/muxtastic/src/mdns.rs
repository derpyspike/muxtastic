use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mdns_sd::{ServiceDaemon, ServiceInfo};
use muxtastic_core::replay::VERSION;
use muxtastic_core::SYNTHETIC_NODE_NUM;
use tracing::{info, warn};

use crate::app::AppState;

const SERVICE_TYPE: &str = "_meshtastic._tcp.local.";

pub struct MdnsHandle {
    daemon: ServiceDaemon,
    fullname: String,
}

impl MdnsHandle {
    pub fn shutdown(&self) {
        if let Err(error) = self.daemon.unregister(&self.fullname) {
            warn!(%error, "mDNS unregister failed");
        }
        if let Err(error) = self.daemon.shutdown() {
            warn!(%error, "mDNS shutdown failed");
        }
        info!("mDNS service unregistered");
    }
}

/// Register the multiplexer on the LAN as `_meshtastic._tcp.local.`.
///
/// Waits up to `timeout` for a real node id so the instance name is stable and
/// unique; falls back to a timestamp suffix when no node is present.
pub async fn start(state: &Arc<AppState>, timeout: Duration) -> Option<MdnsHandle> {
    if !state.config.discovery.enabled {
        info!("mDNS discovery disabled");
        return None;
    }

    let node_num = wait_for_node_id(state, timeout).await;
    let slug = node_slug(node_num);
    let instance = format!("Multiplextashtic-{slug}");
    let host = format!("{instance}.local.");
    let address = IpAddr::V4(local_ipv4());

    let short_name = state
        .cache
        .read()
        .unwrap_or_else(|error| error.into_inner())
        .node_info
        .as_ref()
        .and_then(|node| node.user.as_ref())
        .map(|user| user.short_name.clone())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| state.config.virtual_node.short_name.clone());

    let mut properties = HashMap::new();
    properties.insert("shortname".to_owned(), format!("V_{short_name}"));
    properties.insert("id".to_owned(), format!("!{node_num:08x}"));
    properties.insert("version".to_owned(), VERSION.to_owned());
    properties.insert("pio_env".to_owned(), "rust-mux".to_owned());

    let service = match ServiceInfo::new(
        SERVICE_TYPE,
        &instance,
        &host,
        address,
        state.config.server.port,
        properties,
    ) {
        Ok(service) => service,
        Err(error) => {
            warn!(%error, "failed to build mDNS service info");
            return None;
        }
    };

    let fullname = service.get_fullname().to_owned();
    let daemon = match ServiceDaemon::new() {
        Ok(daemon) => daemon,
        Err(error) => {
            warn!(%error, "failed to start mDNS daemon");
            return None;
        }
    };

    match daemon.register(service) {
        Ok(()) => {
            info!(
                instance,
                address = %address,
                port = state.config.server.port,
                "mDNS service registered"
            );
            Some(MdnsHandle { daemon, fullname })
        }
        Err(error) => {
            warn!(%error, "failed to register mDNS service");
            let _ = daemon.shutdown();
            None
        }
    }
}

async fn wait_for_node_id(state: &Arc<AppState>, timeout: Duration) -> u32 {
    let deadline = Instant::now() + timeout;
    loop {
        let node_num = state.node_num();
        if is_real_node_id(node_num) || Instant::now() >= deadline {
            return node_num;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn is_real_node_id(node_num: u32) -> bool {
    node_num != 0 && node_num != SYNTHETIC_NODE_NUM
}

fn node_slug(node_num: u32) -> String {
    if is_real_node_id(node_num) {
        return format!("{node_num:08x}");
    }
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    format!("{:04}", seconds % 10_000)
}

fn local_ipv4() -> Ipv4Addr {
    // Connecting a UDP socket only selects a route; no packets are sent.
    let probe: std::io::Result<SocketAddr> = (|| {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.connect((Ipv4Addr::new(8, 8, 8, 8), 80))?;
        socket.local_addr()
    })();

    match probe {
        Ok(SocketAddr::V4(address)) => *address.ip(),
        _ => Ipv4Addr::LOCALHOST,
    }
}
