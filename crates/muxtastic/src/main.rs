#![forbid(unsafe_code)]

mod app;
mod client;
mod config_loader;
mod logging;
mod mdns;
mod mock;
mod mqtt;
mod physical;
mod provision;
mod server;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use muxtastic_core::channel_crypto::{self, ExtraChannel};
use muxtastic_core::config::{Config, WebStorage};
use muxtastic_core::meshcore::{MeshCoreChannel, MeshCoreKeys, MeshCoreRegion};
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

#[derive(Debug, Parser)]
#[command(name = "muxtastic", version, about = "Meshtastic multiplexer")]
struct Args {
    /// Path to a legacy YAML or native TOML config file.
    #[arg(short, long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Run against a simulated node (no hardware).
    #[arg(long)]
    mock: bool,

    /// Serve only the web UI/history, using [web.mqtt] as the data source.
    #[arg(long)]
    web_only: bool,
}

struct NodeRuntime {
    name: String,
    port: u16,
    state: Arc<app::AppState>,
    to_node_rx: mpsc::Receiver<Vec<u8>>,
    resync_rx: mpsc::Receiver<()>,
}

struct WebNodes {
    nodes: Vec<(String, u16, Arc<app::AppState>)>,
    external_mqtt_enabled: bool,
    external_mqtt_connected: Arc<AtomicBool>,
    mock: bool,
}

/// MQTT sources sharing one broker endpoint, with the local gateways feeding it.
struct MqttSource {
    endpoint: String,
    connected: bool,
    details: Vec<String>,
    topics: Vec<String>,
    gateways: Vec<muxtastic_web::SourceGateway>,
}

impl MqttSource {
    fn merge(
        sources: &mut Vec<Self>,
        endpoint: String,
        connected: bool,
        details: String,
        topics: Vec<String>,
        gateway: Option<muxtastic_web::SourceGateway>,
    ) {
        let source = match sources
            .iter_mut()
            .find(|source| source.endpoint == endpoint)
        {
            Some(source) => source,
            None => {
                sources.push(Self {
                    endpoint: endpoint.clone(),
                    connected: false,
                    details: Vec::new(),
                    topics: Vec::new(),
                    gateways: Vec::new(),
                });
                sources
                    .iter_mut()
                    .find(|source| source.endpoint == endpoint)
                    .expect("MQTT source was just inserted")
            }
        };

        source.connected |= connected;
        if !details.is_empty() && !source.details.contains(&details) {
            source.details.push(details);
        }
        for topic in topics {
            if !source.topics.contains(&topic) {
                source.topics.push(topic);
            }
        }
        if let Some(gateway) = gateway {
            source.gateways.push(gateway);
        }
    }

    fn into_status(self) -> muxtastic_web::SourceStatus {
        let mut details = self.details;
        if self.gateways.len() > 1 {
            details.insert(0, format!("{} gateways", self.gateways.len()));
        }
        muxtastic_web::SourceStatus {
            name: "MQTT".into(),
            kind: "mqtt".into(),
            endpoint: self.endpoint,
            connected: self.connected,
            details: details.join("; "),
            topics: self.topics,
            node: None,
            receiver: None,
            virtual_endpoint: None,
            gateways: self.gateways,
            clients: Vec::new(),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let loaded = config_loader::load(args.config.as_deref(), args.mock || args.web_only)?;
    let _log_guard = logging::init(&loaded.config.logging);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = ?loaded.path,
        mock = args.mock,
        web_only = args.web_only,
        "starting muxtastic"
    );
    if loaded.path.is_none() {
        warn!("no config file found; using built-in defaults");
    }

    let config = loaded.config;
    let started = Instant::now();
    let (shutdown, _) = watch::channel(false);
    let database = open_web_database(&config);
    let external_mqtt_enabled = config.web.mqtt.enabled && database.is_some();
    let external_mqtt_connected = Arc::new(AtomicBool::new(false));

    if args.web_only {
        let Some(database) = database else {
            anyhow::bail!("--web-only requires [web] enabled = true");
        };

        let mut web_task = spawn_web(
            config.web.clone(),
            Arc::clone(&database),
            WebNodes {
                nodes: Vec::new(),
                external_mqtt_enabled,
                external_mqtt_connected: Arc::clone(&external_mqtt_connected),
                mock: false,
            },
            shutdown.subscribe(),
            started,
        );

        spawn_cleanup(
            Arc::clone(&database),
            config.web.retention_days,
            shutdown.subscribe(),
        );

        if config.web.mqtt.enabled {
            info!(
                broker = %config.web.mqtt.broker,
                port = config.web.mqtt.port,
                tls = config.web.mqtt.tls,
                "web-only mode: starting MQTT source"
            );
            tokio::spawn(muxtastic_web::run_mqtt_source(
                database,
                config.web.mqtt.clone(),
                Arc::clone(&external_mqtt_connected),
                None,
                shutdown.subscribe(),
            ));
        } else {
            warn!("web-only mode has no MQTT source; enable [web.mqtt] to populate the UI");
        }

        // In web-only mode the web server is the whole service: losing it
        // (for example a port that is already in use) is fatal.
        let web_stopped = tokio::select! {
            _ = wait_for_shutdown() => false,
            _ = &mut web_task => true,
        };
        info!("shutting down");
        let _ = shutdown.send(true);
        tokio::time::sleep(Duration::from_millis(300)).await;
        web_task.abort();
        if web_stopped {
            anyhow::bail!("the web server stopped unexpectedly");
        }
        return Ok(());
    }

    let mut runtimes = Vec::new();
    for instance in config.instances() {
        let node_config = config.for_instance(&instance);
        let (state, to_node_rx, resync_rx) =
            app::AppState::new(node_config, shutdown.clone(), args.mock);
        runtimes.push(NodeRuntime {
            name: instance.name,
            port: instance.server.port,
            state,
            to_node_rx,
            resync_rx,
        });
    }

    if let Some(database) = &database {
        for runtime in &runtimes {
            runtime.state.set_database(database);
        }
    }

    let node_states: Vec<(String, u16, Arc<app::AppState>)> = runtimes
        .iter()
        .map(|runtime| {
            (
                runtime.name.clone(),
                runtime.port,
                Arc::clone(&runtime.state),
            )
        })
        .collect();
    let mut web_task = database.as_ref().map(|database| {
        spawn_web(
            config.web.clone(),
            Arc::clone(database),
            WebNodes {
                nodes: node_states.clone(),
                external_mqtt_enabled,
                external_mqtt_connected: Arc::clone(&external_mqtt_connected),
                mock: args.mock,
            },
            shutdown.subscribe(),
            started,
        )
    });

    if let Some(database) = &database {
        spawn_cleanup(
            Arc::clone(database),
            config.web.retention_days,
            shutdown.subscribe(),
        );

        if external_mqtt_enabled {
            let local_nodes = node_states.clone();
            let skip_gateway: Arc<dyn Fn(&str) -> bool + Send + Sync> =
                Arc::new(move |gateway: &str| {
                    let Some(hex) = gateway.strip_prefix('!') else {
                        return false;
                    };
                    let Ok(node_num) = u32::from_str_radix(hex, 16) else {
                        return false;
                    };
                    local_nodes
                        .iter()
                        .any(|(_, _, state)| state.node_num() == node_num)
                });
            info!(
                broker = %config.web.mqtt.broker,
                port = config.web.mqtt.port,
                tls = config.web.mqtt.tls,
                "starting read-only MQTT source alongside the physical nodes"
            );
            tokio::spawn(muxtastic_web::run_mqtt_source(
                Arc::clone(database),
                config.web.mqtt.clone(),
                Arc::clone(&external_mqtt_connected),
                Some(skip_gateway),
                shutdown.subscribe(),
            ));
        }
    }

    // Listen first: neither the MQTT bridge nor mDNS may delay the mux port or
    // the signal handler while they wait for the physical node.
    let mut servers = tokio::task::JoinSet::new();
    for (_, _, state) in &node_states {
        servers.spawn(server::run(state.clone()));
    }

    let mut dispatchers = Vec::new();
    let mut resync_tasks = Vec::new();
    let mut physical_tasks = Vec::new();
    let mut bridge_tasks = Vec::new();

    for (index, runtime) in runtimes.into_iter().enumerate() {
        let state = runtime.state;

        dispatchers.push(tokio::spawn(app::dispatcher(
            state.clone(),
            runtime.to_node_rx,
        )));
        resync_tasks.push(tokio::spawn(app::resync_worker(
            state.clone(),
            runtime.resync_rx,
        )));
        physical_tasks.push(if args.mock {
            // Only the mock may use the synthetic node id.
            let mock_node_num = muxtastic_core::SYNTHETIC_NODE_NUM.wrapping_add(index as u32);
            tokio::spawn(mock::run(state.clone(), mock_node_num))
        } else {
            tokio::spawn(physical::run(state.clone()))
        });

        if state.config.mqtt_bridge.enabled {
            bridge_tasks.push(tokio::spawn(run_bridge(state, !args.mock)));
        }
    }

    let mdns_timeout = if args.mock {
        Duration::ZERO
    } else {
        Duration::from_secs(15)
    };
    let mut mdns_tasks = Vec::new();
    for (_, _, state) in &node_states {
        let state = state.clone();
        mdns_tasks.push(tokio::spawn(async move {
            mdns::start(&state, mdns_timeout).await
        }));
    }

    let mut failure: Option<anyhow::Error> = None;
    tokio::select! {
        _ = wait_for_shutdown() => {}
        result = servers.join_next() => {
            // A server only returns when shutdown was requested, so reaching
            // this arm means it could not run (typically a bind failure).
            let reason = match result {
                Some(Ok(Ok(()))) => anyhow::anyhow!("a TCP server stopped unexpectedly"),
                Some(Ok(Err(error))) => error,
                Some(Err(error)) => anyhow::anyhow!("a TCP server task failed: {error}"),
                None => anyhow::anyhow!("no TCP server is running"),
            };
            error!(error = %format!("{reason:#}"), "fatal: the multiplexer cannot serve clients");
            failure = Some(reason);
        }
    }
    info!("shutting down");

    let _ = shutdown.send(true);
    for task in mdns_tasks {
        if task.is_finished() {
            if let Ok(Some(handle)) = task.await {
                handle.shutdown();
            }
        } else {
            task.abort();
        }
    }

    // Give client writers and the MQTT legs a moment to stop before the
    // runtime drops.
    tokio::time::sleep(Duration::from_millis(300)).await;
    servers.abort_all();
    for task in dispatchers {
        task.abort();
    }
    for task in resync_tasks {
        task.abort();
    }
    for task in physical_tasks {
        task.abort();
    }
    for task in bridge_tasks {
        task.abort();
    }
    if let Some(web_task) = web_task.take() {
        web_task.abort();
    }

    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Own one node's MQTT bridge for the life of the process.
///
/// The bridge is created only once the physical node has reported its number,
/// however long that takes, so it never adopts a placeholder identity.
/// Provisioning runs right after, which is the first moment it can work.
async fn run_bridge(state: Arc<app::AppState>, provision: bool) {
    let mut shutdown = state.subscribe_shutdown();
    let waiting_since = Instant::now();
    let mut announced = false;

    while state.node_num() == 0 {
        if *shutdown.borrow() {
            return;
        }
        if !announced && waiting_since.elapsed() >= Duration::from_secs(15) {
            announced = true;
            info!("MQTT bridge is waiting for the physical node to report its number");
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }
    }

    let bridge = Arc::new(mqtt::MqttBridge::new(state.clone()));
    state.set_mqtt_bridge(&bridge);
    bridge.start();
    let provision_task =
        provision.then(|| tokio::spawn(provision::run(state.clone(), bridge.clone())));

    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }

    if let Some(task) = provision_task {
        task.abort();
    }
    bridge.stop();
}

fn spawn_cleanup(
    database: Arc<muxtastic_web::Database>,
    days: u64,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if days == 0 {
            return;
        }
        loop {
            let db = Arc::clone(&database);
            match tokio::task::spawn_blocking(move || db.cleanup_older_than(days)).await {
                Ok(Ok(removed)) if removed > 0 => {
                    info!(removed, days, "pruned old web history");
                }
                Ok(Ok(_)) => {}
                Ok(Err(error)) => warn!(%error, "web history cleanup failed"),
                Err(error) => warn!(%error, "web history cleanup task failed"),
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(3_600)) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    })
}

fn open_web_database(config: &Config) -> Option<Arc<muxtastic_web::Database>> {
    if !config.web.enabled {
        return None;
    }
    let mut extra_channels: Vec<_> = config
        .web
        .extra_channels
        .iter()
        .filter_map(
            |channel| match ExtraChannel::parse(&channel.name, &channel.key) {
                Ok(channel) => Some(channel),
                Err(error) => {
                    warn!(name = %channel.name, %error, "ignoring invalid extra channel");
                    None
                }
            },
        )
        .collect();
    if config.web.try_all_one_byte_keys {
        let before = extra_channels.len();
        channel_crypto::append_all_one_byte_keys(&mut extra_channels);
        info!(
            added = extra_channels.len() - before,
            total = extra_channels.len(),
            "added all one-byte PSK extra channels"
        );
    }
    let database_path = match config.web.storage {
        WebStorage::Sqlite => config.web.database.as_str(),
        WebStorage::Memory => ":memory:",
    };
    let meshcore_channels = config
        .web
        .meshcore_channels
        .iter()
        .filter_map(
            |channel| match MeshCoreChannel::from_config(&channel.name, &channel.key) {
                Ok(channel) => Some(channel),
                Err(error) => {
                    warn!(%error, "ignoring invalid MeshCore channel");
                    None
                }
            },
        )
        .collect();
    let meshcore_regions = config
        .web
        .meshcore_regions
        .iter()
        .filter(|name| !name.trim().is_empty())
        .map(|name| MeshCoreRegion::named(name))
        .collect();
    let meshcore = MeshCoreKeys::new(meshcore_channels, meshcore_regions);
    info!(
        channels = meshcore.channels().len(),
        regions = meshcore.regions().len(),
        "MeshCore keys loaded"
    );
    match muxtastic_web::Database::open_with_keys(database_path, extra_channels, meshcore) {
        Ok((database, receiver)) => {
            tokio::spawn(muxtastic_web::run_writer(
                Arc::downgrade(&database),
                receiver,
            ));
            Some(database)
        }
        Err(error) => {
            warn!(%error, "failed to open the web database; web UI disabled");
            None
        }
    }
}

fn spawn_web(
    config: muxtastic_core::config::WebConfig,
    database: Arc<muxtastic_web::Database>,
    web: WebNodes,
    shutdown: watch::Receiver<bool>,
    started: Instant,
) -> tokio::task::JoinHandle<()> {
    let WebNodes {
        nodes,
        external_mqtt_enabled,
        external_mqtt_connected,
        mock,
    } = web;
    let database_path = match config.storage {
        WebStorage::Sqlite => config.database.clone(),
        WebStorage::Memory => "memory (volatile)".to_owned(),
    };
    let web_mqtt = config.mqtt.clone();
    let status: muxtastic_web::StatusFn = Arc::new(move || {
        let mut physical_connected = false;
        let mut active_clients = 0usize;
        let mut mqtt_enabled = external_mqtt_enabled;
        let mut mqtt_connected = external_mqtt_connected.load(Ordering::SeqCst);
        let mut status_nodes = Vec::new();
        let mut sources = Vec::new();
        let mut mqtt_sources = Vec::new();

        if external_mqtt_enabled {
            MqttSource::merge(
                &mut mqtt_sources,
                format!("{}:{}", web_mqtt.broker, web_mqtt.port),
                external_mqtt_connected.load(Ordering::SeqCst),
                "read-only web source".into(),
                web_mqtt.topics.clone(),
                None,
            );
        }

        for (name, port, state) in &nodes {
            physical_connected |= state.connected.load(Ordering::SeqCst);
            active_clients += state.active_clients.load(Ordering::SeqCst);
            let node = {
                let cache = state
                    .cache
                    .read()
                    .unwrap_or_else(|error| error.into_inner());
                muxtastic_core::details::node_details(&cache)
            };

            let endpoint = if mock {
                "mock".to_owned()
            } else {
                match state.config.node.connection_type {
                    muxtastic_core::config::ConnectionType::Serial => {
                        format!("serial {}", state.config.node.serial_port)
                    }
                    muxtastic_core::config::ConnectionType::Tcp => format!(
                        "tcp {}:{}",
                        state.config.node.tcp_host, state.config.node.tcp_port
                    ),
                }
            };
            let node_num = state.node_num();
            let receiver = (node_num != 0).then(|| format!("!{node_num:08x}"));
            let virtual_endpoint =
                format!("{}:{}", state.config.server.host, state.config.server.port);
            sources.push(muxtastic_web::SourceStatus {
                name: name.clone(),
                kind: "physical".into(),
                endpoint,
                connected: state.connected.load(Ordering::SeqCst),
                details: if node_num == 0 {
                    "handshake pending".into()
                } else {
                    format!("node !{node_num:08x}")
                },
                topics: Vec::new(),
                node: node.clone(),
                receiver: receiver.clone(),
                virtual_endpoint: Some(virtual_endpoint.clone()),
                gateways: Vec::new(),
                clients: state
                    .client_snapshots()
                    .into_iter()
                    .map(|client| muxtastic_web::ClientStatus {
                        id: client.id,
                        peer: client.peer,
                        connected_secs: client.connected_secs,
                        idle_secs: client.idle_secs,
                        rx_frames: client.rx_frames,
                        tx_frames: client.tx_frames,
                        rx_bytes: client.rx_bytes,
                        tx_bytes: client.tx_bytes,
                    })
                    .collect(),
            });

            let mqtt = state.mqtt_bridge();
            if let Some(mqtt) = &mqtt {
                mqtt_enabled = true;
                mqtt_connected |= mqtt.is_connected();
            }
            if state.config.mqtt_bridge.enabled {
                let bridge_config = &state.config.mqtt_bridge;
                let connected = mqtt.is_some_and(|bridge| bridge.is_connected());
                MqttSource::merge(
                    &mut mqtt_sources,
                    format!(
                        "{}:{}{}",
                        bridge_config.broker,
                        bridge_config.port,
                        if bridge_config.tls { " (TLS)" } else { "" }
                    ),
                    connected,
                    format!(
                        "uplink {}; downlink {}",
                        bridge_config.uplink_enabled, bridge_config.downlink_enabled
                    ),
                    vec![
                        format!("{}/#", bridge_config.root_topic),
                        format!("{}/#", bridge_config.raw_root_topic),
                    ],
                    Some(muxtastic_web::SourceGateway {
                        name: name.clone(),
                        node: node.clone(),
                        receiver: receiver.clone(),
                        connected,
                        details: format!(
                            "uplink {}; downlink {}",
                            bridge_config.uplink_enabled, bridge_config.downlink_enabled
                        ),
                    }),
                );
            }

            status_nodes.push(muxtastic_web::NodeStatus {
                name: name.clone(),
                port: *port,
                connected: state.connected.load(Ordering::SeqCst),
                node,
            });
        }

        sources.extend(mqtt_sources.into_iter().map(MqttSource::into_status));

        muxtastic_web::StatusSnapshot {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            uptime_secs: started.elapsed().as_secs(),
            physical_connected,
            active_clients,
            mqtt_enabled,
            mqtt_connected,
            database: database_path.clone(),
            nodes: status_nodes,
            sources,
        }
    });
    tokio::spawn(async move {
        if let Err(error) = muxtastic_web::serve(config, database, status, shutdown).await {
            warn!(%error, "web UI stopped");
        }
    })
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                warn!(%error, "could not install SIGTERM handler; awaiting Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway(name: &str, receiver: &str) -> muxtastic_web::SourceGateway {
        muxtastic_web::SourceGateway {
            name: name.into(),
            node: None,
            receiver: Some(receiver.into()),
            connected: true,
            details: "uplink true; downlink false".into(),
        }
    }

    #[test]
    fn mqtt_gateways_merge_into_one_source() {
        let mut sources = Vec::new();
        MqttSource::merge(
            &mut sources,
            "broker:1883".into(),
            true,
            "uplink true; downlink false".into(),
            vec!["msh/#".into()],
            Some(gateway("mega", "!00000001")),
        );
        MqttSource::merge(
            &mut sources,
            "broker:1883".into(),
            false,
            "uplink true; downlink false".into(),
            vec!["raw/#".into()],
            Some(gateway("milotic", "!00000002")),
        );

        assert_eq!(sources.len(), 1);
        let source = sources.pop().expect("one MQTT source").into_status();
        assert_eq!(source.name, "MQTT");
        assert_eq!(source.kind, "mqtt");
        assert_eq!(source.endpoint, "broker:1883");
        assert!(source.connected);
        assert!(source.node.is_none());
        assert_eq!(source.topics, vec!["msh/#", "raw/#"]);
        assert_eq!(source.gateways.len(), 2);
        assert_eq!(
            source
                .gateways
                .iter()
                .map(|gateway| gateway.name.as_str())
                .collect::<Vec<_>>(),
            vec!["mega", "milotic"]
        );
        assert!(source.details.contains("2 gateways"));
    }
}
