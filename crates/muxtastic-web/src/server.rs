//! Axum web server and JSON API for the Muxtastic UI.

use std::fmt::Display;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use muxtastic_core::config::WebConfig;
use muxtastic_core::details::NodeDetails;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::info;

use crate::db::{
    Database, DirectNode, JrawNode, Message, MqttGateway, Node, NodeName, PacketFilter,
    PacketFilterOptions, PacketListEntry, PacketRow, RawFrame, Reception, RelaySample, RelayStats,
    Stats, Traceroute,
};

/// One physical node in the multi-node status payload.
#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    pub name: String,
    pub port: u16,
    pub connected: bool,
    pub node: Option<NodeDetails>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceGateway {
    pub name: String,
    pub node: Option<NodeDetails>,
    pub receiver: Option<String>,
    pub connected: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientStatus {
    pub id: u64,
    pub peer: String,
    pub connected_secs: u64,
    pub idle_secs: u64,
    pub rx_frames: u64,
    pub tx_frames: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceStatus {
    pub name: String,
    pub kind: String,
    pub endpoint: String,
    pub connected: bool,
    pub details: String,
    pub topics: Vec<String>,
    pub node: Option<NodeDetails>,
    pub receiver: Option<String>,
    pub virtual_endpoint: Option<String>,
    /// Local nodes uplinking through this MQTT source.
    pub gateways: Vec<SourceGateway>,
    /// Clients currently connected to this physical source.
    pub clients: Vec<ClientStatus>,
}

/// Live daemon state included with the stats payload.
#[derive(Debug, Clone, Serialize)]
pub struct StatusSnapshot {
    pub version: String,
    pub uptime_secs: u64,
    pub physical_connected: bool,
    pub active_clients: usize,
    pub mqtt_enabled: bool,
    pub mqtt_connected: bool,
    pub database: String,
    pub nodes: Vec<NodeStatus>,
    pub sources: Vec<SourceStatus>,
}

pub type StatusFn = Arc<dyn Fn() -> StatusSnapshot + Send + Sync>;

#[derive(Clone)]
struct WebState {
    db: Arc<Database>,
    status: StatusFn,
}

type ApiError = (StatusCode, String);

pub async fn serve(
    config: WebConfig,
    db: Arc<Database>,
    status: StatusFn,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind((config.host.as_str(), config.port)).await?;
    let address = listener.local_addr()?;
    info!(%address, database = %config.database, "web UI listening");

    axum::serve(listener, router(WebState { db, status }))
        .with_graceful_shutdown(wait_for_shutdown(shutdown))
        .await?;
    info!("web UI stopped");
    Ok(())
}

fn router(state: WebState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/static/style.css", get(style))
        .route("/static/app.js", get(script))
        .route("/api/stats", get(api_stats))
        .route("/api/status", get(api_status))
        .route("/api/messages", get(api_messages))
        .route("/api/nodes", get(api_nodes))
        .route("/api/node-names", get(api_node_names))
        .route("/api/nodes/{num}", get(api_node))
        .route("/node/{num}", get(node_page))
        .route("/api/raw", get(api_raw))
        .route("/api/channels", get(api_channels))
        .route("/api/receptions", get(api_receptions))
        .route("/api/traceroutes", get(api_traceroutes))
        .route("/api/direct-nodes", get(api_direct_nodes))
        .route("/api/mqtt-gateways", get(api_mqtt_gateways))
        .route("/api/packets", get(api_packets))
        .route("/api/packet-filters", get(api_packet_filters))
        .route("/api/jraw-nodes", get(api_jraw_nodes))
        .route("/api/relay-stats", get(api_relay_stats))
        .route("/api/relay-series", get(api_relay_series))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("static/index.html"))
}

async fn node_page() -> Html<&'static str> {
    Html(include_str!("static/index.html"))
}

async fn style() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("static/style.css"),
    )
        .into_response()
}

async fn script() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("static/app.js"),
    )
        .into_response()
}

#[derive(Serialize)]
struct StatsResponse {
    status: StatusSnapshot,
    stats: Stats,
}

async fn api_stats(State(state): State<WebState>) -> Result<Json<StatsResponse>, ApiError> {
    let stats = blocking(state.db.clone(), |db| db.query_stats()).await?;
    Ok(Json(StatsResponse {
        status: (state.status)(),
        stats,
    }))
}

async fn api_status(State(state): State<WebState>) -> Json<StatusSnapshot> {
    Json((state.status)())
}

#[derive(Deserialize)]
struct MessagesQuery {
    channel: Option<String>,
    limit: Option<usize>,
}

async fn api_messages(
    State(state): State<WebState>,
    Query(query): Query<MessagesQuery>,
) -> Result<Json<Vec<Message>>, ApiError> {
    let limit = query.limit.unwrap_or(200);
    let messages = blocking(state.db.clone(), move |db| {
        db.query_messages(query.channel.as_deref(), limit)
    })
    .await?;
    Ok(Json(messages))
}

async fn api_nodes(State(state): State<WebState>) -> Result<Json<Vec<Node>>, ApiError> {
    let nodes = blocking(state.db.clone(), |db| db.query_nodes()).await?;
    Ok(Json(nodes))
}

async fn api_node_names(State(state): State<WebState>) -> Result<Json<Vec<NodeName>>, ApiError> {
    let nodes = blocking(state.db.clone(), |db| db.query_node_names()).await?;
    Ok(Json(nodes))
}

#[derive(Serialize)]
struct NodeDetailResponse {
    node: Node,
    packets: Vec<PacketRow>,
}

async fn api_node(
    State(state): State<WebState>,
    Path(num): Path<i64>,
) -> Result<Json<NodeDetailResponse>, ApiError> {
    let node = blocking(state.db.clone(), move |db| db.query_node(num)).await?;
    let Some(node) = node else {
        return Err((StatusCode::NOT_FOUND, "node not found".to_owned()));
    };
    let packets = blocking(state.db.clone(), move |db| db.query_node_packets(num, 200)).await?;
    Ok(Json(NodeDetailResponse { node, packets }))
}

#[derive(Deserialize)]
struct RawQuery {
    kind: Option<i64>,
    limit: Option<usize>,
}

async fn api_raw(
    State(state): State<WebState>,
    Query(query): Query<RawQuery>,
) -> Result<Json<Vec<RawFrame>>, ApiError> {
    let limit = query.limit.unwrap_or(200);
    let frames = blocking(state.db.clone(), move |db| {
        db.query_raw_frames(query.kind, limit)
    })
    .await?;
    Ok(Json(frames))
}

async fn api_channels(
    State(state): State<WebState>,
) -> Result<Json<Vec<crate::db::ChannelInfo>>, ApiError> {
    let channels = blocking(state.db.clone(), |db| db.query_channels()).await?;
    Ok(Json(channels))
}

#[derive(Deserialize)]
struct DirectNodesQuery {
    receiver: String,
    limit: Option<usize>,
}

async fn api_direct_nodes(
    State(state): State<WebState>,
    Query(query): Query<DirectNodesQuery>,
) -> Result<Json<Vec<DirectNode>>, ApiError> {
    let limit = query.limit.unwrap_or(200);
    let receiver = query.receiver;
    let nodes = blocking(state.db.clone(), move |db| {
        db.query_direct_nodes(&receiver, limit)
    })
    .await?;
    Ok(Json(nodes))
}

#[derive(Deserialize)]
struct MqttGatewaysQuery {
    limit: Option<usize>,
}

async fn api_mqtt_gateways(
    State(state): State<WebState>,
    Query(query): Query<MqttGatewaysQuery>,
) -> Result<Json<Vec<MqttGateway>>, ApiError> {
    let limit = query.limit.unwrap_or(500);
    let gateways = blocking(state.db.clone(), move |db| db.query_mqtt_gateways(limit)).await?;
    Ok(Json(gateways))
}

#[derive(Deserialize)]
struct PacketsQuery {
    portnum: Option<i64>,
    gateway: Option<String>,
    channel: Option<String>,
    source: Option<String>,
    decrypted: Option<bool>,
    limit: Option<usize>,
}

async fn api_packets(
    State(state): State<WebState>,
    Query(query): Query<PacketsQuery>,
) -> Result<Json<Vec<PacketListEntry>>, ApiError> {
    let filter = PacketFilter {
        portnum: query.portnum,
        gateway: query.gateway,
        channel: query.channel,
        source: query.source,
        decrypted: query.decrypted,
        limit: query.limit.unwrap_or(500),
    };
    let packets = blocking(state.db.clone(), move |db| db.query_packets(&filter)).await?;
    Ok(Json(packets))
}

async fn api_packet_filters(
    State(state): State<WebState>,
) -> Result<Json<PacketFilterOptions>, ApiError> {
    let filters = blocking(state.db.clone(), |db| db.query_packet_filters()).await?;
    Ok(Json(filters))
}

#[derive(Deserialize)]
struct JrawNodesQuery {
    kind: Option<i64>,
    limit: Option<usize>,
}

async fn api_jraw_nodes(
    State(state): State<WebState>,
    Query(query): Query<JrawNodesQuery>,
) -> Result<Json<Vec<JrawNode>>, ApiError> {
    let limit = query.limit.unwrap_or(500);
    let nodes = blocking(state.db.clone(), move |db| {
        db.query_jraw_nodes(query.kind, limit)
    })
    .await?;
    Ok(Json(nodes))
}

#[derive(Deserialize)]
struct RelayStatsQuery {
    receiver: String,
    limit: Option<usize>,
}

async fn api_relay_stats(
    State(state): State<WebState>,
    Query(query): Query<RelayStatsQuery>,
) -> Result<Json<Vec<RelayStats>>, ApiError> {
    let limit = query.limit.unwrap_or(100);
    let receiver = query.receiver;
    let stats = blocking(state.db.clone(), move |db| {
        db.query_relay_stats(&receiver, limit)
    })
    .await?;
    Ok(Json(stats))
}

async fn api_relay_series(
    State(state): State<WebState>,
    Query(query): Query<RelayStatsQuery>,
) -> Result<Json<Vec<RelaySample>>, ApiError> {
    let limit = query.limit.unwrap_or(2000);
    let receiver = query.receiver;
    let series = blocking(state.db.clone(), move |db| {
        db.query_relay_series(&receiver, limit)
    })
    .await?;
    Ok(Json(series))
}

#[derive(Deserialize)]
struct TraceroutesQuery {
    limit: Option<usize>,
}

async fn api_traceroutes(
    State(state): State<WebState>,
    Query(query): Query<TraceroutesQuery>,
) -> Result<Json<Vec<Traceroute>>, ApiError> {
    let limit = query.limit.unwrap_or(200);
    let traces = blocking(state.db.clone(), move |db| db.query_traceroutes(limit)).await?;
    Ok(Json(traces))
}

#[derive(Deserialize)]
struct ReceptionsQuery {
    from_num: Option<i64>,
    packet_id: Option<i64>,
    limit: Option<usize>,
}

async fn api_receptions(
    State(state): State<WebState>,
    Query(query): Query<ReceptionsQuery>,
) -> Result<Json<Vec<Reception>>, ApiError> {
    let limit = query.limit.unwrap_or(200);
    let receptions = match (query.from_num, query.packet_id) {
        (Some(from_num), Some(packet_id)) => {
            blocking(state.db.clone(), move |db| {
                db.query_receptions(from_num, packet_id)
            })
            .await?
        }
        (Some(from_num), None) => {
            blocking(state.db.clone(), move |db| {
                db.query_node_receptions(from_num, limit)
            })
            .await?
        }
        _ => {
            blocking(state.db.clone(), move |db| {
                db.query_recent_receptions(limit)
            })
            .await?
        }
    };
    Ok(Json(receptions))
}

async fn blocking<T, F>(db: Arc<Database>, work: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce(&Database) -> anyhow::Result<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(move || work(&db)).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(internal(error)),
        Err(error) => Err(internal(error)),
    }
}

fn internal(error: impl Display) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}
