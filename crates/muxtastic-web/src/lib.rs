#![forbid(unsafe_code)]
//! Web UI and SQLite history for the Muxtastic multiplexer.
//!
//! The daemon feeds [`Database`] with `FromRadio` frames and reassembled Nexus
//! raw frames, then serves the tabbed UI over Axum. The SQLite file is a normal
//! database file that can be opened by any SQLite client.

pub mod db;
pub mod mqtt_source;
pub mod server;
mod util;

pub use db::{
    run_writer, ChannelCount, ChannelInfo, ChannelNodeCount, CountBucket, Database, DbReceiver,
    DbSource, DbWrite, DirectNode, HourBucket, Message, MqttGateway, Node, NodeCount, PacketFilter,
    PacketFilterOption, PacketFilterOptions, PacketListEntry, PacketRow, RawFrame, Reception,
    Stats, Totals, Traceroute,
};
pub use mqtt_source::{run as run_mqtt_source, GatewayFilter};
pub use server::{
    serve, ClientStatus, NodeStatus, SourceGateway, SourceStatus, StatusFn, StatusSnapshot,
};
