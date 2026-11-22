#![forbid(unsafe_code)]
//! Transport-agnostic logic for the Muxtastic Meshtastic multiplexer.
//!
//! Nothing in this crate performs I/O, reads the clock, or depends on an async
//! runtime. The binary crate owns the operating system and Tokio.

pub mod channel_crypto;
pub mod config;
pub mod details;
pub mod meshcore;
pub mod mqtt;
pub mod nexus;
pub mod packet;
pub mod protocol;
pub mod provision;
pub mod raw_tunnel;
pub mod replay;
pub mod router;
pub mod state;
pub mod util;

/// Node id used by the virtual/mock node when no real id is available.
pub const SYNTHETIC_NODE_NUM: u32 = 0x1234_5678;
