//! LoVPN Linux server core: state, peers, offline enrollment export.
//!
//! This crate performs no network I/O and executes no commands. Applying the
//! generated WireGuard/nftables configuration needs the privileged broker, which
//! is not implemented in this version.
#[cfg(unix)]
pub mod applier;
#[cfg(unix)]
pub mod broker;
pub mod enroll;
#[cfg(unix)]
pub mod enroll_server;
mod error;
pub mod limits;
pub mod state;
#[cfg(unix)]
pub mod store;

pub use error::ServerError;
pub use state::{
    ExportOptions, Peer, PeerStatus, STATE_SCHEMA, ServerSettings, ServerState, SetupParams,
};
#[cfg(unix)]
pub use store::Store;
