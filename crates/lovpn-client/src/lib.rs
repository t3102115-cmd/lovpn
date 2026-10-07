//! LoVPN Linux client core: profiles, session state, connection engine and broker.
//!
//! Everything that changes the machine's networking lives behind the broker
//! (`lovpn-clientd`); the unprivileged `lovpn` CLI only talks to it. See docs/client.md.
#[cfg(unix)]
pub mod broker;
#[cfg(unix)]
pub mod dns;
#[cfg(unix)]
pub mod engine;
mod error;
pub mod model;
pub mod plan;
#[cfg(unix)]
pub mod profiles;
pub mod protocol;
#[cfg(unix)]
pub mod record;

#[cfg(unix)]
pub use engine::Engine;
pub use error::ClientError;
