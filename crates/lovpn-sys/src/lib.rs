//! Shared privileged-component plumbing for the LoVPN server and client brokers.
//!
//! - [`exec`]: run the few fixed system tools (`ip`, `wg`, `nft`, `resolvectl`) without
//!   a shell, with absolute paths, a cleared environment and a timeout;
//! - [`ipc`]: an authenticated Unix-socket service skeleton (peer credentials, bounded
//!   single-line requests, timeouts) and its client.
//!
//! Nothing here knows about VPN policy: callers decide which commands to run.
#[cfg(unix)]
pub mod exec;
pub mod inspect;
#[cfg(unix)]
pub mod ipc;
