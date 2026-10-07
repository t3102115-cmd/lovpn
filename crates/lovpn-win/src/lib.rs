//! LoVPN Windows platform layer.
//!
//! Every `unsafe` block in the workspace lives in this crate, behind small safe APIs:
//! - [`driver`]: WireGuardNT, loaded only after its SHA-256 matches the pinned release;
//! - [`ip`]: addresses, routes, MTU and DNS through the IP Helper API;
//! - [`wfp`]: the persistent Windows Filtering Platform kill switch.
//!
//! On non-Windows targets this crate is empty, so the workspace still builds everywhere.
pub mod dns;
mod error;
pub mod policy;
pub use error::WinError;

#[cfg(windows)]
pub mod daemon;
#[cfg(windows)]
pub mod driver;
#[cfg(windows)]
pub mod engine;
#[cfg(windows)]
pub mod ip;
#[cfg(windows)]
pub mod pipe;
#[cfg(windows)]
pub mod profiles;
#[cfg(any(windows, test))]
pub mod record;
#[cfg(windows)]
pub mod store;
#[cfg(windows)]
pub mod wfp;
