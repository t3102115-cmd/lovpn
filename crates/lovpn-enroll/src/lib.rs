//! LoVPN online enrollment building blocks: one-time token format, the bounded
//! request/response protocol and the pinned TLS 1.3 transport.
//!
//! This crate holds no server state and executes nothing. The server decides what a
//! redemption does (`lovpn-server`); the client only sends its **public** key.
//! No cryptography is implemented here: TLS is `rustls` (ring provider), digests are
//! SHA-256 and comparisons are `subtle` constant-time.
mod error;
pub mod proto;
pub mod tls;
pub mod token;

pub use error::EnrollError;
