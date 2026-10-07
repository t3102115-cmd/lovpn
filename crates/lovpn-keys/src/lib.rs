//! WireGuard-compatible key material with distinct, redacting types.
//!
//! All curve arithmetic is delegated to `x25519-dalek` and all randomness to the
//! operating system through `getrandom`. This crate implements no cryptography; it
//! only enforces canonical encodings, rejects weak values and keeps secrets out of
//! `Debug`/`Display`/error output.
//!
//! Roles are encoded in the type so a server private key cannot be passed where a
//! client private key is expected. Memory zeroization is best effort: moves of
//! small values can leave stack copies that no library can scrub.
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{error::Error, fmt, marker::PhantomData, str::FromStr};
use x25519_dalek::StaticSecret;
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
pub mod file;

mod sealed {
    pub trait Sealed {}
}

/// Marker for key roles. Sealed: roles are a closed set.
pub trait Role: sealed::Sealed {
    const NAME: &'static str;
}

/// The VPN server (WireGuard "interface" owner that accepts peers).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Server {}
/// A client device (WireGuard peer on the server).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Client {}
impl sealed::Sealed for Server {}
impl sealed::Sealed for Client {}
impl Role for Server {
    const NAME: &'static str = "server";
}
impl Role for Client {
    const NAME: &'static str = "client";
}

pub type ServerPrivateKey = PrivateKey<Server>;
pub type ServerPublicKey = PublicKey<Server>;
pub type ClientPrivateKey = PrivateKey<Client>;
pub type ClientPublicKey = PublicKey<Client>;

/// Static, sanitized key errors: never contain key text, lengths or paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyError {
    Encoding,
    NonCanonical,
    Weak,
    Unclamped,
    Randomness,
}

impl KeyError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Encoding => "key.encoding",
            Self::NonCanonical => "key.non-canonical",
            Self::Weak => "key.weak",
            Self::Unclamped => "key.unclamped",
            Self::Randomness => "key.randomness",
        }
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Encoding => "Key must be canonical standard base64 text of exactly 32 bytes (44 characters). Input is not echoed.",
            Self::NonCanonical => "Public key is not a canonical Curve25519 encoding.",
            Self::Weak => "Key is all zero or a known low-order point and is rejected.",
            Self::Unclamped => "Private key is not in WireGuard's clamped form; generate it with LoVPN or `wg genkey`.",
            Self::Randomness => "The operating system random number generator failed; no key was created.",
        })
    }
}

impl Error for KeyError {}

const KEY_LEN: usize = 32;
/// 2^255 - 19, little-endian: public keys must be fully reduced.
const FIELD_PRIME: [u8; KEY_LEN] = {
    let mut p = [0xff; KEY_LEN];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

fn decode_32(text: &str) -> Result<[u8; KEY_LEN], KeyError> {
    if text.len() != 44 {
        return Err(KeyError::Encoding);
    }
    let mut buffer = Zeroizing::new([0u8; 33]);
    // Decode into a fixed buffer; reject anything that is not exactly 32 bytes.
    let written = STANDARD
        .decode_slice(text, &mut buffer[..])
        .map_err(|_| KeyError::Encoding)?;
    if written != KEY_LEN {
        return Err(KeyError::Encoding);
    }
    let mut bytes = [0u8; KEY_LEN];
    bytes.copy_from_slice(&buffer[..KEY_LEN]);
    // Reject non-canonical base64 (non-zero trailing bits, alternate padding).
    let reencoded = Zeroizing::new(STANDARD.encode(bytes));
    if reencoded.as_str() != text {
        bytes.zeroize();
        return Err(KeyError::Encoding);
    }
    Ok(bytes)
}

fn less_than_prime(bytes: &[u8; KEY_LEN]) -> bool {
    for index in (0..KEY_LEN).rev() {
        if bytes[index] != FIELD_PRIME[index] {
            return bytes[index] < FIELD_PRIME[index];
        }
    }
    false
}

/// A WireGuard/X25519 public key for role `R`.
pub struct PublicKey<R: Role> {
    bytes: [u8; KEY_LEN],
    role: PhantomData<fn() -> R>,
}

impl<R: Role> Clone for PublicKey<R> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<R: Role> Copy for PublicKey<R> {}
impl<R: Role> PartialEq for PublicKey<R> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}
impl<R: Role> Eq for PublicKey<R> {}
impl<R: Role> std::hash::Hash for PublicKey<R> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl<R: Role> PublicKey<R> {
    /// Validate raw bytes: reject zero, a set high bit, unreduced values and
    /// low-order points (via the library's contributory-behavior check).
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Result<Self, KeyError> {
        if bytes[31] & 0x80 != 0 || !less_than_prime(&bytes) {
            return Err(KeyError::NonCanonical);
        }
        let probe = StaticSecret::from([9u8; KEY_LEN]);
        let shared = probe.diffie_hellman(&x25519_dalek::PublicKey::from(bytes));
        if bytes.iter().all(|b| *b == 0) || !shared.was_contributory() {
            return Err(KeyError::Weak);
        }
        Ok(Self {
            bytes,
            role: PhantomData,
        })
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }

    /// True when the value has the shape of a clamped private key (1 in 16 genuine
    /// public keys do too). Cannot prove a secret was pasted, but lets tools make
    /// the administrator confirm before storing it as "public" data.
    pub fn resembles_clamped_private_key(&self) -> bool {
        is_clamped(&self.bytes)
    }
}

impl<R: Role> FromStr for PublicKey<R> {
    type Err = KeyError;
    fn from_str(text: &str) -> Result<Self, KeyError> {
        Self::from_bytes(decode_32(text)?)
    }
}

impl<R: Role> fmt::Display for PublicKey<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&STANDARD.encode(self.bytes))
    }
}

impl<R: Role> fmt::Debug for PublicKey<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey<{}>({self})", R::NAME)
    }
}

/// A clamped X25519 private key for role `R`. Zeroized on drop, never printed.
pub struct PrivateKey<R: Role> {
    bytes: Box<[u8; KEY_LEN]>,
    role: PhantomData<fn() -> R>,
}

impl<R: Role> Drop for PrivateKey<R> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl<R: Role> fmt::Debug for PrivateKey<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey<{}>(<redacted>)", R::NAME)
    }
}

fn is_clamped(bytes: &[u8; KEY_LEN]) -> bool {
    bytes[0] & 0b111 == 0 && bytes[31] & 0x80 == 0 && bytes[31] & 0x40 != 0
}

impl<R: Role> PrivateKey<R> {
    /// Generate with the operating system CSPRNG, in WireGuard's clamped form.
    pub fn generate() -> Result<Self, KeyError> {
        let mut bytes = Box::new([0u8; KEY_LEN]);
        if getrandom::fill(&mut bytes[..]).is_err() {
            bytes.zeroize();
            return Err(KeyError::Randomness);
        }
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;
        Ok(Self {
            bytes,
            role: PhantomData,
        })
    }

    /// Strictly parse canonical base64. Unclamped values are rejected as ambiguous.
    pub fn from_base64(text: &str) -> Result<Self, KeyError> {
        let mut raw = decode_32(text)?;
        let mut bytes = Box::new(raw);
        raw.zeroize();
        if !is_clamped(&bytes) {
            bytes.zeroize();
            return Err(KeyError::Unclamped);
        }
        Ok(Self {
            bytes,
            role: PhantomData,
        })
    }

    /// From raw bytes (for example read back from protected storage). Same strictness
    /// as [`Self::from_base64`]: unclamped values are rejected.
    pub fn from_bytes(raw: [u8; KEY_LEN]) -> Result<Self, KeyError> {
        let mut bytes = Box::new(raw);
        if !is_clamped(&bytes) {
            bytes.zeroize();
            return Err(KeyError::Unclamped);
        }
        Ok(Self {
            bytes,
            role: PhantomData,
        })
    }

    pub fn public_key(&self) -> PublicKey<R> {
        let secret = StaticSecret::from(*self.bytes);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        PublicKey {
            bytes: public,
            role: PhantomData,
        }
    }

    /// Raw key bytes for handing to a WireGuard driver API. Zeroized on drop.
    pub fn expose_bytes(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(*self.bytes)
    }

    /// Explicitly expose the secret as base64 for protected storage or handoff to
    /// a WireGuard facility. The returned text is zeroized on drop.
    pub fn expose_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(*self.bytes))
    }
}

/// Optional WireGuard pre-shared key. A secret: never part of a public profile.
pub struct PresharedKey {
    bytes: Box<[u8; KEY_LEN]>,
}

impl Drop for PresharedKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PresharedKey(<redacted>)")
    }
}

impl PresharedKey {
    pub fn generate() -> Result<Self, KeyError> {
        let mut bytes = Box::new([0u8; KEY_LEN]);
        if getrandom::fill(&mut bytes[..]).is_err() {
            bytes.zeroize();
            return Err(KeyError::Randomness);
        }
        if bytes.iter().all(|b| *b == 0) {
            bytes.zeroize();
            return Err(KeyError::Weak);
        }
        Ok(Self { bytes })
    }

    pub fn from_base64(text: &str) -> Result<Self, KeyError> {
        let mut raw = decode_32(text)?;
        let bytes = Box::new(raw);
        raw.zeroize();
        if bytes.iter().all(|b| *b == 0) {
            return Err(KeyError::Weak);
        }
        Ok(Self { bytes })
    }

    pub fn expose_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(*self.bytes))
    }
}
