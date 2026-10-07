//! One-time enrollment token: `lovpn1-<16 hex id>-<43 base64url secret>`.
//!
//! The secret is 256 bits from the OS CSPRNG. The id is a random, non-secret handle
//! used for lookup, listing and logs. The server stores only `digest()` (SHA-256 over
//! a domain tag and the secret); a 256-bit random secret needs no slow KDF, and the
//! digest is compared in constant time.
use crate::EnrollError;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const PREFIX: &str = "lovpn1-";
pub const ID_BYTES: usize = 8;
pub const SECRET_BYTES: usize = 32;
/// Exact length of the textual token.
pub const TOKEN_LEN: usize = PREFIX.len() + ID_BYTES * 2 + 1 + 43;
const DIGEST_TAG: &[u8] = b"lovpn-enroll-token-v1\0";

pub struct Token {
    id: [u8; ID_BYTES],
    secret: [u8; SECRET_BYTES],
}

impl Drop for Token {
    fn drop(&mut self) {
        self.id.zeroize();
        self.secret.zeroize();
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 || !text.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Hex of a stored digest, as kept in server state.
pub fn digest_hex(digest: &[u8; 32]) -> String {
    hex(digest)
}

pub fn parse_digest(text: &str) -> Option<[u8; 32]> {
    unhex::<32>(text)
}

/// Whether `text` is a well-formed lowercase-hex token id.
pub fn valid_id(text: &str) -> bool {
    unhex::<ID_BYTES>(text).is_some()
}

impl Token {
    /// Generate a fresh token from the operating system's random source.
    pub fn generate() -> Result<Self, EnrollError> {
        let mut token = Self {
            id: [0; ID_BYTES],
            secret: [0; SECRET_BYTES],
        };
        getrandom::fill(&mut token.id).map_err(|_| EnrollError::Random)?;
        getrandom::fill(&mut token.secret).map_err(|_| EnrollError::Random)?;
        Ok(token)
    }

    /// Strictly parse token text. Errors never echo the input.
    pub fn parse(text: &str) -> Result<Self, EnrollError> {
        let text = text.trim_end_matches(['\n', '\r']);
        if text.len() != TOKEN_LEN || !text.starts_with(PREFIX) {
            return Err(EnrollError::TokenFormat);
        }
        let rest = &text[PREFIX.len()..];
        let (id_text, secret_text) = rest.split_at(ID_BYTES * 2);
        let secret_text = secret_text
            .strip_prefix('-')
            .ok_or(EnrollError::TokenFormat)?;
        let id = unhex::<ID_BYTES>(id_text).ok_or(EnrollError::TokenFormat)?;
        let mut decoded = URL_SAFE_NO_PAD
            .decode(secret_text)
            .map_err(|_| EnrollError::TokenFormat)?;
        let mut secret = [0u8; SECRET_BYTES];
        let ok = decoded.len() == SECRET_BYTES;
        if ok {
            secret.copy_from_slice(&decoded);
        }
        decoded.zeroize();
        if !ok {
            return Err(EnrollError::TokenFormat);
        }
        // Reject non-canonical base64 (trailing bits) so one secret has one spelling.
        let token = Self { id, secret };
        if token.expose() != text {
            return Err(EnrollError::TokenFormat);
        }
        Ok(token)
    }

    pub fn id_hex(&self) -> String {
        hex(&self.id)
    }

    /// The token text. Only for showing it once to the administrator or sending it
    /// to the server over the pinned channel.
    pub fn expose(&self) -> String {
        format!(
            "{PREFIX}{}-{}",
            hex(&self.id),
            URL_SAFE_NO_PAD.encode(self.secret)
        )
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_TAG);
        hasher.update(self.secret);
        hasher.finalize().into()
    }

    /// Constant-time comparison against a stored digest.
    pub fn matches(&self, stored: &[u8; 32]) -> bool {
        self.digest().ct_eq(stored).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_has_fixed_length() {
        let token = Token::generate().unwrap_or_else(|_| unreachable!());
        let text = token.expose();
        assert_eq!(text.len(), TOKEN_LEN);
        let parsed = Token::parse(&text).unwrap_or_else(|_| unreachable!());
        assert_eq!(parsed.id_hex(), token.id_hex());
        assert!(parsed.matches(&token.digest()));
    }

    #[test]
    fn two_tokens_differ() {
        let a = Token::generate().unwrap_or_else(|_| unreachable!());
        let b = Token::generate().unwrap_or_else(|_| unreachable!());
        assert_ne!(a.expose(), b.expose());
        assert!(!a.matches(&b.digest()));
    }

    #[test]
    fn rejects_malformed_text_without_echo() {
        for bad in [
            "",
            "lovpn1-",
            "lovpn2-0011223344556677-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "lovpn1-0011223344556677_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "lovpn1-00112233445566zz-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "lovpn1-0011223344556677-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
        ] {
            let error = Token::parse(bad).err();
            assert_eq!(error, Some(EnrollError::TokenFormat), "{bad}");
        }
    }

    #[test]
    fn debug_is_redacted() {
        let token = Token::generate().unwrap_or_else(|_| unreachable!());
        assert!(!format!("{token:?}").contains(&token.expose()));
    }

    #[test]
    fn digest_hex_round_trips() {
        let token = Token::generate().unwrap_or_else(|_| unreachable!());
        let hex = digest_hex(&token.digest());
        assert_eq!(parse_digest(&hex), Some(token.digest()));
        assert_eq!(parse_digest("zz"), None);
    }
}
