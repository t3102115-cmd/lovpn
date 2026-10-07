//! Enrollment wire protocol: one JSON line each way over the pinned TLS channel.
//!
//! The request is at most [`MAX_REQUEST`] bytes with a strict schema. It carries the
//! token **in the TLS body** (never a URL or header) and the client's PUBLIC key only.
//! There is deliberately no "proof of possession": WireGuard keys cannot sign, a
//! home-made proof would be invented cryptography, and registering a key one does not
//! hold only produces a peer nobody can use. The token holder is the authority.
use crate::EnrollError;
use serde::{Deserialize, Serialize};
use std::io::Read;

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_REQUEST: usize = 4096;
pub const MAX_RESPONSE: usize = 16 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub token: String,
    pub client_public_key: String,
}

impl Request {
    pub fn new(token: String, client_public_key: String) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            token,
            client_public_key,
        }
    }
}

/// Server answer. A failure carries only a coarse code; unknown, expired, replayed
/// and revoked tokens are indistinguishable (`denied`).
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u32,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_public_key: Option<String>,
    /// Whether the server confirmed applying the new peer to its host. `false` means
    /// the peer is enrolled but may not be live until the administrator applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied: Option<bool>,
}

impl Response {
    pub fn failure(error: EnrollError) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            ok: false,
            code: Some(error.code().into()),
            profile: None,
            server_public_key: None,
            applied: None,
        }
    }

    pub fn success(profile: String, server_public_key: String, applied: bool) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            ok: true,
            code: None,
            profile: Some(profile),
            server_public_key: Some(server_public_key),
            applied: Some(applied),
        }
    }

    /// Map a failure code back to a static error for display.
    pub fn error(&self) -> EnrollError {
        match self.code.as_deref() {
            Some("enroll.rate-limited") => EnrollError::RateLimited,
            Some("enroll.unavailable") => EnrollError::Unavailable,
            Some("enroll.malformed") => EnrollError::Malformed,
            Some("enroll.too-large") => EnrollError::TooLarge,
            _ => EnrollError::Denied,
        }
    }
}

/// Read one `\n`-terminated line of at most `max` bytes (the newline is not
/// returned). Fails with `TooLarge` rather than buffering more.
pub fn read_line(reader: &mut impl Read, max: usize) -> Result<Vec<u8>, EnrollError> {
    let mut line = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Err(EnrollError::Malformed),
            Ok(_) => {
                if byte[0] == b'\n' {
                    return Ok(line);
                }
                if line.len() >= max {
                    return Err(EnrollError::TooLarge);
                }
                line.push(byte[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(EnrollError::Timeout);
            }
            Err(_) => return Err(EnrollError::Io),
        }
    }
}

pub fn parse_request(line: &[u8]) -> Result<Request, EnrollError> {
    let request: Request = serde_json::from_slice(line).map_err(|_| EnrollError::Malformed)?;
    if request.version != PROTOCOL_VERSION {
        return Err(EnrollError::Malformed);
    }
    Ok(request)
}

pub fn parse_response(line: &[u8]) -> Result<Response, EnrollError> {
    let response: Response = serde_json::from_slice(line).map_err(|_| EnrollError::BadResponse)?;
    if response.version != PROTOCOL_VERSION {
        return Err(EnrollError::BadResponse);
    }
    Ok(response)
}

pub fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>, EnrollError> {
    let mut bytes = serde_json::to_vec(message).map_err(|_| EnrollError::Malformed)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_fields_versions_and_non_json() {
        assert!(
            parse_request(br#"{"version":1,"token":"t","client_public_key":"k","x":1}"#).is_err()
        );
        assert!(parse_request(br#"{"version":2,"token":"t","client_public_key":"k"}"#).is_err());
        assert!(parse_request(b"not json").is_err());
        assert!(parse_request(br#"{"version":1,"token":"t","client_public_key":"k"}"#).is_ok());
    }

    #[test]
    fn line_reader_is_bounded() {
        let mut data: &[u8] = b"abcdef\nrest";
        assert_eq!(read_line(&mut data, 6).ok(), Some(b"abcdef".to_vec()));
        let mut data: &[u8] = b"abcdefg\n";
        assert_eq!(read_line(&mut data, 6).err(), Some(EnrollError::TooLarge));
        let mut data: &[u8] = b"no newline";
        assert_eq!(
            read_line(&mut data, 100).err(),
            Some(EnrollError::Malformed)
        );
    }

    #[test]
    fn failure_response_has_no_detail() {
        let text =
            String::from_utf8(encode(&Response::failure(EnrollError::Denied)).unwrap_or_default())
                .unwrap_or_default();
        assert!(!text.contains("profile") && text.contains("enroll.denied"));
    }
}
