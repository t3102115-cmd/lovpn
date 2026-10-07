use std::{error::Error, fmt};

/// Static, sanitized errors. They never carry tokens, keys, addresses or OS text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollError {
    /// Token text is not in the `lovpn1-…` format.
    TokenFormat,
    /// Pin text is not `sha256:` plus 64 hex digits.
    PinFormat,
    /// A message is malformed, has an unknown field/version or is not UTF-8.
    Malformed,
    /// A message exceeded its fixed size bound.
    TooLarge,
    /// The overall deadline for the exchange elapsed.
    Timeout,
    /// The server certificate does not match the pin. Nothing was sent.
    PinMismatch,
    /// TLS could not be established (not a pin mismatch).
    Tls,
    /// Network input/output failed.
    Io,
    /// The server refused the request (deliberately undifferentiated).
    Denied,
    /// The server is temporarily refusing connections from this source.
    RateLimited,
    /// The server could not process the request right now.
    Unavailable,
    /// The server's answer failed local validation.
    BadResponse,
    /// The OS random source failed.
    Random,
}

impl EnrollError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::TokenFormat => "enroll.token-format",
            Self::PinFormat => "enroll.pin-format",
            Self::Malformed => "enroll.malformed",
            Self::TooLarge => "enroll.too-large",
            Self::Timeout => "enroll.timeout",
            Self::PinMismatch => "enroll.pin-mismatch",
            Self::Tls => "enroll.tls",
            Self::Io => "enroll.io",
            Self::Denied => "enroll.denied",
            Self::RateLimited => "enroll.rate-limited",
            Self::Unavailable => "enroll.unavailable",
            Self::BadResponse => "enroll.bad-response",
            Self::Random => "enroll.random",
        }
    }
}

impl fmt::Display for EnrollError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TokenFormat => "That is not a LoVPN enrollment token (expected lovpn1-<id>-<secret>).",
            Self::PinFormat => "The server pin must be 'sha256:' followed by 64 hexadecimal digits.",
            Self::Malformed => "The enrollment message is malformed.",
            Self::TooLarge => "The enrollment message exceeds its size limit.",
            Self::Timeout => "The enrollment exchange timed out.",
            Self::PinMismatch => "The server's certificate does not match the pin you supplied. Nothing was sent. Check the address and the pin; do not retry against an untrusted network.",
            Self::Tls => "A TLS 1.3 connection to the enrollment server could not be established.",
            Self::Io => "Network input/output failed.",
            Self::Denied => "The server refused this enrollment. The token may be wrong, expired, already used or revoked; ask the administrator for a new one.",
            Self::RateLimited => "The server is temporarily refusing enrollment attempts from this address. Wait and retry later.",
            Self::Unavailable => "The server could not process the enrollment right now. Retry later.",
            Self::BadResponse => "The server's answer was invalid and was discarded.",
            Self::Random => "The operating system random source failed.",
        })
    }
}

impl Error for EnrollError {}
