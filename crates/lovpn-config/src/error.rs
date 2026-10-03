use std::{error::Error, fmt};

/// Static, sanitized diagnostics: never stores input, paths, keys or addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    TooLarge,
    Syntax,
    Version,
    Name,
    Endpoint,
    PublicKey,
    Interface,
    Addresses,
    Mtu,
    Routes,
    Ipv6Policy,
    Dns,
    DnsRoute,
}

impl ConfigError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooLarge => "config.too-large",
            Self::Syntax => "config.syntax",
            Self::Version => "config.version",
            Self::Name => "config.name",
            Self::Endpoint => "config.endpoint",
            Self::PublicKey => "config.public-key",
            Self::Interface => "config.interface",
            Self::Addresses => "config.addresses",
            Self::Mtu => "config.mtu",
            Self::Routes => "config.routes",
            Self::Ipv6Policy => "config.ipv6-policy",
            Self::Dns => "config.dns",
            Self::DnsRoute => "config.dns-route",
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "Configuration exceeds the 64 KiB limit.",
            Self::Syntax => "Invalid configuration: check TOML, required fields, types and unknown fields. Input is not echoed for privacy.",
            Self::Version => "Unsupported configuration version. Only schema version 1 is accepted; no automatic migration is available.",
            Self::Name => "Profile name must be 1–80 bytes of letters, numbers, spaces or -_.(), without surrounding spaces.",
            Self::Endpoint => "Endpoint must be a literal unicast IP and nonzero port, without a scope ID or special-use local address.",
            Self::PublicKey => "Server public key must be a canonical base64-encoded, nonzero 32-byte key. This does not authenticate the server.",
            Self::Interface => "Tunnel interface must start with lovpn and contain at most 15 ASCII letters, digits, underscores or hyphens.",
            Self::Addresses => "Provide 1–8 distinct unicast tunnel addresses, including IPv4; network/broadcast IPv4 host addresses are invalid.",
            Self::Mtu => "This configuration version requires an MTU from 1280 to 1420.",
            Self::Routes => "Routes must be canonical, distinct and nonoverlapping (1–64). Full mode requires exactly the enabled families' default routes; split mode forbids default and special-use routes.",
            Self::Ipv6Policy => "IPv6 addresses/routes must agree with the explicit block or tunnel policy.",
            Self::Dns => "Provide 1–4 distinct unicast DNS IPs; local stubs, link-local and blocked IPv6 resolvers are not supported.",
            Self::DnsRoute => "Every DNS resolver must be covered by a configured tunnel route.",
        })
    }
}

impl Error for ConfigError {}
