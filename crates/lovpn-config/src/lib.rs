//! Strict, public-only configuration. No filesystem access or secret storage.
//! Deserialization is not validation: consumers must call [`ClientConfig::validate`].
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

mod error;
mod validate;
pub use error::ConfigError;

pub const MAX_CONFIG_BYTES: usize = 65_536;
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub schema_version: u32,
    pub profile: Profile,
    pub tunnel: Tunnel,
    pub dns: Dns,
    pub firewall: Firewall,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub endpoint: SocketAddr,
    pub server_public_key: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tunnel {
    pub interface: String,
    pub addresses: Vec<IpNet>,
    pub mtu: u16,
    pub routing: RoutingMode,
    pub routes: Vec<IpNet>,
    pub ipv6: Ipv6Mode,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    pub servers: Vec<IpAddr>,
    /// Additional suffix-specific resolvers through the tunnel (Windows NRPT).
    /// Baseline tunnel DNS remains mandatory; this never enables physical-uplink DNS.
    #[serde(default)]
    pub scopes: Vec<DnsScope>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DnsScope {
    pub namespace: String,
    pub servers: Vec<Ipv4Addr>,
}

/// Also used to validate persisted NRPT intent before recovery or restoration.
pub fn validate_dns_scopes(scopes: &[DnsScope]) -> Result<(), ConfigError> {
    validate::validate_dns_scopes(scopes)
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Firewall {
    pub kill_switch: KillSwitchMode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RoutingMode {
    Full,
    Split,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Ipv6Mode {
    Block,
    Tunnel,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum KillSwitchMode {
    Off,
    VpnOnly,
    Strict,
}

/// Parse at most 64 KiB and validate every security-relevant field.
///
/// TOML errors are intentionally discarded: their snippets can contain secrets
/// accidentally pasted into an unsupported field. No source error is retained.
pub fn parse(input: &str) -> Result<ClientConfig, ConfigError> {
    if input.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge);
    }
    let config: ClientConfig = toml::from_str(input).map_err(|_| ConfigError::Syntax)?;
    config.validate()?;
    Ok(config)
}
