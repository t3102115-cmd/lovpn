#[cfg(unix)]
use lovpn_sys::exec::ExecError;
use std::{error::Error, fmt};

/// Static, sanitized errors: never contain keys, paths, addresses or OS error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientError {
    ProfileName,
    ProfileExists,
    ProfileNotFound,
    ProfileInvalid,
    TooManyProfiles,
    KeyInvalid,
    ServerKeyMismatch,
    UnsupportedIpv6Tunnel,
    UnsupportedRouting,
    UnsupportedEndpoint,
    DnsUnsupported,
    ForeignInterface,
    ForeignTable,
    ForeignRule,
    ForeignRoute,
    ToolMissing,
    CommandFailed(&'static str),
    NotConnected,
    SwitchWhileConnected,
    UnsupportedOperation,
    NoProfileSelected,
    Record,
    Storage,
    Permissions,
}

impl ClientError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProfileName => "profile.name",
            Self::ProfileExists => "profile.exists",
            Self::ProfileNotFound => "profile.not-found",
            Self::ProfileInvalid => "profile.invalid",
            Self::TooManyProfiles => "profile.too-many",
            Self::KeyInvalid => "profile.key-invalid",
            Self::ServerKeyMismatch => "profile.server-key-mismatch",
            Self::UnsupportedIpv6Tunnel => "connect.ipv6-tunnel-unsupported",
            Self::UnsupportedRouting => "connect.routing-unsupported",
            Self::UnsupportedEndpoint => "connect.endpoint-unsupported",
            Self::DnsUnsupported => "connect.dns-unsupported",
            Self::ForeignInterface => "connect.foreign-interface",
            Self::ForeignTable => "connect.foreign-table",
            Self::ForeignRule => "connect.foreign-rule",
            Self::ForeignRoute => "connect.foreign-route",
            Self::ToolMissing => "connect.tool-missing",
            Self::CommandFailed(_) => "connect.command-failed",
            Self::NotConnected => "session.not-connected",
            Self::SwitchWhileConnected => "session.switch-while-connected",
            Self::UnsupportedOperation => "unsupported.platform",
            Self::NoProfileSelected => "session.no-profile",
            Self::Record => "session.record",
            Self::Storage => "profile.storage",
            Self::Permissions => "profile.permissions",
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProfileName => f.write_str("Profile names are 1-32 lowercase letters, digits, '-' or '_', starting with a letter or digit."),
            Self::ProfileExists => f.write_str("A profile with that name already exists; remove it first."),
            Self::ProfileNotFound => f.write_str("No profile with that name exists. Run `lovpn profile list`."),
            Self::ProfileInvalid => f.write_str("The profile failed validation (see `lovpn config validate`)."),
            Self::TooManyProfiles => f.write_str("Profile limit (64) reached."),
            Self::KeyInvalid => f.write_str("The private key is not a canonical, clamped WireGuard key."),
            Self::ServerKeyMismatch => f.write_str("The profile's server public key does not match the key you expected. Do not use this profile: it may have been altered."),
            Self::UnsupportedIpv6Tunnel => f.write_str("IPv6-through-the-tunnel is not supported by this client yet; use the 'block' policy."),
            Self::UnsupportedRouting => f.write_str("Only full-tunnel routing is supported by this client yet."),
            Self::UnsupportedEndpoint => f.write_str("IPv6 server endpoints are not supported by this client yet."),
            Self::DnsUnsupported => f.write_str("No supported resolver (systemd-resolved) was found, so DNS cannot be protected. Nothing was changed. Start systemd-resolved or run the service with --dns-backend unmanaged to connect without DNS management (DNS will be reported unprotected)."),
            Self::ForeignInterface => f.write_str("An interface with the LoVPN name exists but LoVPN did not create it (or it is not WireGuard). It was not modified."),
            Self::ForeignTable => f.write_str("An nftables table with LoVPN's name exists without the LoVPN ownership marker. It was not modified."),
            Self::ForeignRule => f.write_str("A routing rule at LoVPN's reserved priority exists and is not LoVPN's. It was not modified."),
            Self::ForeignRoute => f.write_str("The LoVPN policy-routing table contains a route LoVPN did not install. It was not modified."),
            Self::ToolMissing => f.write_str("A required system tool (ip, wg, nft or resolvectl) was not found in a standard location."),
            Self::CommandFailed(step) => write!(f, "A network configuration step failed ({step}). Changes were rolled back where possible; the kill switch, if armed, stays armed. Run diagnostics."),
            Self::NotConnected => f.write_str("There is no active connection."),
            Self::UnsupportedOperation => f.write_str("This operation is not available on this platform. See docs/client.md."),
            Self::SwitchWhileConnected => f.write_str("A connection is active. Run `lovpn connect <name>` to switch servers directly, or disconnect first."),
            Self::NoProfileSelected => f.write_str("No profile was chosen and none was used before."),
            Self::Record => f.write_str("The service's own state record could not be read or written safely."),
            Self::Storage => f.write_str("Profile storage input/output failed; nothing was partially kept."),
            Self::Permissions => f.write_str("The profile directory must be mode 0700 and owned by the service; files 0600 without links."),
        }
    }
}

impl Error for ClientError {}

#[cfg(unix)]
impl From<ExecError> for ClientError {
    fn from(error: ExecError) -> Self {
        match error {
            ExecError::ToolMissing => Self::ToolMissing,
            ExecError::Failed(step) => Self::CommandFailed(step),
        }
    }
}
