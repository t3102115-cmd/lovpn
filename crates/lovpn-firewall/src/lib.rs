//! Pure Linux policy compiler. Does not inspect, install or execute anything.
use lovpn_config::{ClientConfig, Ipv6Mode, KillSwitchMode, RoutingMode};
use std::{error::Error, fmt};

pub mod server;

pub const TABLE_NAME: &str = "lovpn_client";
/// Ownership marker carried in every LoVPN-installed table comment (client and server),
/// followed by ` gen=<generation>`. A same-named table without it is foreign.
pub const OWNER_COMMENT: &str = "lovpn-owned";
pub const WIREGUARD_FWMARK: u32 = 0x4c6f;

pub struct FirewallPlan {
    ruleset: String,
    reset_ruleset: String,
}

impl FirewallPlan {
    pub fn ruleset(&self) -> &str {
        &self.ruleset
    }

    /// Removal releases this policy's protection. Never executed by this crate.
    pub fn reset_ruleset(&self) -> &str {
        &self.reset_ruleset
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirewallError {
    InvalidConfig,
    Disabled,
    SplitUnsupported,
    Ipv6UnderlayUnsupported,
}

impl FirewallError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidConfig => "firewall.invalid-config",
            Self::Disabled => "firewall.disabled",
            Self::SplitUnsupported => "firewall.split-unsupported",
            Self::Ipv6UnderlayUnsupported => "firewall.ipv6-underlay-unsupported",
        }
    }
}

impl fmt::Display for FirewallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "Configuration failed revalidation; no firewall plan was generated.",
            Self::Disabled => "Kill switch is off. No protection plan can be generated; no existing rules were changed.",
            Self::SplitUnsupported => "Split-route enforcement is not implemented. No firewall plan was generated.",
            Self::Ipv6UnderlayUnsupported => "IPv6 endpoint enforcement needs a tested NDP policy and is not implemented. IPv6 inside an IPv4 tunnel is supported by this compiler.",
        })
    }
}

impl Error for FirewallError {}

/// Compile a laboratory full-tunnel policy, never an assurance of OS protection.
///
/// A future broker must authenticate its caller, verify interface provenance and
/// table ownership, set WireGuard's socket mark, serialize generations, and apply
/// the whole batch atomically. Interface-name matching is not link authentication.
pub fn compile(config: &ClientConfig) -> Result<FirewallPlan, FirewallError> {
    build(config, TableHeader::Preview)
}

/// Like [`compile`], but the table is created atomically with an ownership comment
/// stamped with `generation`, so an installed policy can later be recognized as LoVPN's
/// and its generation observed. Used by the client broker.
pub fn compile_owned(
    config: &ClientConfig,
    generation: u64,
) -> Result<FirewallPlan, FirewallError> {
    build(config, TableHeader::Owned(generation))
}

enum TableHeader {
    Preview,
    Owned(u64),
}

fn build(config: &ClientConfig, header: TableHeader) -> Result<FirewallPlan, FirewallError> {
    config
        .validate()
        .map_err(|_| FirewallError::InvalidConfig)?;
    if config.firewall.kill_switch == KillSwitchMode::Off {
        return Err(FirewallError::Disabled);
    }
    if config.tunnel.routing != RoutingMode::Full {
        return Err(FirewallError::SplitUnsupported);
    }
    if config.profile.endpoint.is_ipv6() {
        return Err(FirewallError::Ipv6UnderlayUnsupported);
    }

    let banner = match header {
        TableHeader::Preview => {
            "# LoVPN laboratory preview ONLY: not installed, not verified protection.\n\
             # A broker must verify table/link ownership and apply this whole batch."
        }
        TableHeader::Owned(_) => {
            "# LoVPN client kill-switch policy, installed by the broker as one atomic batch.\n\
             # Observed state, not this text, decides whether it is protecting."
        }
    };
    let table_header = match header {
        TableHeader::Preview => {
            format!("add table inet {TABLE_NAME}\nflush table inet {TABLE_NAME}\n")
        }
        TableHeader::Owned(generation) => format!(
            "add table inet {TABLE_NAME}\ndelete table inet {TABLE_NAME}\nadd table inet {TABLE_NAME} {{ comment \"{OWNER_COMMENT} gen={generation}\"; }}\n"
        ),
    };
    let mut rules = format!(
        "{banner}\n\
         # WireGuard must use fwmark {WIREGUARD_FWMARK:#x}. Only exceptions besides the tunnel,\n\
         # the marked endpoint flow and loopback: IPv4 DHCP client traffic (udp 68 -> 67), so\n\
         # the uplink lease can renew. No LAN, NDP or other exceptions.\n\
         {table_header}\
         add chain inet {TABLE_NAME} output {{ type filter hook output priority -150; policy drop; }}\n\
         add chain inet {TABLE_NAME} forward {{ type filter hook forward priority -150; policy drop; }}\n\
         add rule inet {TABLE_NAME} output oifname \"lo\" counter accept\n"
    );
    if config.tunnel.ipv6 == Ipv6Mode::Block {
        rules.push_str(&format!(
            "add rule inet {TABLE_NAME} output meta nfproto ipv6 counter drop\n"
        ));
    }
    rules.push_str(&format!(
        "add rule inet {TABLE_NAME} output meta mark {WIREGUARD_FWMARK:#x} ip daddr {} udp dport {} counter accept\n",
        config.profile.endpoint.ip(), config.profile.endpoint.port()
    ));
    rules.push_str(&format!(
        "add rule inet {TABLE_NAME} output meta nfproto ipv4 udp sport 68 udp dport 67 counter accept\n"
    ));
    let family = if config.tunnel.ipv6 == Ipv6Mode::Block {
        "meta nfproto ipv4 "
    } else {
        ""
    };
    rules.push_str(&format!(
        "add rule inet {TABLE_NAME} output {family}oifname \"{}\" counter accept\n",
        config.tunnel.interface
    ));
    Ok(FirewallPlan {
        ruleset: rules,
        reset_ruleset: format!(
            "# WARNING: removal permits traffic outside the VPN. Preview only.\n\
             # Verify ownership before removing this table. Never flush the host ruleset.\n\
             delete table inet {TABLE_NAME}\n"
        ),
    })
}
