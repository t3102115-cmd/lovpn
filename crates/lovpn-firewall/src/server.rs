//! Pure Linux server forwarding/NAT policy compiler. Executes nothing.
//!
//! The server policy only ever *adds restrictions and NAT* in tables it names; it
//! never sets a drop policy on the host's input/output path and cannot override
//! another table's verdicts. Hosts whose own firewall drops forwarded traffic must
//! allow it explicitly: LoVPN does not edit unrelated rules.
use ipnet::Ipv4Net;
use std::{error::Error, fmt, net::Ipv4Addr};

pub const FILTER_TABLE: &str = "lovpn_server";
pub const NAT_TABLE: &str = "lovpn_server_nat";
pub const MAX_LEASES: usize = 1024;
pub use crate::OWNER_COMMENT;

#[derive(Clone, Debug)]
pub struct ServerPolicy {
    /// WireGuard interface owned by LoVPN, e.g. `lovpn-srv0`.
    pub interface: String,
    /// Uplink interface for NAT, e.g. `eth0`.
    pub wan_interface: String,
    pub pool: Ipv4Net,
    /// Active peer addresses only; revoked leases must not appear here.
    pub leases: Vec<Ipv4Addr>,
    /// State generation stamped into the table comments so the installed policy's
    /// generation can be observed later.
    pub generation: u64,
}

pub struct ServerFirewallPlan {
    ruleset: String,
    reset_ruleset: String,
}

impl ServerFirewallPlan {
    pub fn ruleset(&self) -> &str {
        &self.ruleset
    }
    /// Removes only the two LoVPN-named tables. Never executed by this crate.
    pub fn reset_ruleset(&self) -> &str {
        &self.reset_ruleset
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerFirewallError {
    Interface,
    Pool,
    Lease,
}

impl ServerFirewallError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Interface => "server-firewall.interface",
            Self::Pool => "server-firewall.pool",
            Self::Lease => "server-firewall.lease",
        }
    }
}

impl fmt::Display for ServerFirewallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Interface => "Interface names must be 1–15 ASCII letters, digits, '_', '-' or '.', and the WireGuard and uplink interfaces must differ.",
            Self::Pool => "Address pool must be a canonical IPv4 network from /16 to /29.",
            Self::Lease => "Leases must be distinct usable addresses inside the pool, at most 1024.",
        })
    }
}

impl Error for ServerFirewallError {}

fn valid_interface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}

pub fn compile(policy: &ServerPolicy) -> Result<ServerFirewallPlan, ServerFirewallError> {
    if !valid_interface(&policy.interface)
        || !valid_interface(&policy.wan_interface)
        || policy.interface == policy.wan_interface
    {
        return Err(ServerFirewallError::Interface);
    }
    let pool = policy.pool;
    if pool.addr() != pool.network() || !(16..=29).contains(&pool.prefix_len()) {
        return Err(ServerFirewallError::Pool);
    }
    let mut leases = policy.leases.clone();
    leases.sort();
    if leases.len() > MAX_LEASES
        || leases.windows(2).any(|pair| pair[0] == pair[1])
        || leases.iter().any(|lease| {
            !pool.contains(lease) || *lease == pool.network() || *lease == pool.broadcast()
        })
    {
        return Err(ServerFirewallError::Lease);
    }
    let (wg, wan) = (&policy.interface, &policy.wan_interface);
    let generation = policy.generation;
    let t = FILTER_TABLE;
    let mut rules = format!(
        "# LoVPN server policy preview: not installed, not verified protection.\n\
         # Owns only tables inet {t} and ip {NAT_TABLE}. Never edit the host ruleset.\n\
         # Needs net.ipv4.ip_forward=1 and an allowed UDP listen port (not managed here).\n\
         add table inet {t}\n\
         delete table inet {t}\n\
         add table inet {t} {{ comment \"{OWNER_COMMENT} gen={generation}\"; }}\n\
         add chain inet {t} forward {{ type filter hook forward priority -10; policy accept; }}\n\
         add rule inet {t} forward iifname \"{wg}\" meta nfproto ipv6 counter drop\n\
         add rule inet {t} forward oifname \"{wg}\" meta nfproto ipv6 counter drop\n"
    );
    if leases.is_empty() {
        rules.push_str(&format!(
            "add rule inet {t} forward iifname \"{wg}\" counter drop\n"
        ));
    } else {
        let set = leases
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        rules.push_str(&format!(
            "add rule inet {t} forward iifname \"{wg}\" ip saddr != {{ {set} }} counter drop\n"
        ));
    }
    rules.push_str(&format!(
        "add rule inet {t} forward iifname \"{wg}\" oifname \"{wg}\" counter drop\n\
         add rule inet {t} forward iifname \"{wg}\" oifname != \"{wan}\" counter drop\n\
         add rule inet {t} forward oifname \"{wg}\" iifname != \"{wan}\" counter drop\n\
         add table ip {NAT_TABLE}\n\
         delete table ip {NAT_TABLE}\n\
         add table ip {NAT_TABLE} {{ comment \"{OWNER_COMMENT} gen={generation}\"; }}\n\
         add chain ip {NAT_TABLE} postrouting {{ type nat hook postrouting priority 100; policy accept; }}\n\
         add rule ip {NAT_TABLE} postrouting ip saddr {pool} oifname \"{wan}\" counter masquerade\n"
    ));
    Ok(ServerFirewallPlan {
        ruleset: rules,
        reset_ruleset: format!(
            "# Removes only LoVPN-named server tables; clients lose NAT/forward policy.\n\
             delete table inet {t}\n\
             delete table ip {NAT_TABLE}\n"
        ),
    })
}
