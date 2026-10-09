//! Platform-neutral client model shared by the Linux and Windows brokers and the CLI:
//! connection state, checks, profile summaries. Serialized as the broker's JSON.
use lovpn_config::KillSwitchMode;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// A handshake older than this is stale: persistent keepalive rekeys roughly every 2 min.
pub const HANDSHAKE_MAX_AGE_SECS: u64 = 180;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Desired {
    Connected,
    #[default]
    Disconnected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckStatus {
    Ok,
    Fail,
    Unknown,
    /// Not applicable (for example the kill switch is off).
    Off,
}

#[derive(Clone, Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    /// Every check was observed and passed.
    Protected,
    /// Connected as requested but an observed check failed.
    Degraded,
    Connecting,
    /// Not connected and no kill switch armed: normal networking.
    Disconnected,
    /// Not connected, kill switch armed: network traffic is blocked on purpose.
    Blocked,
    /// A check could not be observed; nothing is claimed.
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct Status {
    pub state: State,
    pub desired: Desired,
    pub profile: Option<String>,
    pub kill_switch: Option<String>,
    pub kill_switch_armed: bool,
    pub checks: Vec<Check>,
    /// Machine-readable reasons the state is not `protected`.
    pub reasons: Vec<String>,
    pub handshake_age_secs: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub generation: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectReport {
    pub profile: String,
    pub handshake_seen: bool,
    pub kill_switch_armed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TickAction {
    Healthy,
    Repaired,
    Nudged,
    Failed,
    Idle,
}

#[derive(Clone, Debug, Serialize)]
pub struct TickReport {
    pub action: TickAction,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProfileInfo {
    pub name: String,
    pub endpoint: SocketAddr,
    pub server_public_key: String,
    pub kill_switch: &'static str,
    pub interface: String,
}

pub fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.len() <= 32
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

pub fn kill_switch_name(mode: KillSwitchMode) -> &'static str {
    match mode {
        KillSwitchMode::Off => "off",
        KillSwitchMode::VpnOnly => "vpn-only",
        KillSwitchMode::Strict => "strict",
    }
}

/// The single rule for what a set of observed checks means. `Protected` requires every
/// check to have been observed and to have passed; an unobserved check is never a pass.
/// `no_handshake_yet` and `recent` allow a freshly started tunnel to read `Connecting`
/// instead of `Degraded` while its first handshake is still outstanding.
pub fn derive_state(checks: &[Check], no_handshake_yet: bool, recent: bool) -> State {
    let any_fail = checks.iter().any(|c| c.status == CheckStatus::Fail);
    let any_unknown = checks.iter().any(|c| c.status == CheckStatus::Unknown);
    let only_handshake_missing = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Fail)
        .all(|c| c.name == "handshake")
        && no_handshake_yet;
    if any_fail && only_handshake_missing && recent {
        State::Connecting
    } else if any_fail {
        State::Degraded
    } else if any_unknown {
        State::Unknown
    } else {
        State::Protected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(name: &'static str, status: CheckStatus) -> Check {
        Check {
            name,
            status,
            detail: String::new(),
        }
    }

    #[test]
    fn protected_needs_every_check_observed_and_passing() {
        let ok = [c("a", CheckStatus::Ok), c("firewall", CheckStatus::Off)];
        assert_eq!(derive_state(&ok, false, true), State::Protected);
        let unknown = [c("a", CheckStatus::Ok), c("dns", CheckStatus::Unknown)];
        assert_eq!(derive_state(&unknown, false, true), State::Unknown);
        let failed = [c("a", CheckStatus::Fail), c("dns", CheckStatus::Unknown)];
        assert_eq!(derive_state(&failed, false, true), State::Degraded);
    }

    #[test]
    fn a_missing_first_handshake_reads_connecting_only_while_fresh() {
        let waiting = [c("handshake", CheckStatus::Fail), c("dns", CheckStatus::Ok)];
        assert_eq!(derive_state(&waiting, true, true), State::Connecting);
        assert_eq!(derive_state(&waiting, true, false), State::Degraded);
        let also_broken = [
            c("handshake", CheckStatus::Fail),
            c("dns", CheckStatus::Fail),
        ];
        assert_eq!(derive_state(&also_broken, true, true), State::Degraded);
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        fn status() -> impl Strategy<Value = CheckStatus> {
            prop_oneof![
                Just(CheckStatus::Ok),
                Just(CheckStatus::Fail),
                Just(CheckStatus::Unknown),
                Just(CheckStatus::Off),
            ]
        }

        fn checks() -> impl Strategy<Value = Vec<Check>> {
            proptest::collection::vec(
                (
                    prop_oneof![
                        Just("handshake"),
                        Just("dns"),
                        Just("ipv6"),
                        Just("firewall")
                    ],
                    status(),
                )
                    .prop_map(|(name, status)| c(name, status)),
                0..8,
            )
        }

        proptest! {
            /// `Protected` is only ever the answer when nothing failed and nothing was unobserved.
            #[test]
            fn protected_implies_every_check_ok_or_off(
                checks in checks(), fresh in any::<bool>(), recent in any::<bool>()
            ) {
                if derive_state(&checks, fresh, recent) == State::Protected {
                    prop_assert!(checks.iter().all(|c| matches!(c.status, CheckStatus::Ok | CheckStatus::Off)));
                }
            }

            /// Making any one check worse never makes the state read better.
            #[test]
            fn degrading_a_check_never_improves_the_state(
                mut checks in checks(), index in any::<prop::sample::Index>(),
                fresh in any::<bool>(), recent in any::<bool>()
            ) {
                prop_assume!(!checks.is_empty());
                let rank = |s: State| match s {
                    State::Protected => 0,
                    State::Connecting => 1,
                    State::Unknown => 2,
                    _ => 3,
                };
                let before = derive_state(&checks, fresh, recent);
                let at = index.index(checks.len());
                if checks[at].name != "handshake" {
                    checks[at].status = CheckStatus::Fail;
                    prop_assert!(rank(derive_state(&checks, fresh, recent)) >= rank(before));
                }
            }
        }
    }
}
