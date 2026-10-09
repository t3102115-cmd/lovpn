//! Failure budgets for the enrollment listener. Pure logic plus a small JSON codec;
//! the listener persists it (`enroll-limits.json`) so a restart does not reset a
//! brute-force attacker's budget.
//!
//! A *source* is an IPv4 address or an IPv6 /64. Each source has a failure budget per
//! window; exceeding it blocks the source with exponential back-off (30 s doubling to
//! 1 h). A global budget, counting only refused tokens, bounds distributed guessing. Checks run **before** the TLS
//! handshake and before any body is read. Time never goes backwards here: if the clock
//! does, the last seen time is used, so blocks are not shortened.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr};

pub const WINDOW_SECS: u64 = 15 * 60;
pub const SOURCE_BUDGET: u32 = 5;
pub const GLOBAL_BUDGET: u32 = 60;
pub const BASE_BLOCK_SECS: u64 = 30;
pub const MAX_BLOCK_SECS: u64 = 60 * 60;
pub const MAX_SOURCES: usize = 1024;
pub const MAX_LIMITS_BYTES: u64 = 256 * 1024;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bucket {
    failures: u32,
    window_start: u64,
    blocked_until: u64,
    strikes: u32,
}

impl Bucket {
    fn roll(&mut self, now: u64) {
        if now.saturating_sub(self.window_start) >= WINDOW_SECS {
            self.failures = 0;
            self.window_start = now;
            // Strikes decay only after a full quiet window.
            if now >= self.blocked_until {
                self.strikes = self.strikes.saturating_sub(1);
            }
        }
    }

    fn record(&mut self, now: u64, budget: u32) {
        if self.window_start == 0 {
            self.window_start = now;
        }
        self.roll(now);
        self.failures = self.failures.saturating_add(1);
        if self.failures >= budget {
            let shift = self.strikes.min(7);
            let block = (BASE_BLOCK_SECS << shift).min(MAX_BLOCK_SECS);
            self.blocked_until = now.saturating_add(block);
            self.strikes = self.strikes.saturating_add(1);
            self.failures = 0;
            self.window_start = now;
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    last_unix: u64,
    global: Bucket,
    sources: BTreeMap<String, Bucket>,
}

/// Stable key for a source address (IPv6 collapses to its /64).
pub fn source_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.to_string();
            }
            let o = v6.octets();
            format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::/64",
                o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]
            )
        }
    }
}

impl Limits {
    pub fn from_json(bytes: &[u8]) -> Option<Self> {
        if bytes.len() as u64 > MAX_LIMITS_BYTES {
            return None;
        }
        let limits: Self = serde_json::from_slice(bytes).ok()?;
        (limits.sources.len() <= MAX_SOURCES).then_some(limits)
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    fn clock(&mut self, now: u64) -> u64 {
        self.last_unix = self.last_unix.max(now);
        self.last_unix
    }

    /// `Err(seconds)` when the source (or everyone) is blocked.
    pub fn check(&mut self, source: &str, now: u64) -> Result<(), u64> {
        let now = self.clock(now);
        let mut wait = 0;
        if self.global.blocked_until > now {
            wait = self.global.blocked_until - now;
        }
        if let Some(bucket) = self.sources.get(source)
            && bucket.blocked_until > now
        {
            wait = wait.max(bucket.blocked_until - now);
        }
        if wait == 0 { Ok(()) } else { Err(wait) }
    }

    /// Record a failed attempt against its source. `guessed_token` is true only when a token
    /// was actually presented and refused: only those count against the global budget, which
    /// exists to bound distributed token guessing. Handshake failures and malformed requests
    /// cost an attacker nothing to produce from one address, so letting them fill the global
    /// bucket would let a single source block everyone (review F-05).
    pub fn failure(&mut self, source: &str, now: u64, guessed_token: bool) {
        let now = self.clock(now);
        if guessed_token {
            self.global.record(now, GLOBAL_BUDGET);
        }
        if !self.sources.contains_key(source) && self.sources.len() >= MAX_SOURCES {
            // Evict the least harmful entry: not blocked, oldest window.
            let victim = self
                .sources
                .iter()
                .filter(|(_, b)| b.blocked_until <= now)
                .min_by_key(|(_, b)| b.window_start)
                .map(|(k, _)| k.clone());
            if let Some(key) = victim {
                self.sources.remove(&key);
            } else {
                // Everyone is blocked: count only against the global budget.
                return;
            }
        }
        self.sources
            .entry(source.to_string())
            .or_default()
            .record(now, SOURCE_BUDGET);
    }

    /// A successful enrollment clears that source's counters (not the global ones).
    pub fn success(&mut self, source: &str, now: u64) {
        self.clock(now);
        self.sources.remove(source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_blocks_after_budget_with_backoff() {
        let mut limits = Limits::default();
        let now = 1_000_000;
        for _ in 0..SOURCE_BUDGET {
            assert!(limits.check("a", now).is_ok());
            limits.failure("a", now, true);
        }
        assert_eq!(limits.check("a", now), Err(BASE_BLOCK_SECS));
        assert!(
            limits.check("b", now).is_ok(),
            "other sources are unaffected"
        );
        // After the block expires another burst blocks for twice as long.
        let later = now + BASE_BLOCK_SECS;
        assert!(limits.check("a", later).is_ok());
        for _ in 0..SOURCE_BUDGET {
            limits.failure("a", later, true);
        }
        assert_eq!(limits.check("a", later), Err(BASE_BLOCK_SECS * 2));
    }

    #[test]
    fn global_budget_blocks_everyone() {
        let mut limits = Limits::default();
        let now = 5_000_000;
        for i in 0..GLOBAL_BUDGET {
            limits.failure(&format!("src{i}"), now, true);
        }
        assert!(limits.check("brand-new", now).is_err());
    }

    #[test]
    fn one_source_without_guesses_cannot_block_everyone() {
        let mut limits = Limits::default();
        let now = 5_000_000;
        for i in 0..(GLOBAL_BUDGET * 3) {
            limits.failure(&format!("src{i}"), now, false);
        }
        assert!(limits.check("brand-new", now).is_ok());
    }

    #[test]
    fn clock_going_backwards_never_shortens_a_block() {
        let mut limits = Limits::default();
        for _ in 0..SOURCE_BUDGET {
            limits.failure("a", 10_000, true);
        }
        assert!(limits.check("a", 5_000).is_err());
    }

    #[test]
    fn survives_serialization_and_rejects_garbage() {
        let mut limits = Limits::default();
        for _ in 0..SOURCE_BUDGET {
            limits.failure("a", 10_000, true);
        }
        let again = Limits::from_json(&limits.to_json());
        assert!(again.is_some_and(|mut l| l.check("a", 10_000).is_err()));
        assert!(Limits::from_json(b"{\"junk\":1}").is_none());
        assert!(Limits::from_json(b"\xff").is_none());
    }

    #[test]
    fn success_clears_only_the_source() {
        let mut limits = Limits::default();
        limits.failure("a", 100, true);
        limits.success("a", 101);
        for _ in 0..SOURCE_BUDGET - 1 {
            limits.failure("a", 102, true);
        }
        assert!(limits.check("a", 102).is_ok());
    }

    #[test]
    fn ipv6_sources_collapse_to_a_64() {
        let a: IpAddr = "2001:db8:1:2:3:4:5:6"
            .parse()
            .unwrap_or_else(|_| unreachable!());
        let b: IpAddr = "2001:db8:1:2:ffff::1"
            .parse()
            .unwrap_or_else(|_| unreachable!());
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap_or_else(|_| unreachable!());
        assert_eq!(source_key(a), source_key(b));
        assert_ne!(source_key(a), source_key(c));
    }
}
