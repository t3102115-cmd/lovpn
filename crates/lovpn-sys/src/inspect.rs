//! Pure parsers for the read-only observations both brokers make. No I/O.
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableState {
    Absent,
    Foreign,
    Owned { generation: Option<u64> },
}

/// Classify `nft list table` output against an ownership comment prefix such as
/// `lovpn-owned` (optionally followed by ` gen=<N>`). Anything else is foreign.
pub fn classify_table(success: bool, listing: &str, owner: &str) -> TableState {
    if !success {
        return TableState::Absent;
    }
    for line in listing.lines() {
        let line = line.trim();
        let text = line
            .strip_prefix("comment \"")
            .and_then(|rest| rest.strip_suffix('"'));
        if let Some(text) = text
            && (text == owner || text.starts_with(&format!("{owner} ")))
        {
            let generation = text
                .split_whitespace()
                .find_map(|word| word.strip_prefix("gen="))
                .and_then(|value| value.parse().ok());
            return TableState::Owned { generation };
        }
    }
    TableState::Foreign
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct LinkObservation {
    pub present: bool,
    pub wireguard: bool,
    pub mtu: Option<u32>,
    pub up: bool,
}

/// Parse `ip -j -d link show dev X`.
pub fn parse_link(success: bool, json: &str) -> LinkObservation {
    if !success {
        return LinkObservation::default();
    }
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(json) else {
        return LinkObservation::default();
    };
    let Some(link) = items.first() else {
        return LinkObservation::default();
    };
    LinkObservation {
        present: true,
        wireguard: link["linkinfo"]["info_kind"] == "wireguard",
        mtu: link["mtu"].as_u64().and_then(|v| u32::try_from(v).ok()),
        up: link["flags"]
            .as_array()
            .is_some_and(|flags| flags.iter().any(|f| f == "UP")),
    }
}

/// `(local address, prefix length)` pairs of the given family (`inet`/`inet6`).
pub fn parse_addresses_of(json: &str, family: &str) -> Vec<(String, u64)> {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    items
        .iter()
        .flat_map(|link| link["addr_info"].as_array().cloned().unwrap_or_default())
        .filter(|a| a["family"] == family)
        .filter_map(|a| Some((a["local"].as_str()?.to_string(), a["prefixlen"].as_u64()?)))
        .collect()
}

/// IPv4 addresses of a link.
pub fn parse_addresses(json: &str) -> Vec<(String, u64)> {
    parse_addresses_of(json, "inet")
}

/// A policy-routing rule as printed by `ip -j rule show`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rule {
    pub priority: u64,
    pub negated_fwmark: Option<String>,
    pub table: Option<String>,
    pub action: Option<String>,
}

pub fn parse_rules(json: &str) -> Vec<Rule> {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|rule| {
            Some(Rule {
                priority: rule["priority"].as_u64()?,
                negated_fwmark: rule
                    .get("not")
                    .filter(|_| rule.get("fwmark").is_some())
                    .and(rule["fwmark"].as_str())
                    .map(String::from),
                table: rule["table"].as_str().map(String::from),
                action: rule["action"].as_str().map(String::from),
            })
        })
        .collect()
}

/// `(destination, device)` pairs from `ip -j route show table N`.
pub fn parse_routes(json: &str) -> Vec<(String, String)> {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|r| {
            Some((
                r["dst"].as_str()?.to_string(),
                r["dev"].as_str()?.to_string(),
            ))
        })
        .collect()
}

/// The device a successful `ip -j route get` resolved to.
pub fn parse_route_get(success: bool, json: &str) -> Option<String> {
    if !success {
        return None;
    }
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(json) else {
        return None;
    };
    items.first()?["dev"].as_str().map(String::from)
}
