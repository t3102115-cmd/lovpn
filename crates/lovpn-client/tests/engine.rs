#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(target_os = "linux")]
mod common;

use common::{Lab, MARK, TABLE, profile_text};
use lovpn_client::{
    ClientError,
    dns::Kind,
    engine::{CheckStatus, State, TickAction},
    record::{Desired, RecordStore},
};

fn checks(status: &lovpn_client::engine::Status) -> Vec<(&'static str, CheckStatus)> {
    status.checks.iter().map(|c| (c.name, c.status)).collect()
}

fn connected(mode: &str) -> Lab {
    let mut lab = Lab::new();
    lab.import("home", mode);
    lab.engine.connect(Some("home")).unwrap();
    let now = lab.now();
    lab.fake.host().handshake_ts = now - 5;
    lab
}

// ---------------------------------------------------------------- ordering ----

#[test]
fn kill_switch_is_installed_before_the_tunnel_exists_and_the_key_stays_on_stdin() {
    let mut lab = Lab::new();
    lab.import("home", "strict");
    lab.engine.connect(Some("home")).unwrap();
    let host = lab.fake.host();
    let position = |needle: &str| {
        host.log
            .iter()
            .position(|l| l.contains(needle))
            .unwrap_or(usize::MAX)
    };
    assert!(
        position("nft -f -") < position("link add"),
        "firewall must precede the interface"
    );
    assert!(position("link add") < position("syncconf"));
    assert!(position("syncconf") < position("route replace"));
    assert!(position("route replace") < position("rule add"));
    assert!(position("rule add") < position("resolvectl dns lovpn0 10.66.0.1"));
    assert_eq!(host.wg_fwmark.as_deref(), Some(MARK));
    let secret = &lab.client_private;
    assert!(
        host.log.iter().all(|l| !l.contains(secret.as_str())),
        "private key reached a command line"
    );
    assert_eq!(
        host.stdin_seen
            .iter()
            .filter(|s| s.contains(secret.as_str()))
            .count(),
        1
    );
    assert_eq!(
        host.tables.get("inet lovpn_client").map(String::as_str),
        Some("lovpn-owned gen=1")
    );
    // IPv4 rules and the IPv6 block exist.
    assert_eq!(host.rules4.len(), 2);
    assert_eq!(host.rules6.len(), 1);
    assert!(host.dns["lovpn0"].1 == ["~."] && host.dns["lovpn0"].2);
}

#[test]
fn connect_is_idempotent_and_rewrites_nothing_when_already_correct() {
    let mut lab = connected("strict");
    lab.fake.clear_log();
    lab.engine.connect(Some("home")).unwrap();
    let mutating = lab.fake.mutating();
    assert!(
        !mutating
            .iter()
            .any(|l| l.contains("link add") || l.contains("rule add") || l.contains("nft -f")),
        "{mutating:?}"
    );
}

// ----------------------------------------------------------------- observe ----

#[test]
fn protected_requires_every_check_to_be_observed_ok() {
    let lab = connected("strict");
    let status = lab.engine.observe();
    assert_eq!(status.state, State::Protected, "{:?}", status.reasons);
    assert!(
        status.checks.iter().all(|c| c.status == CheckStatus::Ok),
        "{:?}",
        checks(&status)
    );
    assert_eq!(status.rx_bytes, 1234);
    assert_eq!(status.handshake_age_secs, Some(5));
    assert_eq!(status.checks.len(), 7);
}

#[test]
fn a_handshake_alone_never_means_protected() {
    let mut lab = connected("strict");
    // Handshake is fresh but the kill switch table vanished.
    lab.fake.host().tables.clear();
    assert_eq!(lab.engine.observe().state, State::Degraded);
    lab.engine.repair().unwrap();
    assert_eq!(lab.engine.observe().state, State::Protected);
    // Fresh handshake but DNS not on the tunnel link.
    lab.fake.host().dns.clear();
    let status = lab.engine.observe();
    assert_eq!(status.state, State::Degraded);
    assert!(status.reasons.contains(&"dns".to_string()));
    // Fresh handshake but the IPv6 block rule is gone and IPv6 can route.
    lab.engine.repair().unwrap();
    lab.fake.host().rules6.clear();
    let status = lab.engine.observe();
    assert_eq!(status.state, State::Degraded);
    assert!(status.reasons.contains(&"ipv6".to_string()));
}

#[test]
fn stale_or_missing_observations_are_degraded_or_unknown_never_protected() {
    let lab = connected("strict");
    let now = lab.now();
    lab.fake.host().handshake_ts = now - 500;
    let status = lab.engine.observe();
    assert_eq!(status.state, State::Degraded);
    assert!(status.reasons.contains(&"handshake".to_string()));
    lab.fake.host().handshake_ts = now - 5;
    assert_eq!(lab.engine.observe().state, State::Protected);
    // An observation that cannot be made yields unknown, not protected.
    lab.fake.host().blind_step = Some("inspect-firewall");
    let status = lab.engine.observe();
    assert_eq!(status.state, State::Unknown);
    assert!(status.reasons.contains(&"firewall-unknown".to_string()));
    lab.fake.host().blind_step = None;
    // Server unreachable through the uplink: endpoint check fails.
    lab.fake.host().uplink_up = false;
    let status = lab.engine.observe();
    assert_eq!(status.state, State::Degraded);
    assert!(status.reasons.contains(&"endpoint-route".to_string()));
}

#[test]
fn unmanaged_dns_is_reported_as_unprotected_never_protected() {
    let mut lab = Lab::with_dns(Kind::Unmanaged);
    lab.import("home", "strict");
    lab.engine.connect(Some("home")).unwrap();
    let now = lab.now();
    lab.fake.host().handshake_ts = now - 1;
    let status = lab.engine.observe();
    assert_eq!(status.state, State::Degraded);
    assert_eq!(status.reasons, vec!["dns-unmanaged".to_string()]);
    assert!(
        lab.fake.host().dns.is_empty(),
        "unmanaged DNS must not touch the resolver"
    );
    assert!(
        !lab.fake
            .host()
            .log
            .iter()
            .any(|l| l.starts_with("resolvectl"))
    );
}

#[test]
fn refuses_to_connect_when_the_resolver_cannot_be_managed() {
    let mut lab = Lab::new();
    lab.import("home", "strict");
    lab.fake.host().resolved_ok = false;
    assert_eq!(
        lab.engine.connect(Some("home")).err(),
        Some(ClientError::DnsUnsupported)
    );
    assert!(lab.fake.mutating().is_empty(), "{:?}", lab.fake.mutating());
    assert_eq!(lab.engine.observe().state, State::Disconnected);
}

// ------------------------------------------------------------- kill switch ----

#[test]
fn disconnect_semantics_differ_by_kill_switch_mode() {
    // strict: stays blocked until released.
    let mut lab = connected("strict");
    lab.engine.disconnect(false).unwrap();
    let host = lab.fake.host();
    assert!(
        host.link.is_none()
            && host.rules4.is_empty()
            && host.rules6.is_empty()
            && host.dns.is_empty()
    );
    assert!(
        host.tables.contains_key("inet lovpn_client"),
        "strict keeps the firewall"
    );
    drop(host);
    assert_eq!(lab.engine.observe().state, State::Blocked);
    lab.engine.disconnect(true).unwrap();
    assert!(lab.fake.host().tables.is_empty());
    assert_eq!(lab.engine.observe().state, State::Disconnected);

    // vpn-only: a normal disconnect restores networking.
    let mut lab = connected("vpn-only");
    lab.engine.disconnect(false).unwrap();
    assert!(lab.fake.host().tables.is_empty());
    assert_eq!(lab.engine.observe().state, State::Disconnected);

    // off: never installs a firewall, but routing still fails closed while connected.
    let mut lab = Lab::new();
    lab.import("home", "off");
    lab.engine.connect(Some("home")).unwrap();
    assert!(lab.fake.host().tables.is_empty());
    assert_eq!(lab.fake.host().rules4.len(), 2);
    let now = lab.now();
    lab.fake.host().handshake_ts = now - 1;
    let status = lab.engine.observe();
    assert_eq!(status.state, State::Protected);
    assert_eq!(
        checks(&status)
            .iter()
            .find(|c| c.0 == "firewall")
            .unwrap()
            .1,
        CheckStatus::Off
    );
}

#[test]
fn losing_the_interface_never_leaks_at_the_routing_level() {
    let lab = connected("off");
    // Simulate the VPN interface vanishing (crash) with no firewall at all.
    {
        let mut h = lab.fake.host();
        h.link = None;
        h.tunnel_default = false;
    }
    assert_eq!(
        lab.fake.host().rules4.len(),
        2,
        "rules stay, so unmarked traffic is unreachable"
    );
    let status = lab.engine.observe();
    assert_eq!(status.state, State::Degraded);
    let ipv4 = status.checks.iter().find(|c| c.name == "ipv4").unwrap();
    assert_eq!(ipv4.status, CheckStatus::Fail);
    assert!(ipv4.detail.contains("no route"), "{}", ipv4.detail);
}

#[test]
fn disconnect_refuses_to_delete_foreign_routes_and_keeps_recovery_desired() {
    let mut lab = connected("vpn-only");
    lab.fake.host().foreign_route = true;
    assert_eq!(
        lab.engine.disconnect(true).err(),
        Some(ClientError::ForeignRoute)
    );
    assert_eq!(lab.engine.observe().desired, Desired::Connected);
    assert!(lab.fake.host().link.is_some());
    assert!(lab.fake.host().tunnel_default);
    assert!(lab.fake.host().foreign_route);
}

#[test]
fn reconnect_recreates_only_the_interface() {
    let mut lab = connected("strict");
    lab.fake.clear_log();
    lab.engine.reconnect().unwrap();
    let mutating = lab.fake.mutating();
    assert!(
        mutating.iter().any(|l| l.contains("link del"))
            && mutating.iter().any(|l| l.contains("link add"))
    );
    assert!(
        !mutating
            .iter()
            .any(|l| l.contains("rule del") || l.contains("delete table") || l.contains("revert")),
        "{mutating:?}"
    );
    assert!(lab.fake.host().tables.contains_key("inet lovpn_client"));
}

#[test]
fn failed_connect_is_fail_closed_for_strict_and_not_stranding_for_others() {
    for (mode, expect_firewall) in [("strict", true), ("vpn-only", false), ("off", false)] {
        let mut lab = Lab::new();
        lab.import("home", mode);
        lab.fake.host().fail_step = Some("configure-wireguard");
        let error = lab.engine.connect(Some("home")).err();
        assert_eq!(
            error,
            Some(ClientError::CommandFailed("configure-wireguard")),
            "{mode}"
        );
        lab.fake.host().fail_step = None;
        let host = lab.fake.host();
        assert_eq!(
            host.tables.contains_key("inet lovpn_client"),
            expect_firewall,
            "{mode}"
        );
        assert!(
            host.link.is_none() && host.rules4.is_empty(),
            "{mode}: partial tunnel left behind"
        );
        drop(host);
        let state = lab.engine.observe().state;
        assert_eq!(
            state,
            if expect_firewall {
                State::Blocked
            } else {
                State::Disconnected
            },
            "{mode}"
        );
        // A retry from this state works.
        assert!(lab.engine.connect(Some("home")).is_ok(), "{mode}");
    }
}

// ----------------------------------------------------------------- foreign ----

#[test]
fn foreign_tables_interfaces_and_rules_are_refused_without_any_change() {
    let mut lab = Lab::new();
    lab.import("home", "strict");
    lab.fake
        .host()
        .tables
        .insert("inet lovpn_client".into(), String::new());
    assert_eq!(
        lab.engine.connect(Some("home")).err(),
        Some(ClientError::ForeignTable)
    );
    assert!(lab.fake.mutating().is_empty());
    lab.fake.host().tables.clear();

    lab.fake.host().link = Some((
        "lovpn0".into(),
        common::Link {
            kind: "dummy".into(),
            up: true,
            mtu: 1500,
            addresses: vec![],
        },
    ));
    assert_eq!(
        lab.engine.connect(Some("home")).err(),
        Some(ClientError::ForeignInterface)
    );
    assert!(lab.fake.mutating().is_empty());
    // Same name and WireGuard, but not created by this service.
    lab.fake.host().link.as_mut().unwrap().1.kind = "wireguard".into();
    assert_eq!(
        lab.engine.connect(Some("home")).err(),
        Some(ClientError::ForeignInterface)
    );
    lab.fake.host().link = None;

    lab.fake.host().rules4.push(common::SimRule {
        priority: 9100,
        not_mark: false,
        table: Some("77".into()),
        unreachable: false,
    });
    assert_eq!(
        lab.engine.connect(Some("home")).err(),
        Some(ClientError::ForeignRule)
    );
    assert!(lab.fake.mutating().is_empty());
    // And teardown never deletes someone else's rule.
    lab.engine.reset().unwrap();
    assert_eq!(
        lab.fake.host().rules4.len(),
        1,
        "foreign rule must survive reset"
    );
}

// --------------------------------------------------------------- recovery ----

#[test]
fn monitor_repairs_drift_without_ever_lowering_protection() {
    let mut lab = connected("strict");
    assert_eq!(lab.engine.tick(false).action, TickAction::Healthy);
    lab.fake.clear_log();
    assert!(lab.fake.mutating().is_empty());

    // VPN interface crashed: repaired, and the firewall was never removed.
    {
        let mut h = lab.fake.host();
        h.link = None;
        h.tunnel_default = false;
    }
    let report = lab.engine.tick(false);
    assert_eq!(report.action, TickAction::Repaired, "{report:?}");
    assert!(
        !lab.fake
            .mutating()
            .iter()
            .any(|l| l.contains("delete table") || l.contains("rule del"))
    );
    let now = lab.now();
    lab.fake.host().handshake_ts = now;
    assert_eq!(lab.engine.observe().state, State::Protected);

    // Someone deleted the kill switch: restored.
    lab.fake.host().tables.clear();
    assert_eq!(lab.engine.tick(false).action, TickAction::Repaired);
    assert!(lab.fake.host().tables.contains_key("inet lovpn_client"));
}

#[test]
fn stale_handshake_and_resume_nudge_instead_of_tearing_down() {
    let mut lab = connected("strict");
    let now = lab.now();
    lab.fake.host().handshake_ts = now - 400;
    lab.fake.clear_log();
    let report = lab.engine.tick(false);
    assert_eq!(report.action, TickAction::Nudged);
    assert_eq!(lab.fake.host().nudges, 1);
    assert!(
        lab.fake.mutating().iter().all(|l| l.starts_with("wg set")),
        "{:?}",
        lab.fake.mutating()
    );
    // After suspend/resume with a still-fresh-looking handshake, nudge anyway.
    lab.fake.host().handshake_ts = now;
    assert_eq!(lab.engine.tick(true).action, TickAction::Nudged);
    assert_eq!(lab.engine.tick(false).action, TickAction::Healthy);
}

#[test]
fn strict_kill_switch_is_restored_while_disconnected() {
    let mut lab = connected("strict");
    lab.engine.disconnect(false).unwrap();
    assert_eq!(lab.engine.tick(false).action, TickAction::Healthy);
    lab.fake.host().tables.clear(); // removed behind our back
    assert_eq!(lab.engine.tick(false).action, TickAction::Repaired);
    assert!(lab.fake.host().tables.contains_key("inet lovpn_client"));
    assert_eq!(lab.engine.observe().state, State::Blocked);
    // vpn-only disconnected: nothing to enforce.
    let mut lab = connected("vpn-only");
    lab.engine.disconnect(false).unwrap();
    assert_eq!(lab.engine.tick(false).action, TickAction::Idle);
}

#[test]
fn restart_recovers_from_the_record_after_a_reboot_style_loss_of_kernel_state() {
    let mut lab = connected("strict");
    // Everything the kernel held is gone (reboot): the service restarts from its record.
    {
        let mut h = lab.fake.host();
        h.link = None;
        h.tunnel_default = false;
        h.rules4.clear();
        h.rules6.clear();
        h.tables.clear();
        h.dns.clear();
        h.handshake_ts = 0;
    }
    lab.fake.clear_log();
    let report = lab.engine.recover_on_start();
    assert_eq!(report.action, TickAction::Repaired, "{report:?}");
    let host = lab.fake.host();
    let first_nft = host
        .log
        .iter()
        .position(|l| l.starts_with("nft -f"))
        .unwrap();
    let first_link = host
        .log
        .iter()
        .position(|l| l.contains("link add"))
        .unwrap();
    assert!(
        first_nft < first_link,
        "kill switch must come back before the tunnel"
    );
    assert!(
        host.tables.contains_key("inet lovpn_client")
            && host.link.is_some()
            && host.rules4.len() == 2
    );
    drop(host);
    // Strict + user had disconnected before the reboot: still blocked, not open.
    let mut lab = connected("strict");
    lab.engine.disconnect(false).unwrap();
    lab.fake.host().tables.clear();
    assert_eq!(lab.engine.recover_on_start().action, TickAction::Idle);
    assert!(
        lab.fake.host().tables.contains_key("inet lovpn_client"),
        "strict stays armed across reboot"
    );
}

#[test]
fn reset_restores_normal_networking_even_with_a_corrupt_record() {
    let mut lab = connected("strict");
    std::fs::write(lab.state_dir().join("session.json"), "{ corrupt").unwrap();
    assert_eq!(
        lab.engine.observe().state,
        State::Disconnected,
        "unreadable record claims nothing"
    );
    lab.engine.reset().unwrap();
    let host = lab.fake.host();
    assert!(host.tables.is_empty() && host.rules4.is_empty() && host.rules6.is_empty());
    drop(host);
    assert_eq!(lab.engine.observe().state, State::Disconnected);
    // The interface was not provably ours (record lost), so it is left for the user.
    assert!(lab.fake.host().link.is_some());
}

// ---------------------------------------------------------------- profiles ----

#[test]
fn linux_refuses_scoped_dns_on_import_and_before_connect_mutations() {
    let mut lab = Lab::new();
    let text = profile_text(&lab.server_public, "strict", "").replace(
        "[dns]",
        "[dns]\nscopes = [{ namespace = \".corp.example\", servers = [\"10.66.0.53\"] }]",
    );
    assert_eq!(
        lab.engine
            .import_profile("office", &text, &lab.client_private, &lab.server_public)
            .err(),
        Some(ClientError::UnsupportedOperation)
    );
    assert!(lab.engine.list_profiles().unwrap().is_empty());
    assert!(!lab.state_dir().join("profiles/office.key").exists());
    // An administrator can copy a Windows profile over an existing profile; the
    // connect boundary still rejects it before touching host networking.
    lab.import("home", "strict");
    std::fs::write(lab.state_dir().join("profiles/home.toml"), text).unwrap();
    lab.fake.clear_log();
    assert_eq!(
        lab.engine.connect(Some("home")).err(),
        Some(ClientError::UnsupportedOperation)
    );
    assert!(lab.fake.mutating().is_empty());
}

#[test]
fn import_requires_the_expected_server_key_and_a_supported_profile() {
    let lab = Lab::new();
    let text = profile_text(&lab.server_public, "strict", "");
    let other = lovpn_keys::ServerPrivateKey::generate()
        .unwrap()
        .public_key()
        .to_string();
    assert_eq!(
        lab.engine
            .import_profile("home", &text, &lab.client_private, &other)
            .err(),
        Some(ClientError::ServerKeyMismatch)
    );
    assert!(
        lab.engine.list_profiles().unwrap().is_empty(),
        "a mismatching profile must not be kept"
    );
    for bad in ["Home", "", "-x", "a b", "../x", &"n".repeat(33)] {
        assert_eq!(
            lab.engine
                .import_profile(bad, &text, &lab.client_private, &lab.server_public)
                .err(),
            Some(ClientError::ProfileName),
            "{bad:?}"
        );
    }
    // Unclamped / malformed private keys are refused, and never echoed in errors.
    let error = lab
        .engine
        .import_profile("home", &text, "AAAA", &lab.server_public)
        .err();
    assert_eq!(error, Some(ClientError::KeyInvalid));
    // IPv6-tunnel and split profiles are refused rather than half-supported.
    let v6 = text
        .replace("ipv6 = \"block\"", "ipv6 = \"tunnel\"")
        .replace("[\"10.66.0.2/32\"]", "[\"10.66.0.2/32\", \"fd66::2/128\"]")
        .replace("[\"0.0.0.0/0\"]", "[\"0.0.0.0/0\", \"::/0\"]");
    assert_eq!(
        lab.engine
            .import_profile("v6", &v6, &lab.client_private, &lab.server_public)
            .err(),
        Some(ClientError::UnsupportedIpv6Tunnel)
    );
    let split = text
        .replace("routing = \"full\"", "routing = \"split\"")
        .replace("[\"0.0.0.0/0\"]", "[\"10.66.0.0/24\"]");
    assert_eq!(
        lab.engine
            .import_profile("split", &split, &lab.client_private, &lab.server_public)
            .err(),
        Some(ClientError::UnsupportedRouting)
    );
    // Valid import, then duplicates are refused.
    lab.engine
        .import_profile("home", &text, &lab.client_private, &lab.server_public)
        .unwrap();
    assert_eq!(
        lab.engine
            .import_profile("home", &text, &lab.client_private, &lab.server_public)
            .err(),
        Some(ClientError::ProfileExists)
    );
}

#[test]
fn stored_profiles_are_private_and_the_key_is_never_listed() {
    use std::os::unix::fs::PermissionsExt;
    let mut lab = Lab::new();
    lab.import("home", "strict");
    let dir = lab.state_dir().join("profiles");
    for file in ["home.toml", "home.key"] {
        let mode = std::fs::metadata(dir.join(file))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{file}");
    }
    let listing = serde_json::to_string(&lab.engine.list_profiles().unwrap()).unwrap();
    assert!(!listing.contains(&lab.client_private));
    // Tampering with permissions makes the profile unusable instead of silently trusted.
    std::fs::set_permissions(dir.join("home.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(lab.engine.connect(Some("home")).is_err());
    assert!(lab.fake.mutating().is_empty());
    // A profile in use cannot be removed.
    std::fs::set_permissions(dir.join("home.key"), std::fs::Permissions::from_mode(0o600)).unwrap();
    lab.engine.connect(Some("home")).unwrap();
    assert!(lab.engine.remove_profile("home").is_err());
    lab.engine.disconnect(true).unwrap();
    lab.engine.remove_profile("home").unwrap();
    assert!(!dir.join("home.key").exists());
}

#[test]
fn session_record_refuses_links_and_group_readable_files() {
    use std::os::unix::fs::PermissionsExt;

    let lab = Lab::new();
    let path = lab.state_dir().join("session.json");
    let target = lab.state_dir().join("record-target");
    std::fs::write(&target, r#"{"schema_version":1}"#).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let store = RecordStore::open(&lab.state_dir()).unwrap();
    assert!(
        store.load().is_err(),
        "session records must not follow symlinks"
    );

    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, r#"{"schema_version":1}"#).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.load().is_err(), "session records must stay private");
}

#[test]
fn switching_profiles_keeps_the_firewall_and_reinstalls_it_for_the_new_endpoint() {
    let mut lab = Lab::new();
    lab.import("one", "strict");
    let second = profile_text(&lab.server_public, "strict", "")
        .replace("192.0.2.1:51820", "192.0.2.9:51820");
    lab.engine
        .import_profile("two", &second, &lab.client_private, &lab.server_public)
        .unwrap();
    lab.engine.connect(Some("one")).unwrap();
    lab.fake.clear_log();
    lab.engine.connect(Some("two")).unwrap();
    let host = lab.fake.host();
    assert!(
        !host
            .log
            .iter()
            .any(|l| l.contains("delete table inet lovpn_client")),
        "firewall must be replaced atomically, not removed"
    );
    assert!(host.log.iter().filter(|l| l.starts_with("nft -f")).count() >= 1);
    assert_eq!(host.tables["inet lovpn_client"], "lovpn-owned gen=2");
    drop(host);
    assert!(lab.engine.observe().profile.as_deref() == Some("two"));
    let _ = (TABLE, Desired::Connected);
}

#[test]
fn use_profile_selects_without_touching_the_network_and_refuses_while_connected() {
    let mut lab = Lab::new();
    lab.import("home", "strict");
    lab.import("work", "vpn-only");
    assert!(lab.engine.use_profile("nope").is_err());
    lab.engine.use_profile("work").unwrap();
    assert_eq!(
        lab.engine.selected_profile().unwrap().as_deref(),
        Some("work")
    );
    assert!(lab.fake.mutating().is_empty());
    lab.engine.connect(None).unwrap();
    assert!(lab.engine.use_profile("home").is_err());
    assert_eq!(
        lab.engine.selected_profile().unwrap().as_deref(),
        Some("work")
    );
}
