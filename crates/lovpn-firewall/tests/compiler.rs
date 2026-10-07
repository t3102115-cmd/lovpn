#![allow(clippy::unwrap_used)]

use lovpn_config::{Ipv6Mode, KillSwitchMode, RoutingMode, parse};
use lovpn_firewall::{
    FirewallError, OWNER_COMMENT, TABLE_NAME, WIREGUARD_FWMARK, compile, compile_owned,
};

const SAMPLE: &str = include_str!("../../../examples/client.toml");

#[test]
fn owned_policy_replaces_only_its_table_and_stamps_exact_generation() {
    let config = parse(SAMPLE).unwrap();
    for generation in [0, 1, 42, u64::MAX] {
        let plan = compile_owned(&config, generation).unwrap();
        assert_eq!(
            plan.ruleset(),
            compile_owned(&config, generation).unwrap().ruleset()
        );
        let statements: Vec<_> = plan
            .ruleset()
            .lines()
            .filter(|line| !line.starts_with('#'))
            .collect();
        assert_eq!(statements[0], format!("add table inet {TABLE_NAME}"));
        assert_eq!(statements[1], format!("delete table inet {TABLE_NAME}"));
        assert_eq!(
            statements[2],
            format!(
                "add table inet {TABLE_NAME} {{ comment \"{OWNER_COMMENT} gen={generation}\"; }}"
            )
        );
        assert_eq!(plan.ruleset().matches("comment \"").count(), 1);
        assert!(
            statements
                .iter()
                .all(|line| line.contains(&format!("inet {TABLE_NAME}")))
        );
        assert!(!plan.ruleset().contains("flush ruleset"));
        let preview = compile(&config).unwrap();
        // Installation metadata cannot broaden the preview's packet policy.
        assert_eq!(
            plan.ruleset()
                .lines()
                .filter(|line| line.starts_with("add rule"))
                .collect::<Vec<_>>(),
            preview
                .ruleset()
                .lines()
                .filter(|line| line.starts_with("add rule"))
                .collect::<Vec<_>>()
        );
        assert_eq!(plan.reset_ruleset(), preview.reset_ruleset());
    }
}

#[test]
fn dhcp_exception_is_ipv4_client_only_with_default_drop_retained() {
    for ipv6 in [Ipv6Mode::Block, Ipv6Mode::Tunnel] {
        let mut config = parse(SAMPLE).unwrap();
        config.tunnel.ipv6 = ipv6;
        if ipv6 == Ipv6Mode::Tunnel {
            config.tunnel.addresses.push("fd66::2/128".parse().unwrap());
            config.tunnel.routes.push("::/0".parse().unwrap());
        }
        for plan in [
            compile(&config).unwrap(),
            compile_owned(&config, 7).unwrap(),
        ] {
            let dhcp: Vec<_> = plan
                .ruleset()
                .lines()
                .filter(|line| line.starts_with("add rule") && line.contains("udp sport"))
                .collect();
            assert_eq!(
                dhcp,
                [format!(
                    "add rule inet {TABLE_NAME} output meta nfproto ipv4 udp sport 68 udp dport 67 counter accept"
                )]
            );
            assert_eq!(plan.ruleset().matches("policy drop;").count(), 2);
            assert!(!plan.ruleset().contains("udp dport 546"));
            assert!(!plan.ruleset().contains("udp dport 547"));
            assert!(!plan.ruleset().contains("icmpv6"));
            assert!(!plan.ruleset().contains("ip daddr 192.168."));
        }
    }
}

#[test]
fn owned_policy_revalidates_and_refuses_unsupported_modes() {
    let mut config = parse(SAMPLE).unwrap();
    config.firewall.kill_switch = KillSwitchMode::Off;
    assert_eq!(
        compile_owned(&config, 1).err(),
        Some(FirewallError::Disabled)
    );
    config.firewall.kill_switch = KillSwitchMode::Strict;
    config.profile.endpoint = "[2001:db8::1]:51820".parse().unwrap();
    assert_eq!(
        compile_owned(&config, 1).err(),
        Some(FirewallError::Ipv6UnderlayUnsupported)
    );
    config.profile.endpoint = "192.0.2.1:51820".parse().unwrap();
    config.tunnel.interface = "x\"; flush ruleset".into();
    assert_eq!(
        compile_owned(&config, 1).err(),
        Some(FirewallError::InvalidConfig)
    );
}

#[test]
fn policy_is_deterministic_scoped_and_has_no_existing_flow_bypass() {
    let config = parse(SAMPLE).unwrap();
    let first = compile(&config).unwrap();
    assert_eq!(first.ruleset(), compile(&config).unwrap().ruleset());
    let rules = first.ruleset();
    assert!(rules.contains("policy drop"));
    assert!(rules.contains("hook forward"));
    assert!(rules.contains(&format!(
        "meta mark {WIREGUARD_FWMARK:#x} ip daddr 192.0.2.1 udp dport 51820"
    )));
    assert!(!rules.contains("ct state"));
    assert!(!rules.contains("established"));
    assert!(!rules.contains("udp dport 53 "));
    assert!(!rules.contains("flush ruleset"));
    assert!(!rules.contains("hook input"));
    assert!(!rules.contains("My Home Server"));
    for line in rules.lines().filter(|line| !line.starts_with('#')) {
        assert!(line.contains(&format!("inet {TABLE_NAME}")));
    }
    let reset: Vec<_> = first
        .reset_ruleset()
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert_eq!(reset, ["delete table inet lovpn_client"]);
}

#[test]
fn ipv6_block_precedes_tunnel_acceptance() {
    let rules = compile(&parse(SAMPLE).unwrap()).unwrap();
    assert!(
        rules.ruleset().find("nfproto ipv6 counter drop").unwrap()
            < rules.ruleset().find("oifname \"lovpn0\"").unwrap()
    );
}

#[test]
fn tunnel_ipv6_has_no_block_and_still_requires_exact_ipv4_endpoint() {
    let mut config = parse(SAMPLE).unwrap();
    config.tunnel.ipv6 = Ipv6Mode::Tunnel;
    config.tunnel.addresses.push("fd66::2/128".parse().unwrap());
    config.tunnel.routes.push("::/0".parse().unwrap());
    let rules = compile(&config).unwrap();
    assert!(!rules.ruleset().contains("nfproto ipv6 counter drop"));
    assert!(
        rules
            .ruleset()
            .contains("ip daddr 192.0.2.1 udp dport 51820")
    );
}

#[test]
fn refuses_off_split_and_ipv6_underlay() {
    let mut config = parse(SAMPLE).unwrap();
    config.firewall.kill_switch = KillSwitchMode::Off;
    assert_eq!(compile(&config).err(), Some(FirewallError::Disabled));
    config.firewall.kill_switch = KillSwitchMode::VpnOnly;
    assert!(compile(&config).is_ok());
    config.tunnel.routing = RoutingMode::Split;
    config.tunnel.routes = vec!["10.66.0.0/24".parse().unwrap()];
    assert_eq!(
        compile(&config).err(),
        Some(FirewallError::SplitUnsupported)
    );
    config.tunnel.routing = RoutingMode::Full;
    config.tunnel.routes = vec!["0.0.0.0/0".parse().unwrap()];
    config.profile.endpoint = "[2001:db8::1]:51820".parse().unwrap();
    assert_eq!(
        compile(&config).err(),
        Some(FirewallError::Ipv6UnderlayUnsupported)
    );
}

#[test]
fn mutation_requires_revalidation_and_cannot_inject_rules() {
    let mut config = parse(SAMPLE).unwrap();
    config.tunnel.interface = "lovpn0\"; flush ruleset".into();
    assert_eq!(compile(&config).err(), Some(FirewallError::InvalidConfig));
}

#[test]
fn profile_name_and_public_key_never_appear_in_plan() {
    let config = parse(SAMPLE).unwrap();
    let plan = compile(&config).unwrap();
    assert!(!plan.ruleset().contains(&config.profile.name));
    assert!(!plan.ruleset().contains(&config.profile.server_public_key));
}

mod server_policy {
    use lovpn_firewall::server::{ServerFirewallError, ServerPolicy, compile};

    fn policy() -> ServerPolicy {
        ServerPolicy {
            interface: "lovpn-srv0".into(),
            wan_interface: "eth0".into(),
            pool: "10.66.0.0/24".parse().unwrap_or_else(|_| unreachable!()),
            leases: vec![
                "10.66.0.3".parse().unwrap_or_else(|_| unreachable!()),
                "10.66.0.2".parse().unwrap_or_else(|_| unreachable!()),
            ],
            generation: 7,
        }
    }

    #[test]
    fn deterministic_owned_tables_only_and_no_host_policy_changes() {
        let first = compile(&policy()).unwrap_or_else(|_| unreachable!());
        let second = compile(&policy()).unwrap_or_else(|_| unreachable!());
        assert_eq!(first.ruleset(), second.ruleset());
        let rules = first.ruleset();
        assert!(rules.contains("ip saddr != { 10.66.0.2, 10.66.0.3 }"));
        assert!(rules.contains("masquerade"));
        assert!(!rules.contains("policy drop"), "must not drop host traffic");
        assert!(!rules.contains("flush ruleset"));
        assert!(rules.contains("comment \"lovpn-owned gen=7\""));
        for line in rules.lines().filter(|l| !l.starts_with('#')) {
            assert!(
                line.contains("lovpn_server"),
                "every statement must name a LoVPN-owned table: {line}"
            );
        }
        let reset = first.reset_ruleset();
        assert_eq!(reset.lines().filter(|l| l.starts_with("delete")).count(), 2);
        assert!(!reset.contains("flush"));
    }

    #[test]
    fn no_leases_drops_all_peer_forwarding() {
        let mut empty = policy();
        empty.leases.clear();
        let plan = compile(&empty).unwrap_or_else(|_| unreachable!());
        assert!(
            plan.ruleset()
                .contains("iifname \"lovpn-srv0\" counter drop")
        );
        assert!(!plan.ruleset().contains("{  }"));
    }

    #[test]
    fn rejects_injection_bad_pool_and_foreign_or_duplicate_leases() {
        for name in [
            "",
            "a b",
            "x\"; flush ruleset; \"",
            "toolonginterface0",
            "e\nth",
        ] {
            let mut p = policy();
            p.wan_interface = name.into();
            assert_eq!(
                compile(&p).err(),
                Some(ServerFirewallError::Interface),
                "{name:?}"
            );
        }
        let mut same = policy();
        same.wan_interface = same.interface.clone();
        assert_eq!(compile(&same).err(), Some(ServerFirewallError::Interface));
        for pool in ["10.66.0.0/30", "10.0.0.0/8", "10.66.0.1/24"] {
            let mut p = policy();
            p.pool = pool.parse().unwrap_or_else(|_| unreachable!());
            assert_eq!(compile(&p).err(), Some(ServerFirewallError::Pool), "{pool}");
        }
        for lease in ["10.66.1.2", "10.66.0.0", "10.66.0.255"] {
            let mut p = policy();
            p.leases
                .push(lease.parse().unwrap_or_else(|_| unreachable!()));
            assert_eq!(
                compile(&p).err(),
                Some(ServerFirewallError::Lease),
                "{lease}"
            );
        }
        let mut dup = policy();
        dup.leases
            .push("10.66.0.2".parse().unwrap_or_else(|_| unreachable!()));
        assert_eq!(compile(&dup).err(), Some(ServerFirewallError::Lease));
    }
}
