#![allow(clippy::unwrap_used)]
//! Whatever text a profile or a server policy carries, the compiler either refuses it or
//! produces statements that touch only LoVPN's own tables: never the host's ruleset.
use ipnet::Ipv4Net;
use lovpn_config::parse;
use lovpn_firewall::server::{ServerPolicy, compile as compile_server};
use lovpn_firewall::{TABLE_NAME, compile, compile_owned};
use proptest::prelude::*;

const SAMPLE: &str = include_str!("../../../examples/client.toml");

fn only_our_tables(ruleset: &str) -> Result<(), String> {
    for line in ruleset
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let ours = ["add", "delete", "flush", "create"].iter().any(|verb| {
            ["table", "chain", "rule", "set", "map", "element"]
                .iter()
                .any(|kind| {
                    line.starts_with(&format!("{verb} {kind} inet lovpn"))
                        || line.starts_with(&format!("{verb} {kind} ip lovpn"))
                })
        });
        if !ours || line.contains("flush ruleset") {
            return Err(format!("statement outside LoVPN's tables: {line}"));
        }
    }
    Ok(())
}

proptest! {
    #[test]
    fn hostile_interface_names_never_escape_the_table(name in "\\PC{0,40}") {
        let toml_name = name.replace('\\', "\\\\").replace('"', "\\\"");
        let text = SAMPLE.replacen("interface = \"lovpn0\"", &format!("interface = \"{toml_name}\""), 1);
        if let Ok(config) = parse(&text) {
            for plan in [compile(&config), compile_owned(&config, 7)].into_iter().flatten() {
                prop_assert_eq!(only_our_tables(plan.ruleset()), Ok(()));
                prop_assert_eq!(only_our_tables(plan.reset_ruleset()), Ok(()));
            }
        }
    }

    #[test]
    fn server_policies_with_hostile_text_never_escape_their_tables(
        interface in "\\PC{0,30}",
        wan in "\\PC{0,30}",
        octets in prop::collection::vec(any::<u8>(), 0..40),
        generation in any::<u64>(),
    ) {
        let leases = octets.chunks(1).map(|b| std::net::Ipv4Addr::new(10, 66, 0, b[0])).collect();
        let policy = ServerPolicy {
            interface,
            wan_interface: wan,
            pool: "10.66.0.0/24".parse::<Ipv4Net>().unwrap(),
            leases,
            generation,
        };
        if let Ok(plan) = compile_server(&policy) {
            prop_assert_eq!(only_our_tables(plan.ruleset()), Ok(()));
            prop_assert_eq!(only_our_tables(plan.reset_ruleset()), Ok(()));
        }
    }
}

#[test]
fn the_table_name_is_ours() {
    assert!(TABLE_NAME.starts_with("lovpn"));
}
