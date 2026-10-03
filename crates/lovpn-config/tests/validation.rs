#![allow(clippy::unwrap_used, clippy::expect_used)]

use lovpn_config::{ConfigError, MAX_CONFIG_BYTES, parse};
use proptest::prelude::*;

const SAMPLE: &str = include_str!("../../../examples/client.toml");

#[test]
fn accepts_public_full_tunnel_profile_without_modifying_addresses() {
    let config = parse(SAMPLE).unwrap();
    assert_eq!(config.tunnel.addresses[0].to_string(), "10.66.0.2/32");
    assert_eq!(config.profile.endpoint.port(), 51820);
}

#[test]
fn dual_stack_requires_addresses_routes_and_dns_agreement() {
    let dual = SAMPLE
        .replace("[\"10.66.0.2/32\"]", "[\"10.66.0.2/32\", \"fd66::2/128\"]")
        .replace("[\"0.0.0.0/0\"]", "[\"0.0.0.0/0\", \"::/0\"]")
        .replace("ipv6 = \"block\"", "ipv6 = \"tunnel\"")
        .replace("[\"10.66.0.1\"]", "[\"fd66::1\"]");
    assert!(parse(&dual).is_ok());
    assert!(parse(&dual.replace(", \"::/0\"", "")).is_err());
    assert!(parse(&dual.replace(", \"fd66::2/128\"", "")).is_err());
    assert!(parse(&dual.replace("ipv6 = \"tunnel\"", "ipv6 = \"block\"")).is_err());
}

#[test]
fn unknown_fields_are_rejected_at_every_level_without_echo() {
    for section in [
        "schema_version = 1",
        "[profile]",
        "[tunnel]",
        "[dns]",
        "[firewall]",
    ] {
        let input = SAMPLE.replace(
            section,
            &format!("{section}\nprivate_key = \"DO_NOT_ECHO_ME\""),
        );
        let error = parse(&input).err().expect("unknown field accepted");
        assert_eq!(error, ConfigError::Syntax);
        assert!(!format!("{error:?} {error}").contains("DO_NOT_ECHO_ME"));
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
fn errors_do_not_echo_malformed_toml() {
    let error = parse("PASSWORD_DO_NOT_ECHO = [").err().unwrap();
    assert!(!format!("{error:?} {error}").contains("PASSWORD_DO_NOT_ECHO"));
}

#[test]
fn missing_duplicate_and_implicit_fields_fail() {
    assert!(parse(&SAMPLE.replace("schema_version = 1", "")).is_err());
    assert!(parse(&SAMPLE.replace("ipv6 = \"block\"", "")).is_err());
    assert!(parse(&format!("{SAMPLE}\nkill_switch = \"off\"")).is_err());
    assert!(parse(&SAMPLE.replace("strict", "magic")).is_err());
}

#[test]
fn bounded_input() {
    assert_eq!(
        parse(&"x".repeat(MAX_CONFIG_BYTES + 1)).err(),
        Some(ConfigError::TooLarge)
    );
    let input = format!(
        "{SAMPLE}#{}",
        "x".repeat(MAX_CONFIG_BYTES - SAMPLE.len() - 1)
    );
    assert_eq!(input.len(), MAX_CONFIG_BYTES);
    assert!(parse(&input).is_ok());
}

#[test]
fn endpoint_special_ranges_scope_and_zero_port_are_rejected() {
    for endpoint in [
        "0.1.2.3:51820",
        "127.0.0.1:51820",
        "169.254.1.1:51820",
        "224.0.0.1:51820",
        "255.255.255.255:51820",
        "192.0.2.1:0",
        "[::1]:51820",
        "[::]:51820",
        "[fe80::1]:51820",
        "[ff02::1]:51820",
        "[::ffff:192.0.2.1]:51820",
        "host.example:51820",
    ] {
        assert!(
            parse(&SAMPLE.replace("192.0.2.1:51820", endpoint)).is_err(),
            "{endpoint}"
        );
    }
    let mut config = parse(SAMPLE).unwrap();
    config.profile.endpoint = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
        "2001:db8::1".parse().unwrap(),
        51820,
        0,
        3,
    ));
    assert_eq!(config.validate(), Err(ConfigError::Endpoint));
}

#[test]
fn invalid_keys_are_not_imported() {
    let mut config = parse(SAMPLE).unwrap();
    for key in [
        "",
        "not-base64",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB=",
    ] {
        config.profile.server_public_key = key.into();
        assert_eq!(config.validate(), Err(ConfigError::PublicKey));
    }
}

#[test]
fn interface_and_display_name_injection_rejected() {
    let mut config = parse(SAMPLE).unwrap();
    for interface in [
        "lo",
        "eth0",
        "lovpn0\";flush ruleset",
        "lovpn0\n",
        "lovpn012345678901",
        "lovpnλ",
    ] {
        config.tunnel.interface = interface.into();
        assert_eq!(config.validate(), Err(ConfigError::Interface));
    }
    config.tunnel.interface = "lovpn0".into();
    for name in [
        "",
        " leading",
        "trailing ",
        "injected\nname",
        "bidi\u{202e}name",
        "<script>",
    ] {
        config.profile.name = name.into();
        assert_eq!(config.validate(), Err(ConfigError::Name));
    }
}

#[test]
fn host_addresses_are_not_networks_or_duplicate_ips() {
    for replacement in [
        "10.66.0.0/24",
        "10.66.0.255/24",
        "127.0.0.1/32",
        "224.0.0.1/32",
    ] {
        assert!(parse(&SAMPLE.replace("10.66.0.2/32", replacement)).is_err());
    }
    assert!(parse(&SAMPLE.replace("10.66.0.2/32", "10.66.0.2/24")).is_ok());
    assert!(
        parse(&SAMPLE.replace("[\"10.66.0.2/32\"]", "[\"10.66.0.2/32\", \"10.66.0.2/24\"]"))
            .is_err()
    );
}

#[test]
fn route_semantics_and_dns_coverage_are_enforced() {
    let split = SAMPLE
        .replace("routing = \"full\"", "routing = \"split\"")
        .replace("0.0.0.0/0", "10.66.0.0/24");
    assert!(parse(&split).is_ok());
    for route in [
        "0.0.0.0/0",
        "10.66.0.1/24",
        "10.67.0.0/24",
        "127.0.0.0/8",
        "169.0.0.0/8",
        "224.0.0.0/4",
    ] {
        assert!(
            parse(&split.replace("10.66.0.0/24", route)).is_err(),
            "{route}"
        );
    }
    for routes in [
        "[\"10.66.0.0/24\", \"10.66.0.0/25\"]",
        "[\"10.66.0.0/24\", \"10.66.0.0/24\"]",
    ] {
        assert!(parse(&split.replace("[\"10.66.0.0/24\"]", routes)).is_err());
    }
    assert!(parse(&SAMPLE.replace("0.0.0.0/0", "10.66.0.0/24")).is_err());
}

#[test]
fn unsafe_dns_and_empty_lists_fail() {
    for dns in [
        "127.0.0.53",
        "0.0.0.0",
        "169.254.1.1",
        "255.255.255.255",
        "224.0.0.1",
        "::1",
        "fd66::1",
    ] {
        assert!(parse(&SAMPLE.replace("[\"10.66.0.1\"]", &format!("[\"{dns}\"]"))).is_err());
    }
    for list in ["[]", "[\"10.66.0.1\", \"10.66.0.1\"]"] {
        assert!(parse(&SAMPLE.replace("[\"10.66.0.1\"]", list)).is_err());
    }
}

#[test]
fn explicit_off_is_data_not_a_claim_of_protection() {
    assert!(parse(&SAMPLE.replace("strict", "off")).is_ok());
}

proptest! {
    #[test]
    fn arbitrary_utf8_never_panics(chars in prop::collection::vec(any::<char>(), 0..4096)) {
        let input: String = chars.into_iter().collect();
        let _ = parse(&input);
    }

    #[test]
    fn unknown_versions_always_fail(version in any::<u32>()) {
        let input = SAMPLE.replace("schema_version = 1", &format!("schema_version = {version}"));
        prop_assert_eq!(parse(&input).is_ok(), version == 1);
    }

    #[test]
    fn only_supported_mtu_accepted(mtu in any::<u16>()) {
        let mut config = parse(SAMPLE).unwrap();
        config.tunnel.mtu = mtu;
        prop_assert_eq!(config.validate().is_ok(), (1280..=1420).contains(&mtu));
    }
}
