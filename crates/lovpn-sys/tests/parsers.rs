//! The observers read the output of `ip -j`. Whatever that output is (truncated,
//! hostile, wrong-typed), parsing it must not panic: a panic would end the
//! daemon's observation loop while the kill switch is up.
#![allow(clippy::unwrap_used)]

use lovpn_sys::inspect::{
    parse_addresses, parse_addresses_of, parse_link, parse_route_get, parse_routes,
    parse_routes_checked, parse_rules,
};
use proptest::prelude::*;

fn json_ish() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        proptest::collection::vec(any::<u8>(), 0..512)
            .prop_map(|b| String::from_utf8_lossy(&b).into_owned()),
        // Plausible shapes with wrong types or missing fields.
        Just(r#"[{"ifname":1,"addr_info":"x","dst":[],"priority":"high"}]"#.to_owned()),
        Just(r#"[{"addr_info":[{"local":null,"prefixlen":-1}]}]"#.to_owned()),
        Just(r#"{"a":[[[[[[[[[[[[]]]]]]]]]]]]}"#.to_owned()),
        Just("[".repeat(10_000)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn inspect_parsers_never_panic(text in json_ish(), ok in any::<bool>()) {
        let _ = parse_link(ok, &text);
        let _ = parse_addresses(&text);
        let _ = parse_addresses_of(&text, "inet6");
        let _ = parse_rules(&text);
        let _ = parse_routes(&text);
        let _ = parse_routes_checked(&text);
        let _ = parse_route_get(ok, &text);
    }

    #[test]
    fn garbage_is_never_reported_as_a_checked_route_table(text in "[^\\[\\{]{0,200}") {
        prop_assert!(parse_routes_checked(&text).is_none());
    }
}
