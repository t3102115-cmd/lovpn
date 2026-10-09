#![no_main]
use lovpn_sys::inspect::*;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_link(true, text);
        let _ = parse_addresses(text);
        let _ = parse_addresses_of(text, "inet6");
        let _ = parse_rules(text);
        let _ = parse_routes(text);
        let _ = parse_routes_checked(text);
        let _ = parse_route_get(true, text);
    }
});
