#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = lovpn_enroll::proto::parse_request(data);
    let _ = lovpn_enroll::proto::parse_response(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = lovpn_enroll::token::Token::parse(text);
        let _ = lovpn_enroll::token::parse_digest(text);
    }
});
