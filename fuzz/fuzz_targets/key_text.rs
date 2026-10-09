#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = text.parse::<lovpn_keys::ClientPublicKey>();
        let _ = lovpn_keys::ClientPrivateKey::from_base64(text);
    }
});
