#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<lovpn_client::protocol::Request>(data);
});
