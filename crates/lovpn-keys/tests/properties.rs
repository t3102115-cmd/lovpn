//! Key text parsing is strict: only canonical base64 of exactly 32 bytes is
//! accepted, and anything accepted prints back identically.
#![allow(clippy::unwrap_used)]

use lovpn_keys::{ClientPrivateKey, ClientPublicKey};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn arbitrary_text_never_panics(text in any::<String>()) {
        let _ = text.parse::<ClientPublicKey>();
        let _ = ClientPrivateKey::from_base64(&text);
    }

    #[test]
    fn accepted_public_keys_round_trip_exactly(text in "[A-Za-z0-9+/=]{0,60}") {
        if let Ok(key) = text.parse::<ClientPublicKey>() {
            prop_assert_eq!(key.to_string(), text);
        }
    }

    #[test]
    fn validated_public_keys_round_trip_through_text(bytes in any::<[u8; 32]>()) {
        if let Ok(key) = ClientPublicKey::from_bytes(bytes) {
            let back: ClientPublicKey = key.to_string().parse().unwrap();
            prop_assert_eq!(back.as_bytes(), &bytes);
        }
    }

    #[test]
    fn unclamped_private_keys_are_refused(mut bytes in any::<[u8; 32]>()) {
        bytes[0] |= 1; // low bits must be clear in a clamped key
        prop_assert!(ClientPrivateKey::from_bytes(bytes).is_err());
    }

    #[test]
    fn the_private_key_text_never_appears_in_debug_output(bytes in any::<[u8; 32]>()) {
        let mut b = bytes;
        b[0] &= 248; b[31] &= 127; b[31] |= 64;
        let key = ClientPrivateKey::from_bytes(b).unwrap();
        let shown = format!("{key:?}");
        prop_assert!(!shown.contains(&*key.expose_base64()));
    }
}
