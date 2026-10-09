//! The local broker and the Windows pipe both decode this one request type from bytes
//! sent by another local process. Decoding must never panic and never accept unknown
//! fields or operations.
#![allow(clippy::unwrap_used)]

use lovpn_client::protocol::Request;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = serde_json::from_slice::<Request>(&bytes);
    }

    #[test]
    fn unknown_operations_are_refused(op in "[a-z-]{1,24}") {
        let known = ["ping","status","list-profiles","import-profile","remove-profile",
            "generate-identity","import-identity-profile","use-profile","public-key",
            "connect","disconnect","reconnect","repair","reset","logs"];
        prop_assume!(!known.contains(&op.as_str()));
        let json = format!(r#"{{"op":"{op}"}}"#);
        prop_assert!(serde_json::from_str::<Request>(&json).is_err());
    }

    /// Every operation that carries data refuses unknown fields. (serde does not enforce
    /// `deny_unknown_fields` on the data-less variants such as `ping`; they take no input,
    /// so an ignored extra field changes nothing. Documented in docs/release.md.)
    #[test]
    fn extra_fields_are_refused_where_an_operation_takes_input(
        field in "[a-z_]{1,16}", value in any::<u32>()
    ) {
        for (op, base) in [
            ("remove-profile", r#""name":"a""#),
            ("use-profile", r#""name":"a""#),
            ("public-key", r#""name":"a""#),
            ("generate-identity", r#""name":"a""#),
            ("connect", ""),
            ("disconnect", ""),
            ("logs", ""),
        ] {
            prop_assume!(!["name", "profile", "release", "lines"].contains(&field.as_str()));
            let sep = if base.is_empty() { "" } else { "," };
            let json = format!(r#"{{"op":"{op}"{sep}{base},"{field}":{value}}}"#);
            prop_assert!(serde_json::from_str::<Request>(&json).is_err(), "{json}");
        }
    }
}
