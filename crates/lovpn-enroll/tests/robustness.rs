#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Hostile-input properties for everything the enrollment listener parses from the network.
//! These are property tests, not coverage-guided fuzzing: they show that no input in the
//! generated space panics, over-reads or is accepted by mistake.
use lovpn_enroll::{
    EnrollError,
    proto::{self, Request},
    token::Token,
};
use proptest::prelude::*;
use std::io::Cursor;

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic_any_parser(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
        let _ = proto::parse_request(&bytes);
        let _ = proto::parse_response(&bytes);
        let _ = Token::parse(&String::from_utf8_lossy(&bytes));
    }

    #[test]
    fn read_line_never_returns_more_than_max_and_never_reads_past_the_newline(
        body in prop::collection::vec(any::<u8>().prop_filter("no newline", |b| *b != b'\n'), 0..600),
        tail in prop::collection::vec(any::<u8>(), 0..64),
        max in 1usize..512,
    ) {
        let mut input = body.clone();
        input.push(b'\n');
        input.extend_from_slice(&tail);
        let mut cursor = Cursor::new(input);
        match proto::read_line(&mut cursor, max) {
            Ok(line) => {
                prop_assert!(line.len() <= max);
                prop_assert_eq!(line, body);
                prop_assert_eq!(cursor.position() as usize, cursor.get_ref().len() - tail.len());
            }
            Err(error) => {
                prop_assert_eq!(error, EnrollError::TooLarge);
                prop_assert!(body.len() >= max);
            }
        }
    }

    #[test]
    fn a_stream_without_a_newline_is_malformed_not_a_hang(body in prop::collection::vec(any::<u8>().prop_filter("no newline", |b| *b != b'\n'), 0..200)) {
        let mut cursor = Cursor::new(body);
        prop_assert!(proto::read_line(&mut cursor, 4096).is_err());
    }

    /// The id is only a lookup handle; the digest covers the secret. So a changed secret
    /// never matches, and a changed id parses to a *different handle* that finds no record.
    #[test]
    fn a_changed_token_never_redeems_the_original_record(position in 0usize..200, replacement in any::<char>()) {
        let token = Token::generate().unwrap();
        let text = token.expose();
        let stored = token.digest();
        let handle = token.id_hex();
        prop_assert!(Token::parse(&text).unwrap().matches(&stored));
        let mut chars: Vec<char> = text.chars().collect();
        let index = position % chars.len();
        if chars[index] != replacement {
            chars[index] = replacement;
            let mutated: String = chars.into_iter().collect();
            if let Ok(parsed) = Token::parse(&mutated) {
                prop_assert!(
                    parsed.id_hex() != handle || !parsed.matches(&stored),
                    "a mutated token would redeem the original record: {mutated}"
                );
            }
        }
    }

    #[test]
    fn oversized_or_unknown_fields_in_a_request_are_refused(extra in "[a-z]{1,12}", value in "[ -~]{0,64}") {
        let line = format!(
            r#"{{"version":1,"token":"x","client_public_key":"y","{extra}":"{}"}}"#,
            value.replace(['\\', '"'], "")
        );
        let parsed: Result<Request, _> = proto::parse_request(line.as_bytes());
        if !matches!(extra.as_str(), "version" | "token" | "client_public_key") {
            prop_assert!(parsed.is_err(), "an unknown field was accepted");
        }
    }
}
