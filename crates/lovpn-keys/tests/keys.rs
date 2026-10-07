use base64::{Engine, engine::general_purpose::STANDARD};
#[cfg(unix)]
use lovpn_keys::file::{self, KeyFileError};
use lovpn_keys::{ClientPrivateKey, ClientPublicKey, KeyError, PresharedKey, ServerPrivateKey};
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

#[test]
fn generated_keys_are_clamped_unique_and_round_trip() {
    let first = ClientPrivateKey::generate().unwrap_or_else(|_| unreachable!());
    let second = ClientPrivateKey::generate().unwrap_or_else(|_| unreachable!());
    assert_ne!(first.public_key(), second.public_key());
    let text = first.expose_base64();
    let parsed = ClientPrivateKey::from_base64(&text).unwrap_or_else(|_| unreachable!());
    assert_eq!(parsed.public_key(), first.public_key());
    let public = first.public_key().to_string();
    assert_eq!(public.parse::<ClientPublicKey>(), Ok(first.public_key()));
}

#[test]
fn public_key_matches_rfc7748_vector() {
    // RFC 7748 §6.1 Alice: private (already clamped) -> public.
    // The RFC lists the raw scalar; X25519 clamps it, so use the clamped form that
    // WireGuard tooling stores (byte 0 & 248, byte 31 & 127 | 64) — same public key.
    let private = hex("70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a");
    let public = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let key = ClientPrivateKey::from_base64(&b64(&private)).unwrap_or_else(|_| unreachable!());
    assert_eq!(key.public_key().as_bytes().as_slice(), public.as_slice());
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap_or(0))
        .collect()
}

#[test]
fn weak_noncanonical_and_malformed_public_keys_are_rejected() {
    let weak = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];
    for item in weak {
        assert_eq!(
            b64(&hex(item)).parse::<ClientPublicKey>(),
            Err(KeyError::Weak),
            "{item}"
        );
    }
    // p, p+1 (unreduced) and a set high bit are ambiguous encodings.
    for item in [
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0200000000000000000000000000000000000000000000000000000000000080",
    ] {
        assert_eq!(
            b64(&hex(item)).parse::<ClientPublicKey>(),
            Err(KeyError::NonCanonical),
            "{item}"
        );
    }
    let good = ClientPrivateKey::generate()
        .unwrap_or_else(|_| unreachable!())
        .public_key()
        .to_string();
    for bad in [
        String::new(),
        good[..43].to_string(),
        format!("{good}="),
        format!(" {good}"),
        format!("{good}\n"),
        good.replace('=', "A"),
        good.replace(&good[..4], "****"),
        STANDARD.encode([7u8; 31]),
        // Same bytes, URL-safe alphabet.
        b64(&[0xfb; 32]).replace('+', "-"),
    ] {
        assert!(bad.parse::<ClientPublicKey>().is_err(), "{bad:?}");
    }
    // Non-canonical trailing bits in the final base64 symbol.
    let mut tampered = good.into_bytes();
    tampered[42] = if tampered[42] == b'B' { b'C' } else { b'B' };
    assert!(
        String::from_utf8(tampered)
            .map(|s| s.parse::<ClientPublicKey>().is_err())
            .unwrap_or(true)
    );
}

#[test]
fn private_keys_must_be_clamped_and_nonzero() {
    for bytes in [[0u8; 32], [0xffu8; 32], [1u8; 32]] {
        assert_eq!(
            ClientPrivateKey::from_base64(&b64(&bytes)).err(),
            Some(KeyError::Unclamped)
        );
    }
    assert!(PresharedKey::from_base64(&b64(&[0u8; 32])).is_err());
    assert!(PresharedKey::generate().is_ok());
}

#[test]
fn secrets_are_redacted_in_debug_and_errors() {
    let private = ServerPrivateKey::generate().unwrap_or_else(|_| unreachable!());
    let secret = private.expose_base64().to_string();
    let psk = PresharedKey::generate().unwrap_or_else(|_| unreachable!());
    let psk_text = psk.expose_base64().to_string();
    let rendered = format!("{private:?} {psk:?} {:#?}", Some(&private));
    assert!(!rendered.contains(&secret) && !rendered.contains(&psk_text));
    assert!(rendered.contains("<redacted>"));
    // Error output never echoes input, even when it contains secret-like text.
    let error = ClientPrivateKey::from_base64(&format!("{secret}x")).err();
    let text = format!(
        "{error:?} {}",
        error.map(|e| e.to_string()).unwrap_or_default()
    );
    assert!(!text.contains(&secret));
}

#[cfg(unix)]
mod unix_files {
    use super::*;
    fn secure_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| unreachable!());
        dir
    }

    #[test]
    fn key_file_round_trip_has_private_mode_and_refuses_overwrite() {
        let dir = secure_dir();
        let path = dir.path().join("client.key");
        let key = ClientPrivateKey::generate().unwrap_or_else(|_| unreachable!());
        assert_eq!(file::write_new(&path, &key), Ok(()));
        let mode = std::fs::metadata(&path).map(|m| m.permissions().mode() & 0o777);
        assert_eq!(mode.ok(), Some(0o600));
        let loaded = file::read::<lovpn_keys::Client>(&path).unwrap_or_else(|_| unreachable!());
        assert_eq!(loaded.public_key(), key.public_key());
        let other = ClientPrivateKey::generate().unwrap_or_else(|_| unreachable!());
        assert_eq!(file::write_new(&path, &other), Err(KeyFileError::Exists));
        let again = file::read::<lovpn_keys::Client>(&path).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            again.public_key(),
            key.public_key(),
            "original key must survive"
        );
    }

    #[test]
    fn key_file_rejects_unsafe_files() {
        let dir = secure_dir();
        let key = ClientPrivateKey::generate().unwrap_or_else(|_| unreachable!());
        let path = dir.path().join("k");
        assert_eq!(file::write_new(&path, &key), Ok(()));

        // Group/other readable.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            file::read::<lovpn_keys::Client>(&path).err(),
            Some(KeyFileError::Permissions)
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|_| unreachable!());

        // Symlink (read and write) refused.
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            file::read::<lovpn_keys::Client>(&link).err(),
            Some(KeyFileError::Unavailable)
        );
        let victim = dir.path().join("victim");
        let dangling = dir.path().join("dangling");
        symlink(&victim, &dangling).unwrap_or_else(|_| unreachable!());
        assert!(file::write_new(&dangling, &key).is_err());
        assert!(!victim.exists(), "write must not follow a symlink");

        // Hard link, oversized, garbage, directory, missing.
        let hard = dir.path().join("hard");
        std::fs::hard_link(&path, &hard).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            file::read::<lovpn_keys::Client>(&path).err(),
            Some(KeyFileError::Unavailable)
        );
        let big = dir.path().join("big");
        std::fs::write(&big, vec![b'A'; 4096]).unwrap_or_else(|_| unreachable!());
        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            file::read::<lovpn_keys::Client>(&big),
            Err(KeyFileError::Invalid(_))
        ));
        let junk = dir.path().join("junk");
        std::fs::write(&junk, "not a key\n").unwrap_or_else(|_| unreachable!());
        std::fs::set_permissions(&junk, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|_| unreachable!());
        let error = file::read::<lovpn_keys::Client>(&junk).err();
        assert!(matches!(error, Some(KeyFileError::Invalid(_))));
        assert!(
            !error
                .map(|e| e.to_string())
                .unwrap_or_default()
                .contains(dir.path().to_string_lossy().as_ref())
        );
        assert!(file::read::<lovpn_keys::Client>(dir.path()).is_err());
        assert_eq!(
            file::read::<lovpn_keys::Client>(&dir.path().join("none")).err(),
            Some(KeyFileError::Unavailable)
        );
    }

    #[test]
    fn key_file_refuses_group_writable_parent_directory() {
        let dir = secure_dir();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770))
            .unwrap_or_else(|_| unreachable!());
        let key = ClientPrivateKey::generate().unwrap_or_else(|_| unreachable!());
        let path = dir.path().join("k");
        assert_eq!(file::write_new(&path, &key), Err(KeyFileError::Permissions));
        assert!(!path.exists());
    }
}
