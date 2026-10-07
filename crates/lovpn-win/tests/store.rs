//! Windows storage tests: DPAPI sealing, the protected directory, and profile rules.
//! Run natively on Windows (`cargo test -p lovpn-win`); the file is empty elsewhere.
#![cfg(windows)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use lovpn_client::ClientError;
use lovpn_keys::{ClientPrivateKey, ServerPrivateKey};
use lovpn_win::{profiles::ProfileStore, store};
use std::{os::windows::process::CommandExt, process::Command};

fn private_dir() -> std::path::PathBuf {
    // ProgramData is where the service lives; tests use a unique child so they can run
    // alongside an installed service.
    store::default_state_dir().join(format!(
        "test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn profile_text(server_public: &str) -> String {
    format!(
        "schema_version = 1\n[profile]\nname = \"t\"\nendpoint = \"192.0.2.1:51820\"\nserver_public_key = \"{server_public}\"\n[tunnel]\ninterface = \"lovpn0\"\naddresses = [\"10.66.0.2/32\"]\nmtu = 1380\nrouting = \"full\"\nroutes = [\"0.0.0.0/0\"]\nipv6 = \"block\"\n[dns]\nservers = [\"10.66.0.1\"]\n[firewall]\nkill_switch = \"strict\"\n"
    )
}

#[test]
fn dpapi_round_trips_and_the_sealed_form_hides_the_secret() {
    let secret = [0x5au8; 32];
    let sealed = store::seal(&secret).unwrap();
    assert_ne!(&sealed[..], &secret[..]);
    assert!(!sealed.windows(32).any(|w| w == secret));
    let plain = store::unseal(&sealed).unwrap();
    assert_eq!(&plain[..], &secret[..]);
    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    assert!(store::unseal(&tampered).is_err());
}

#[test]
fn private_dir_is_locked_to_system_and_administrators() {
    let dir = private_dir();
    store::ensure_private_dir(&dir).unwrap();
    let listing = Command::new("icacls")
        .arg(&dir)
        .creation_flags(0x0800_0000)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&listing.stdout).to_string();
    assert!(text.contains("NT AUTHORITY\\SYSTEM"), "{text}");
    assert!(text.contains("BUILTIN\\Administrators"), "{text}");
    assert!(!text.contains("BUILTIN\\Users"), "{text}");
    assert!(!text.contains("Everyone"), "{text}");
    // Idempotent: a second call keeps working and keeps the same protection.
    store::ensure_private_dir(&dir).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn profile_import_enforces_the_server_key_and_never_stores_a_plain_key() {
    let dir = private_dir();
    let profiles = ProfileStore::open(dir.clone()).unwrap();
    let server = ServerPrivateKey::generate().unwrap().public_key();
    let other = ServerPrivateKey::generate().unwrap().public_key();
    let key = ClientPrivateKey::generate().unwrap();
    let text = profile_text(&server.to_string());

    // Wrong expected server key: refused, nothing stored.
    assert_eq!(
        profiles
            .import("home", &text, Some(&key), &other)
            .unwrap_err(),
        ClientError::ServerKeyMismatch
    );
    assert!(profiles.list().unwrap().is_empty());

    profiles.import("home", &text, Some(&key), &server).unwrap();
    assert_eq!(profiles.list().unwrap().len(), 1);
    let on_disk = std::fs::read(dir.join("home.key")).unwrap();
    assert!(!on_disk.windows(32).any(|w| w == &key.expose_bytes()[..]));
    let (config, loaded) = profiles.load("home").unwrap();
    assert_eq!(config.profile.server_public_key, server.to_string());
    assert_eq!(loaded.public_key(), key.public_key());

    // Duplicate names and bad names are refused.
    assert_eq!(
        profiles
            .import("home", &text, Some(&key), &server)
            .unwrap_err(),
        ClientError::ProfileExists
    );
    assert_eq!(
        profiles
            .import("../evil", &text, Some(&key), &server)
            .unwrap_err(),
        ClientError::ProfileName
    );
    profiles.remove("home").unwrap();
    assert!(profiles.list().unwrap().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn service_held_identity_flow_returns_only_the_public_key() {
    let dir = private_dir();
    let profiles = ProfileStore::open(dir.clone()).unwrap();
    let public = profiles.generate_identity("laptop").unwrap();
    assert_eq!(profiles.public_key_of("laptop").unwrap(), public);
    // A second identity with the same name is refused; an identity alone is not a profile.
    assert_eq!(
        profiles.generate_identity("laptop").unwrap_err(),
        ClientError::ProfileExists
    );
    assert!(profiles.list().unwrap().is_empty());
    let server = ServerPrivateKey::generate().unwrap().public_key();
    profiles
        .import("laptop", &profile_text(&server.to_string()), None, &server)
        .unwrap();
    assert_eq!(profiles.list().unwrap().len(), 1);
    // Importing without a pending identity is refused.
    assert!(
        profiles
            .import("ghost", &profile_text(&server.to_string()), None, &server)
            .is_err()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn scoped_profile_import_preserves_baseline_and_scope_intent() {
    let dir = private_dir();
    let profiles = ProfileStore::open(dir.clone()).unwrap();
    let server = ServerPrivateKey::generate().unwrap().public_key();
    let key = ClientPrivateKey::generate().unwrap();
    let text = profile_text(&server.to_string()).replace(
        "[dns]",
        "[dns]\nscopes = [{ namespace = \".corp.example\", servers = [\"10.66.0.53\"] }]",
    );
    profiles
        .import("office", &text, Some(&key), &server)
        .unwrap();
    let (config, _) = profiles.load("office").unwrap();
    assert_eq!(config.dns.servers[0].to_string(), "10.66.0.1");
    assert_eq!(config.dns.scopes[0].namespace, ".corp.example");
    assert_eq!(profiles.list().unwrap()[0].name, "office");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn nrpt_intent_roundtrips_durably_and_offline_release_cannot_race_service() {
    use lovpn_win::{
        dns,
        record::{Record, RecordStore},
    };
    let dir = private_dir();
    let records = RecordStore::open(dir.clone()).unwrap();
    assert_eq!(records.load().unwrap().schema_version, 1);
    let scopes = vec![dns::Scope {
        namespace: ".corp.example".into(),
        servers: vec![std::net::Ipv4Addr::new(10, 66, 0, 53)],
    }];
    let journal = dns::new_journal(&scopes).unwrap();
    assert_ne!(journal.owner, dns::new_journal(&scopes).unwrap().owner);
    let record = Record {
        schema_version: 2,
        nrpt: Some(journal.clone()),
        ..Record::default()
    };
    records.save(&record).unwrap();
    assert_eq!(records.load().unwrap().nrpt, Some(journal));
    assert!(RecordStore::open(dir.clone()).is_err());
    // Replacement of an existing record is required for acknowledging restoration.
    records
        .save(&Record {
            schema_version: 2,
            ..Record::default()
        })
        .unwrap();
    assert!(records.load().unwrap().nrpt.is_none());
    drop(records);
    let records = RecordStore::open(dir.clone()).unwrap();
    std::fs::write(dir.join("session.json"), br#"{"schema_version":999}"#).unwrap();
    assert!(records.load().is_err());
    drop(records);
    std::fs::remove_dir_all(dir).unwrap();
}
