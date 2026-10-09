#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(target_os = "linux")]

use lovpn_keys::{ClientPrivateKey, ClientPublicKey, ServerPrivateKey};
use lovpn_server::{
    ExportOptions, PeerStatus, ServerError, ServerState, SetupParams, Store, store::MAX_STATE_BYTES,
};
use std::{os::unix::fs::PermissionsExt, path::Path, sync::Arc, thread};

fn params() -> SetupParams {
    SetupParams {
        label: "Home Server".into(),
        interface: "lovpn-srv0".into(),
        wan_interface: "eth0".into(),
        endpoint: "192.0.2.10:51820".parse().unwrap(),
        listen_port: 51820,
        pool: "10.66.0.0/29".parse().unwrap(),
        dns: vec!["10.66.0.1".parse().unwrap()],
        mtu: 1380,
    }
}

fn client_key() -> ClientPublicKey {
    ClientPrivateKey::generate().unwrap().public_key()
}

fn new_state() -> (ServerState, ServerPrivateKey) {
    let key = ServerPrivateKey::generate().unwrap();
    (
        ServerState::new(params(), key.public_key(), 1_000).unwrap(),
        key,
    )
}

fn store_in(dir: &Path) -> (Store, ServerPrivateKey) {
    let state_dir = dir.join("state");
    Store::create_dir(&state_dir).unwrap();
    let store = Store::open(&state_dir).unwrap();
    let (state, key) = new_state();
    store.init(&state, &key).unwrap();
    (store, key)
}

#[test]
fn peer_lifecycle_leases_and_exports_validate_with_client_parser() {
    let (mut state, _) = new_state();
    let a = client_key();
    let peer = state.create_peer("laptop", a, 2_000).unwrap().clone();
    assert_eq!(peer.address.to_string(), "10.66.0.2");
    assert_eq!(state.server_address().to_string(), "10.66.0.1");
    let b = state
        .create_peer("phone", client_key(), 2_001)
        .unwrap()
        .clone();
    assert_eq!(b.address.to_string(), "10.66.0.3");

    let profile = state
        .export_profile("laptop", &ExportOptions::default())
        .unwrap();
    let parsed = lovpn_config::parse(&profile).unwrap();
    assert_eq!(parsed.tunnel.addresses[0].to_string(), "10.66.0.2/32");
    assert_eq!(parsed.profile.server_public_key, state.server.public_key);
    // Export is selectable by numeric id too, and contains no private material.
    assert_eq!(
        state
            .export_profile("1", &ExportOptions::default())
            .unwrap(),
        profile
    );
    assert!(!profile.contains("private_key") && !profile.contains("preshared"));

    // Revoked peers cannot be exported; their lease is quarantined, not reused.
    state.revoke_peer("laptop", 3_000).unwrap();
    assert_eq!(
        state
            .export_profile("laptop", &ExportOptions::default())
            .err(),
        Some(ServerError::NotFound)
    );
    let c = state
        .create_peer("tablet", client_key(), 3_001)
        .unwrap()
        .clone();
    assert_eq!(c.address.to_string(), "10.66.0.4");
    assert_eq!(state.peers[0].status, PeerStatus::Revoked);
    assert_eq!(
        state.revoke_peer("laptop", 3_002).err(),
        Some(ServerError::NotFound)
    );
    // A revoked name may be reused by a new peer with a new id and key.
    assert_eq!(
        state.create_peer("laptop", client_key(), 3_003).unwrap().id,
        4
    );
    state.validate().unwrap();
}

#[test]
fn keys_are_never_reused_rotation_keeps_lease_and_retires_old_key() {
    let (mut state, server) = new_state();
    let first = client_key();
    state.create_peer("one", first, 1).unwrap();
    assert_eq!(
        state.create_peer("two", first, 1).err(),
        Some(ServerError::DuplicateKey)
    );
    // Server's own public key is not a valid client key.
    let as_client: ClientPublicKey = server.public_key().to_string().parse().unwrap();
    assert_eq!(
        state.create_peer("srv", as_client, 1).err(),
        Some(ServerError::Key)
    );
    assert_eq!(
        state.create_peer("one", client_key(), 1).err(),
        Some(ServerError::DuplicateName)
    );
    for bad in ["", "12", "has space", "a/b", "x\"y", &"n".repeat(65)] {
        assert_eq!(
            state.create_peer(bad, client_key(), 1).err(),
            Some(ServerError::Name),
            "{bad}"
        );
    }

    let rotated = client_key();
    let before = state.find_active("one").unwrap().address;
    state.rotate_peer("one", rotated).unwrap();
    let peer = state.find_active("one").unwrap();
    assert_eq!((peer.address, peer.key_epoch), (before, 1));
    assert_eq!(peer.public_key, rotated.to_string());
    // Old key can no longer enroll or rotate in, even for another peer.
    assert_eq!(
        state.create_peer("old", first, 1).err(),
        Some(ServerError::DuplicateKey)
    );
    assert_eq!(
        state.rotate_peer("one", first).err(),
        Some(ServerError::DuplicateKey)
    );
    // A revoked peer's key is also burned.
    state.revoke_peer("one", 2).unwrap();
    assert_eq!(
        state.create_peer("again", rotated, 3).err(),
        Some(ServerError::DuplicateKey)
    );
    state.validate().unwrap();
}

#[test]
fn pool_exhaustion_is_reported_and_leases_stay_in_pool() {
    let (mut state, _) = new_state(); // /29: .1 server, .2-.6 peers
    for index in 0..5 {
        state
            .create_peer(&format!("p{index}"), client_key(), 1)
            .unwrap();
    }
    assert_eq!(
        state.create_peer("extra", client_key(), 1).err(),
        Some(ServerError::PoolExhausted)
    );
    state.revoke_peer("p0", 2).unwrap();
    assert_eq!(
        state.create_peer("extra", client_key(), 3).err(),
        Some(ServerError::PoolExhausted),
        "revoked leases are quarantined"
    );
    let policy = state.firewall_policy();
    assert_eq!(
        policy.leases.len(),
        4,
        "revoked lease must leave the firewall allow set"
    );
    lovpn_firewall::server::compile(&policy).unwrap();
}

#[test]
fn setup_rejects_unsafe_parameters() {
    let key = ServerPrivateKey::generate().unwrap().public_key();
    let mut cases: Vec<(SetupParams, ServerError)> = Vec::new();
    let mut p = params();
    p.pool = "8.8.8.0/24".parse().unwrap();
    cases.push((p, ServerError::Pool));
    let mut p = params();
    p.pool = "10.66.0.0/30".parse().unwrap();
    cases.push((p, ServerError::Pool));
    let mut p = params();
    p.pool = "10.66.0.5/24".parse().unwrap();
    cases.push((p, ServerError::Pool));
    let mut p = params();
    p.wan_interface = "lovpn-srv0".into();
    cases.push((p, ServerError::Interface));
    let mut p = params();
    p.interface = "bad name".into();
    cases.push((p, ServerError::Interface));
    // The root broker must only ever create or touch interfaces named like LoVPN's own.
    let mut p = params();
    p.interface = "eth1".into();
    cases.push((p, ServerError::Interface));
    let mut p = params();
    p.dns = vec![];
    cases.push((p, ServerError::Dns));
    let mut p = params();
    p.dns = vec!["fd00::1".parse().unwrap()];
    cases.push((p, ServerError::Dns));
    let mut p = params();
    p.mtu = 9000;
    cases.push((p, ServerError::Mtu));
    let mut p = params();
    p.label = " padded ".into();
    cases.push((p, ServerError::Label));
    let mut p = params();
    p.endpoint = "127.0.0.1:51820".parse().unwrap();
    cases.push((p, ServerError::Endpoint));
    let mut p = params();
    p.endpoint = "0.0.0.0:51820".parse().unwrap();
    cases.push((p, ServerError::Endpoint));
    for (case, expected) in cases {
        assert_eq!(ServerState::new(case, key, 1).err(), Some(expected));
    }
}

#[test]
fn store_persists_atomically_with_private_modes_and_generations() {
    let dir = tempfile::tempdir().unwrap();
    let (store, key) = store_in(dir.path());
    let state_dir = dir.path().join("state");
    for (name, mode) in [("", 0o700), ("state.json", 0o600), ("server.key", 0o600)] {
        let path = state_dir.join(name);
        let actual = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(actual, mode, "{name}");
    }
    assert_eq!(store.load().unwrap().generation, 1);
    assert_eq!(store.server_key().unwrap().public_key(), key.public_key());

    let k = client_key();
    let (generation, ()) = store
        .update(Some(1), |s| s.create_peer("a", k, 5).map(|_| ()))
        .unwrap();
    assert_eq!(generation, 2);
    // Stale expected generation changes nothing.
    assert_eq!(
        store
            .update(Some(1), |s| s.create_peer("b", client_key(), 5).map(|_| ()))
            .err(),
        Some(ServerError::Generation)
    );
    assert_eq!(store.load().unwrap().peers.len(), 1);
    // A failing mutation commits nothing and does not bump the generation.
    assert!(
        store
            .update(None, |s| s.create_peer("a", client_key(), 5).map(|_| ()))
            .is_err()
    );
    assert_eq!(store.load().unwrap().generation, 2);
    // Re-init never overwrites the identity or state.
    let (state, other) = new_state();
    assert_eq!(store.init(&state, &other).err(), Some(ServerError::Exists));
    assert_eq!(store.server_key().unwrap().public_key(), key.public_key());
}

#[test]
fn concurrent_updates_serialize_without_lost_writes() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = store_in(dir.path());
    let store = Arc::new(store);
    let workers: Vec<_> = (0..5)
        .map(|index| {
            let store = Arc::clone(&store);
            thread::spawn(move || {
                let key = client_key();
                loop {
                    match store.update(None, |s| {
                        s.create_peer(&format!("w{index}"), key, 1).map(|_| ())
                    }) {
                        Err(ServerError::Busy) => thread::yield_now(),
                        other => break other.map(|(g, ())| g),
                    }
                }
            })
        })
        .collect();
    let mut generations: Vec<u64> = workers
        .into_iter()
        .map(|w| w.join().unwrap().unwrap())
        .collect();
    generations.sort_unstable();
    assert_eq!(generations, vec![2, 3, 4, 5, 6]);
    let state = store.load().unwrap();
    assert_eq!(state.peers.len(), 5);
    let mut addresses: Vec<_> = state.peers.iter().map(|p| p.address).collect();
    addresses.dedup();
    assert_eq!(addresses.len(), 5);
}

#[test]
fn crash_before_rename_leaves_old_state_and_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = store_in(dir.path());
    let state_dir = dir.path().join("state");
    let crashing = Store::open(&state_dir).unwrap().with_crash_before_rename();
    let result = crashing.update(None, |s| s.create_peer("lost", client_key(), 1).map(|_| ()));
    assert_eq!(result.err(), Some(ServerError::Storage));
    assert!(
        state_dir.join("state.json.tmp").exists(),
        "temp file left behind by the crash"
    );
    // Old complete state is intact and readable despite the leftover temp file.
    let state = store.load().unwrap();
    assert_eq!((state.generation, state.peers.len()), (1, 0));
    // A garbage temp file from a torn write is replaced by the next writer.
    std::fs::write(state_dir.join("state.json.tmp"), b"{\"torn").unwrap();
    let (generation, ()) = store
        .update(None, |s| s.create_peer("kept", client_key(), 2).map(|_| ()))
        .unwrap();
    assert_eq!(generation, 2);
    assert!(!state_dir.join("state.json.tmp").exists());
    assert_eq!(store.load().unwrap().peers[0].name, "kept");
}

#[test]
fn corrupt_oversized_downgraded_and_tampered_state_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = store_in(dir.path());
    let path = dir.path().join("state/state.json");
    let original = std::fs::read_to_string(&path).unwrap();
    let write = |text: &str| {
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    };

    write("{ not json");
    assert_eq!(store.load().err(), Some(ServerError::State));
    write(&original.replace("\"schema_version\": 1", "\"schema_version\": 2"));
    assert_eq!(store.load().err(), Some(ServerError::Version));
    write(&original.replace("\"schema_version\": 1", "\"schema_version\": 0"));
    assert_eq!(store.load().err(), Some(ServerError::Version));
    write(&original.replace("\"peers\": []", "\"peers\": [], \"surprise\": true"));
    assert_eq!(store.load().err(), Some(ServerError::State));
    // Hand-edited policy that fails revalidation (public pool) is refused.
    write(&original.replace("10.66.0.0/29", "8.8.8.0/29"));
    assert!(store.load().is_err());
    write(&" ".repeat(MAX_STATE_BYTES as usize + 1));
    assert_eq!(store.load().err(), Some(ServerError::State));
    // Updates against corrupt state fail closed and never overwrite it.
    write("{ not json");
    assert!(store.update(None, |_| Ok(())).is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ not json");
    write(&original);
    assert!(store.load().is_ok());
}

#[test]
fn unsafe_directory_and_file_permissions_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = store_in(dir.path());
    let state_dir = dir.path().join("state");
    let state_file = state_dir.join("state.json");

    std::fs::set_permissions(&state_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(store.load().err(), Some(ServerError::Permissions));
    std::fs::set_permissions(&state_file, std::fs::Permissions::from_mode(0o600)).unwrap();

    std::fs::set_permissions(
        state_dir.join("server.key"),
        std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    assert_eq!(store.server_key().err(), Some(ServerError::Permissions));
    std::fs::set_permissions(
        state_dir.join("server.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        Store::open(&state_dir).err(),
        Some(ServerError::Permissions)
    );
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&state_dir, &link).unwrap();
    assert_eq!(Store::open(&link).err(), Some(ServerError::Permissions));

    // A key that does not match the recorded identity is rejected.
    let replacement = ServerPrivateKey::generate().unwrap();
    std::fs::remove_file(state_dir.join("server.key")).unwrap();
    lovpn_keys::file::write_new(&state_dir.join("server.key"), &replacement).unwrap();
    assert_eq!(store.server_key().err(), Some(ServerError::State));
}

#[test]
fn errors_and_state_never_contain_private_keys() {
    let dir = tempfile::tempdir().unwrap();
    let (store, key) = store_in(dir.path());
    let secret = key.expose_base64().to_string();
    let state_text = std::fs::read_to_string(dir.path().join("state/state.json")).unwrap();
    assert!(!state_text.contains(&secret));
    for error in [
        ServerError::Key,
        ServerError::State,
        ServerError::Storage,
        ServerError::Permissions,
    ] {
        assert!(!format!("{error} {error:?}").contains(&secret));
    }
    let _ = store;
}

#[test]
fn an_installer_created_empty_private_directory_is_adopted_but_nothing_else_is() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let make = |name: &str, mode: u32| {
        let path = dir.path().join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    };
    // What systemd-tmpfiles leaves behind: empty, 0700, ours.
    let ready = make("ready", 0o700);
    assert!(Store::create_dir(&ready).is_ok());
    let (state, key) = new_state();
    let store = Store::open(&ready).unwrap();
    store.init(&state, &key).unwrap();
    // Existing state is never adopted (non-empty), nor a directory with a loose mode.
    assert_eq!(Store::create_dir(&ready).unwrap_err(), ServerError::Exists);
    let loose = make("loose", 0o755);
    assert_eq!(Store::create_dir(&loose).unwrap_err(), ServerError::Exists);
    let target = make("target", 0o700);
    let link = dir.path().join("link");
    symlink(&target, &link).unwrap();
    assert_eq!(Store::create_dir(&link).unwrap_err(), ServerError::Exists);
    // A missing directory is still created, mode 0700.
    let fresh = dir.path().join("fresh");
    Store::create_dir(&fresh).unwrap();
    assert_eq!(
        std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
        0o700
    );
}
