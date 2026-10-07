#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(target_os = "linux")]
//! Online enrollment: token state machine, atomicity, and the real pinned-TLS listener.

use lovpn_enroll::{
    EnrollError, proto,
    tls::{self, Pin},
    token::Token,
};
use lovpn_keys::{ClientPrivateKey, ClientPublicKey, ServerPrivateKey};
use lovpn_server::{
    ExportOptions, PeerStatus, ServerError, ServerState, SetupParams, Store,
    enroll::{CLOCK_TOLERANCE, MAX_TOKENS, REPLAY_WINDOW, TokenStatus},
    enroll_server::{Enroller, Outcome},
};
use std::{
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

const T0: u64 = 1_000_000;

fn params() -> SetupParams {
    SetupParams {
        label: "Home Server".into(),
        interface: "lovpn-srv0".into(),
        wan_interface: "eth0".into(),
        endpoint: "192.0.2.10:51820".parse().unwrap(),
        listen_port: 51820,
        pool: "10.66.0.0/28".parse().unwrap(),
        dns: vec!["10.66.0.1".parse().unwrap()],
        mtu: 1380,
    }
}

fn key() -> ClientPublicKey {
    ClientPrivateKey::generate().unwrap().public_key()
}

fn state() -> ServerState {
    let server = ServerPrivateKey::generate().unwrap();
    ServerState::new(params(), server.public_key(), T0 - 100).unwrap()
}

fn store_in(dir: &Path) -> Store {
    let state_dir = dir.join("state");
    Store::create_dir(&state_dir).unwrap();
    let store = Store::open(&state_dir).unwrap();
    let server = ServerPrivateKey::generate().unwrap();
    store
        .init(
            &ServerState::new(params(), server.public_key(), T0 - 100).unwrap(),
            &server,
        )
        .unwrap();
    let identity = tls::generate_identity().unwrap();
    store
        .init_tls_identity(&identity.certificate_der, &identity.private_key_der)
        .unwrap();
    store
}

fn issue(state: &mut ServerState, name: &str, ttl: u64, now: u64) -> Token {
    let token = Token::generate().unwrap();
    state.issue_token(&token, name, ttl, now).unwrap();
    token
}

// ---------------------------------------------------------------- state machine

#[test]
fn redemption_creates_the_peer_and_consumes_the_token_exactly_once() {
    let mut state = state();
    let token = issue(&mut state, "laptop", 900, T0);
    let client = key();
    let redemption = state.redeem_token(&token, client, T0 + 1).unwrap();
    assert!(!redemption.replayed);
    let peer = state.find_active("laptop").unwrap();
    assert_eq!(peer.id, redemption.peer_id);
    assert_eq!(peer.public_key, client.to_string());
    assert_eq!(peer.address.to_string(), "10.66.0.2");
    // A different key can never reuse the token.
    assert_eq!(
        state.redeem_token(&token, key(), T0 + 2).unwrap_err(),
        ServerError::Denied
    );
    assert_eq!(state.active_peers().count(), 1);
}

#[test]
fn tokens_are_never_stored_only_their_digests() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let token = Token::generate().unwrap();
    store
        .update(None, |s| {
            s.issue_token(&token, "phone", 900, T0).map(|_| ())
        })
        .unwrap();
    let text = token.expose();
    let secret = text.splitn(3, '-').nth(2).unwrap().to_string();
    let on_disk = std::fs::read_to_string(dir.path().join("state/state.json")).unwrap();
    assert!(!on_disk.contains(&text) && !on_disk.contains(&secret));
    assert!(on_disk.contains(&token.id_hex()));
    for entry in std::fs::read_dir(dir.path().join("state")).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !String::from_utf8_lossy(&bytes).contains(&secret),
                "{path:?}"
            );
        }
    }
}

#[test]
fn expiry_boundary_is_exact_and_expired_tokens_are_refused() {
    let mut state = state();
    let token = issue(&mut state, "a", 100, T0);
    let expires = T0 + 100;
    assert_eq!(
        state.redeem_token(&token, key(), expires).unwrap_err(),
        ServerError::Denied,
        "the expiry instant itself is already too late"
    );
    let token = issue(&mut state, "b", 100, T0);
    assert!(state.redeem_token(&token, key(), expires - 1).is_ok());
}

#[test]
fn replay_with_the_same_key_inside_the_window_is_idempotent_then_refused() {
    let mut state = state();
    let token = issue(&mut state, "laptop", 900, T0);
    let client = key();
    let first = state.redeem_token(&token, client, T0 + 1).unwrap();
    let generation_neutral = state.peers.len();
    let again = state.redeem_token(&token, client, T0 + 30).unwrap();
    assert!(again.replayed);
    assert_eq!(again.peer_id, first.peer_id);
    assert_eq!(state.peers.len(), generation_neutral, "no second peer");
    // Any other key is refused, and so is the same pair once the window has passed.
    assert_eq!(
        state.redeem_token(&token, key(), T0 + 5).unwrap_err(),
        ServerError::Denied
    );
    assert_eq!(
        state
            .redeem_token(&token, client, T0 + 1 + REPLAY_WINDOW + 1)
            .unwrap_err(),
        ServerError::Denied
    );
}

#[test]
fn replay_is_refused_once_the_peer_is_revoked() {
    let mut state = state();
    let token = issue(&mut state, "laptop", 900, T0);
    let client = key();
    state.redeem_token(&token, client, T0 + 1).unwrap();
    state.revoke_peer("laptop", T0 + 2).unwrap();
    assert_eq!(
        state.redeem_token(&token, client, T0 + 3).unwrap_err(),
        ServerError::Denied
    );
}

#[test]
fn revoked_unknown_and_wrong_secret_tokens_are_indistinguishable() {
    let mut state = state();
    let token = issue(&mut state, "a", 900, T0);
    let id = token.id_hex();
    state.revoke_token(&id, T0 + 1).unwrap();
    let revoked = state.redeem_token(&token, key(), T0 + 2).unwrap_err();
    let unknown = state
        .redeem_token(&Token::generate().unwrap(), key(), T0 + 2)
        .unwrap_err();
    // Right id, wrong secret: forge by parsing the id with a different secret.
    let other = Token::generate().unwrap();
    let forged_text = format!("{}{}", &token.expose()[..24], &other.expose()[24..]);
    let forged = Token::parse(&forged_text).unwrap();
    let wrong = state.redeem_token(&forged, key(), T0 + 2).unwrap_err();
    assert_eq!(
        (revoked, unknown, wrong),
        (
            ServerError::Denied,
            ServerError::Denied,
            ServerError::Denied
        )
    );
    assert_eq!(state.active_peers().count(), 0);
    // Only pending tokens can be revoked.
    assert_eq!(
        state.revoke_token(&id, T0 + 3).unwrap_err(),
        ServerError::TokenState
    );
    assert_eq!(
        state.revoke_token("0000000000000000", T0 + 3).unwrap_err(),
        ServerError::TokenNotFound
    );
}

#[test]
fn token_naming_ttl_and_capacity_rules() {
    let mut state = state();
    let token = Token::generate().unwrap();
    assert_eq!(
        state.issue_token(&token, "bad name!", 60, T0).unwrap_err(),
        ServerError::Name
    );
    assert_eq!(
        state.issue_token(&token, "ok", 0, T0).unwrap_err(),
        ServerError::Ttl
    );
    assert_eq!(
        state
            .issue_token(&token, "ok", 24 * 3600 + 1, T0)
            .unwrap_err(),
        ServerError::Ttl
    );
    issue(&mut state, "dup", 60, T0);
    assert_eq!(
        state
            .issue_token(&Token::generate().unwrap(), "dup", 60, T0)
            .unwrap_err(),
        ServerError::DuplicateName,
        "two live tokens must not promise the same name"
    );
    state.create_peer("taken", key(), T0).unwrap();
    assert_eq!(
        state
            .issue_token(&Token::generate().unwrap(), "taken", 60, T0)
            .unwrap_err(),
        ServerError::DuplicateName
    );
    for i in 0..MAX_TOKENS {
        if state.enrollment.tokens.len() >= MAX_TOKENS {
            break;
        }
        let _ = state.issue_token(&Token::generate().unwrap(), &format!("n{i}"), 60, T0);
    }
    assert_eq!(
        state
            .issue_token(&Token::generate().unwrap(), "extra", 60, T0)
            .unwrap_err(),
        ServerError::TokenLimit
    );
}

#[test]
fn clock_moving_backwards_is_refused_not_extended() {
    let mut state = state();
    let token = issue(&mut state, "a", 3600, T0);
    state.redeem_token(&token, key(), T0 + 10).unwrap();
    let back = T0 + 10 - CLOCK_TOLERANCE - 1;
    assert_eq!(
        state
            .issue_token(&Token::generate().unwrap(), "b", 60, back)
            .unwrap_err(),
        ServerError::Clock
    );
    let pending = issue(&mut state, "c", 3600, T0 + 10);
    assert_eq!(
        state.redeem_token(&pending, key(), back).unwrap_err(),
        ServerError::Clock
    );
    // A small backwards step inside the tolerance is accepted.
    assert!(state.redeem_token(&pending, key(), T0 + 10 - 5).is_ok());
}

#[test]
fn pool_exhaustion_and_duplicate_keys_do_not_burn_the_token() {
    let mut state = state();
    let existing = key();
    state.create_peer("old", existing, T0).unwrap();
    let token = issue(&mut state, "new", 900, T0);
    assert_eq!(
        state.redeem_token(&token, existing, T0 + 1).unwrap_err(),
        ServerError::DuplicateKey
    );
    assert!(
        state
            .enrollment
            .tokens
            .iter()
            .any(|t| t.status == TokenStatus::Pending),
        "a refused redemption leaves the token usable with a fresh key"
    );
    assert!(state.redeem_token(&token, key(), T0 + 2).is_ok());
}

#[test]
fn state_without_an_enrollment_section_still_loads_and_bad_ones_do_not() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let path = dir.path().join("state/state.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value.as_object_mut().unwrap().remove("enrollment");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(store.load().unwrap().enrollment.tokens.is_empty());
    value["enrollment"] = serde_json::json!({"tokens": [{
        "id": "zz", "digest": "00", "peer_name": "a", "created_unix": 1,
        "expires_unix": 2, "status": {"state": "pending"}}], "clock_high_water": 0});
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(store.load().unwrap_err(), ServerError::State);
}

#[test]
fn concurrent_redemptions_of_one_token_create_exactly_one_peer() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let token = Arc::new(Token::generate().unwrap());
    store
        .update(None, |s| s.issue_token(&token, "race", 900, T0).map(|_| ()))
        .unwrap();
    let state_dir: PathBuf = dir.path().join("state");
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let token = Arc::clone(&token);
            let state_dir = state_dir.clone();
            thread::spawn(move || {
                let store = Store::open(&state_dir).unwrap();
                let client = key();
                loop {
                    match store.update(None, |s| s.redeem_token(&token, client, T0 + 1)) {
                        Err(ServerError::Busy) => thread::sleep(Duration::from_millis(5)),
                        other => return other.map(|(_, r)| r.replayed),
                    }
                }
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| matches!(r, Ok(false))).count(), 1);
    assert!(
        results
            .iter()
            .filter(|r| r.is_err())
            .all(|r| *r == Err(ServerError::Denied))
    );
    let state = store.load().unwrap();
    assert_eq!(state.active_peers().count(), 1);
}

#[test]
fn crash_before_commit_leaves_the_token_pending_and_after_commit_a_retry_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let token = Token::generate().unwrap();
    store
        .update(None, |s| {
            s.issue_token(&token, "crashy", 900, T0).map(|_| ())
        })
        .unwrap();
    let client = key();
    let crashing = Store::open(&dir.path().join("state"))
        .unwrap()
        .with_crash_before_rename();
    assert!(
        crashing
            .update(None, |s| s.redeem_token(&token, client, T0 + 1))
            .is_err()
    );
    let after_crash = store.load().unwrap();
    assert_eq!(after_crash.peers.len(), 0, "no half-created peer");
    assert_eq!(
        after_crash.enrollment.tokens[0].status,
        TokenStatus::Pending
    );
    // The retry works, and a second retry after the commit is idempotent.
    let (_, first) = store
        .update(None, |s| s.redeem_token(&token, client, T0 + 2))
        .unwrap();
    assert!(!first.replayed);
    let state = store.load().unwrap();
    assert!(state.replayed_peer(&token, &client, T0 + 3).is_some());
}

// ------------------------------------------------------------- pinned TLS listener

struct Listener {
    addr: SocketAddr,
    pin: Pin,
    clock: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    outcomes: std::sync::mpsc::Receiver<Outcome>,
}

impl Listener {
    fn start(state_dir: &Path, applied: bool) -> Self {
        let store = Store::open(state_dir).unwrap();
        let (certificate, _) = store.tls_identity().unwrap();
        let pin = Pin::of_certificate(&certificate);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let clock = Arc::new(AtomicU64::new(T0 + 10));
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, outcomes) = std::sync::mpsc::channel();
        let thread = {
            let (clock, stop) = (Arc::clone(&clock), Arc::clone(&stop));
            let state_dir = state_dir.to_path_buf();
            thread::spawn(move || {
                let store = Store::open(&state_dir).unwrap();
                let tick = Arc::clone(&clock);
                let mut enroller =
                    Enroller::new(store, ExportOptions::default(), Box::new(move |_| applied))
                        .unwrap()
                        .with_clock(Box::new(move || tick.load(Ordering::SeqCst)))
                        .with_deadline(Duration::from_secs(2));
                listener.set_nonblocking(true).unwrap();
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((socket, remote)) => {
                            socket.set_nonblocking(false).unwrap();
                            let _ = tx.send(enroller.handle(socket, remote));
                        }
                        Err(_) => thread::sleep(Duration::from_millis(10)),
                    }
                }
            })
        };
        Self {
            addr,
            pin,
            clock,
            stop,
            thread: Some(thread),
            outcomes,
        }
    }

    fn outcome(&self) -> Outcome {
        self.outcomes.recv_timeout(Duration::from_secs(5)).unwrap()
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn enrol(
    addr: SocketAddr,
    pin: Pin,
    token: &str,
    key: &ClientPublicKey,
) -> Result<proto::Response, EnrollError> {
    let request = proto::encode(&proto::Request::new(token.into(), key.to_string())).unwrap();
    let line = tls::exchange(addr, pin, &request, Duration::from_secs(5))?;
    let response = proto::parse_response(&line)?;
    if response.ok {
        Ok(response)
    } else {
        Err(response.error())
    }
}

fn issue_in(store: &Store, name: &str, ttl: u64) -> Token {
    let token = Token::generate().unwrap();
    store
        .update(None, |s| s.issue_token(&token, name, ttl, T0).map(|_| ()))
        .unwrap();
    token
}

#[test]
fn full_enrollment_over_pinned_tls_returns_a_validating_profile() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let token = issue_in(&store, "laptop", 900);
    let listener = Listener::start(&dir.path().join("state"), true);
    let client = key();
    let response = enrol(listener.addr, listener.pin, &token.expose(), &client).unwrap();
    assert_eq!(listener.outcome(), Outcome::Redeemed);
    assert_eq!(response.applied, Some(true));
    let profile = lovpn_config::parse(response.profile.as_deref().unwrap()).unwrap();
    assert_eq!(
        profile.profile.server_public_key.to_string(),
        response.server_public_key.unwrap()
    );
    assert_eq!(profile.tunnel.addresses[0].to_string(), "10.66.0.2/32");
    let state = store.load().unwrap();
    assert_eq!(
        state.find_active("laptop").unwrap().public_key,
        client.to_string()
    );
    assert_eq!(
        state.find_active("laptop").unwrap().status,
        PeerStatus::Active
    );

    // Lost response: the same token and key get the same profile, no second peer.
    let again = enrol(listener.addr, listener.pin, &token.expose(), &client).unwrap();
    assert_eq!(listener.outcome(), Outcome::Replayed);
    assert_eq!(again.profile, response.profile);
    assert_eq!(store.load().unwrap().peers.len(), 1);

    // Anyone else with the token is refused.
    let error = enrol(listener.addr, listener.pin, &token.expose(), &key()).unwrap_err();
    assert_eq!(error, EnrollError::Denied);
    assert_eq!(listener.outcome(), Outcome::Denied);
    assert_eq!(store.load().unwrap().peers.len(), 1);
}

#[test]
fn a_failed_apply_still_enrolls_but_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let token = issue_in(&store, "laptop", 900);
    let listener = Listener::start(&dir.path().join("state"), false);
    let response = enrol(listener.addr, listener.pin, &token.expose(), &key()).unwrap();
    assert_eq!(response.applied, Some(false));
}

#[test]
fn wrong_pin_aborts_before_the_token_is_sent_and_consumes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let token = issue_in(&store, "laptop", 900);
    let listener = Listener::start(&dir.path().join("state"), true);
    let wrong: Pin = format!("sha256:{}", "ab".repeat(32)).parse().unwrap();
    let error = enrol(listener.addr, wrong, &token.expose(), &key()).unwrap_err();
    assert_eq!(error, EnrollError::PinMismatch);
    assert_eq!(
        listener.outcome(),
        Outcome::HandshakeFailed,
        "the server never saw a request"
    );
    assert_eq!(store.load().unwrap().peers.len(), 0);
    // The genuine pin still works afterwards: the token was not consumed.
    assert!(enrol(listener.addr, listener.pin, &token.expose(), &key()).is_ok());
}

#[test]
fn expired_and_revoked_tokens_get_the_same_denial_over_the_wire() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let expired = issue_in(&store, "a", 5);
    let revoked = issue_in(&store, "b", 900);
    store
        .update(None, |s| s.revoke_token(&revoked.id_hex(), T0))
        .unwrap();
    let listener = Listener::start(&dir.path().join("state"), true);
    listener.clock.store(T0 + 600, Ordering::SeqCst);
    for token in [&expired, &revoked, &Token::generate().unwrap()] {
        assert_eq!(
            enrol(listener.addr, listener.pin, &token.expose(), &key()).unwrap_err(),
            EnrollError::Denied
        );
        assert_eq!(listener.outcome(), Outcome::Denied);
    }
    assert_eq!(store.load().unwrap().peers.len(), 0);
}

#[test]
fn malformed_oversized_and_unknown_field_requests_change_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let token = issue_in(&store, "laptop", 900);
    let listener = Listener::start(&dir.path().join("state"), true);
    let line = |bytes: Vec<u8>| -> Result<proto::Response, EnrollError> {
        let mut bytes = bytes;
        bytes.push(b'\n');
        let line = tls::exchange(listener.addr, listener.pin, &bytes, Duration::from_secs(5))?;
        proto::parse_response(&line)
    };
    let good_key = key().to_string();
    let cases: Vec<Vec<u8>> = vec![
        b"not json".to_vec(),
        vec![b'a'; proto::MAX_REQUEST + 100],
        format!(
            r#"{{"version":1,"token":"{}","client_public_key":"{good_key}","extra":1}}"#,
            token.expose()
        )
        .into_bytes(),
        format!(
            r#"{{"version":9,"token":"{}","client_public_key":"{good_key}"}}"#,
            token.expose()
        )
        .into_bytes(),
        format!(
            r#"{{"version":1,"token":"{}","client_public_key":"not-a-key"}}"#,
            token.expose()
        )
        .into_bytes(),
        vec![0xff, 0xfe, 0x00],
    ];
    for case in cases {
        let response = line(case);
        assert!(!response.is_ok_and(|r| r.ok));
        listener.outcome();
    }
    assert_eq!(store.load().unwrap().peers.len(), 0);
    // Six failures from one source trip its budget; wait out the back-off.
    listener
        .clock
        .fetch_add(lovpn_server::limits::BASE_BLOCK_SECS + 1, Ordering::SeqCst);
    assert!(
        enrol(listener.addr, listener.pin, &token.expose(), &key()).is_ok(),
        "token still usable"
    );
}

#[test]
fn guessing_is_rate_limited_before_tls_and_the_budget_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let token = issue_in(&store, "laptop", 900);
    let state_dir = dir.path().join("state");
    {
        let listener = Listener::start(&state_dir, true);
        let bogus = Token::generate().unwrap().expose();
        for _ in 0..lovpn_server::limits::SOURCE_BUDGET {
            assert_eq!(
                enrol(listener.addr, listener.pin, &bogus, &key()).unwrap_err(),
                EnrollError::Denied
            );
            assert_eq!(listener.outcome(), Outcome::Denied);
        }
        // Even the genuine token is refused now: the connection is dropped pre-TLS.
        let blocked = enrol(listener.addr, listener.pin, &token.expose(), &key());
        assert!(blocked.is_err());
        assert_eq!(listener.outcome(), Outcome::RateLimited);
    }
    // A new process starts with the persisted budget and is still blocked.
    let listener = Listener::start(&state_dir, true);
    assert!(enrol(listener.addr, listener.pin, &token.expose(), &key()).is_err());
    assert_eq!(listener.outcome(), Outcome::RateLimited);
    // After the back-off elapses the legitimate token works.
    listener
        .clock
        .fetch_add(lovpn_server::limits::BASE_BLOCK_SECS + 1, Ordering::SeqCst);
    assert!(enrol(listener.addr, listener.pin, &token.expose(), &key()).is_ok());
    assert_eq!(listener.outcome(), Outcome::Redeemed);
}

#[test]
fn a_stalled_client_cannot_hold_the_listener_past_the_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let _store = store_in(dir.path());
    let listener = Listener::start(&dir.path().join("state"), true);
    let started = std::time::Instant::now();
    let _idle = std::net::TcpStream::connect(listener.addr).unwrap();
    assert_eq!(listener.outcome(), Outcome::HandshakeFailed);
    assert!(started.elapsed() < Duration::from_secs(6));
}

#[test]
fn the_tls_identity_is_never_overwritten_and_needs_safe_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let identity = tls::generate_identity().unwrap();
    assert_eq!(
        store
            .init_tls_identity(&identity.certificate_der, &identity.private_key_der)
            .unwrap_err(),
        ServerError::Exists
    );
    use std::os::unix::fs::PermissionsExt;
    let key_path = dir.path().join("state/enroll-tls.json");
    assert_eq!(
        std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(store.tls_identity().unwrap_err(), ServerError::Permissions);
}

#[test]
fn rotation_switches_a_running_listener_to_the_new_pin_and_keeps_pending_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let token = issue_in(&store, "laptop", 900);
    let listener = Listener::start(&dir.path().join("state"), true);
    let old_pin = listener.pin;

    let fresh = tls::generate_identity().unwrap();
    store
        .rotate_tls_identity(&fresh.certificate_der, &fresh.private_key_der)
        .unwrap();
    let new_pin = Pin::of_certificate(&fresh.certificate_der);
    assert_ne!(new_pin, old_pin);

    // The old pin is now refused (and consumes nothing); the new pin works with the
    // same, still-pending token, without restarting the listener.
    assert_eq!(
        enrol(listener.addr, old_pin, &token.expose(), &key()).unwrap_err(),
        EnrollError::PinMismatch
    );
    assert_eq!(listener.outcome(), Outcome::HandshakeFailed);
    assert!(enrol(listener.addr, new_pin, &token.expose(), &key()).is_ok());
    assert_eq!(listener.outcome(), Outcome::Redeemed);
}

#[test]
fn rotation_needs_an_existing_identity_and_never_leaves_a_mismatched_pair() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    Store::create_dir(&state_dir).unwrap();
    let store = Store::open(&state_dir).unwrap();
    let fresh = tls::generate_identity().unwrap();
    assert_eq!(
        store
            .rotate_tls_identity(&fresh.certificate_der, &fresh.private_key_der)
            .unwrap_err(),
        ServerError::NotFound,
        "rotation is not a way to create the first identity"
    );
    let other = tempfile::tempdir().unwrap();
    let store = store_in(other.path());
    let before = store.tls_identity().unwrap().0;
    let again = tls::generate_identity().unwrap();
    store
        .rotate_tls_identity(&again.certificate_der, &again.private_key_der)
        .unwrap();
    let (certificate, key) = store.tls_identity().unwrap();
    assert_ne!(certificate, before);
    // The stored pair always loads as a consistent TLS configuration.
    assert!(tls::server_config(&certificate, &key).is_ok());
    assert!(
        !other.path().join("state/enroll-tls.json.tmp").exists(),
        "no temporary identity file is left behind"
    );
}
