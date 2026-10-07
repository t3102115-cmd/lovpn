#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Fake, Lab, profile_text};
use lovpn_client::{
    Engine,
    broker::{self, Broker, BrokerConfig, BrokerError, Response},
};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        net::UnixStream,
    },
    path::PathBuf,
    process::Command,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

struct Fixture {
    dir: tempfile::TempDir,
    fake: Fake,
    engine: Arc<Mutex<Engine>>,
    server_public: String,
    client_private: String,
}

impl Fixture {
    fn new() -> Self {
        let lab = Lab::new();
        Self {
            dir: lab.dir,
            fake: lab.fake,
            engine: Arc::new(Mutex::new(lab.engine)),
            server_public: lab.server_public,
            client_private: lab.client_private,
        }
    }

    fn config(&self, owner_uid: u32) -> BrokerConfig {
        BrokerConfig {
            socket: self.dir.path().join("broker.sock"),
            owner_uid,
        }
    }

    fn start(&self, owner_uid: u32, requests: usize) -> (PathBuf, JoinHandle<()>) {
        let config = self.config(owner_uid);
        let socket = config.socket.clone();
        let service = Broker::bind(config, Arc::clone(&self.engine)).unwrap();
        let handle = thread::spawn(move || {
            for _ in 0..requests {
                service.serve_one();
            }
        });
        (socket, handle)
    }

    fn import_request(&self) -> Value {
        json!({"op": "import-profile", "name": "laptop",
            "profile": profile_text(&self.server_public, "strict", ""),
            "private_key": self.client_private, "expected_server_key": self.server_public})
    }
}

fn me() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn ask(socket: &std::path::Path, request: Value) -> Response {
    broker::call(socket, &request, Duration::from_secs(10)).unwrap()
}

fn raw(socket: &std::path::Path, bytes: &[u8]) -> Response {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(bytes).unwrap();
    let mut reply = Vec::new();
    BufReader::new(stream)
        .read_until(b'\n', &mut reply)
        .unwrap();
    serde_json::from_slice(&reply).unwrap()
}

#[test]
fn socket_permissions_and_non_owner_denial_prevent_dispatch() {
    // Root is deliberately authorized. This case exercises kernel peer credentials
    // as an ordinary user, without changing identity or requiring privileges.
    if me() == 0 {
        return;
    }
    let fixture = Fixture::new();
    let requests = [
        json!({"op":"ping"}),
        fixture.import_request(),
        json!({"op":"status"}),
        json!({"op":"disconnect", "release":true}),
        json!({"op":"reset"}),
    ];
    let (socket, handle) = fixture.start(me() + 1, requests.len());
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    for request in requests {
        let response = ask(&socket, request);
        assert!(!response.ok);
        assert_eq!(response.code, "auth.denied");
        assert!(response.data.is_null());
    }
    handle.join().unwrap();
    assert!(fixture.fake.host().log.is_empty());
    assert_eq!(
        fixture
            .engine
            .lock()
            .unwrap()
            .list_profiles()
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn malformed_oversized_unknown_and_extra_fields_are_rejected() {
    let fixture = Fixture::new();
    let (socket, handle) = fixture.start(me(), 6);
    let mut oversized = vec![b' '; broker::MAX_REQUEST_BYTES as usize];
    oversized.push(b'\n');
    assert_eq!(raw(&socket, &oversized).code, "request.too-large");
    for request in [
        b"not json\n".as_slice(),
        b"{\"op\":\"format-disk\"}\n",
        b"{\"op\":\"connect\",\"command\":\"unexpected\"}\n",
        b"{\"op\":\"import-profile\",\"name\":\"laptop\"}\n",
    ] {
        let response = raw(&socket, request);
        assert!(!response.ok);
        assert_eq!(response.code, "request.malformed");
        assert!(response.data.is_null());
    }
    // Rejection must leave the service able to accept the next connection.
    assert_eq!(
        ask(&socket, json!({"op":"ping"})).data,
        json!({"pong":true})
    );
    handle.join().unwrap();
    assert!(fixture.fake.host().log.is_empty());
}

#[test]
fn empty_connection_times_out_and_next_connection_succeeds() {
    let fixture = Fixture::new();
    let (socket, handle) = fixture.start(me(), 2);
    let start = Instant::now();
    let response = raw(&socket, b""); // Keep the write side open; do not fake EOF.
    assert_eq!(response.code, "request.io");
    assert!(!response.ok);
    assert!(start.elapsed() >= lovpn_sys::ipc::IO_TIMEOUT);
    assert!(start.elapsed() < Duration::from_secs(10));
    assert!(ask(&socket, json!({"op":"ping"})).ok);
    handle.join().unwrap();
    assert!(fixture.fake.host().log.is_empty());
}

#[test]
fn double_bind_refuses_live_socket_without_replacing_it() {
    let fixture = Fixture::new();
    let service = Broker::bind(fixture.config(me()), Arc::clone(&fixture.engine)).unwrap();
    assert_eq!(
        Broker::bind(fixture.config(me()), Arc::clone(&fixture.engine)).err(),
        Some(BrokerError::AlreadyRunning)
    );
    // The liveness probe is itself a connection. Consume it, then verify that the
    // original listener, not a replacement, still serves the pathname.
    let handle = thread::spawn(move || {
        service.serve_one();
        service.serve_one();
    });
    assert!(ask(&fixture.config(me()).socket, json!({"op":"ping"})).ok);
    handle.join().unwrap();
}

#[test]
fn import_over_socket_never_echoes_or_logs_secrets() {
    const CHILD_REQUEST: &str = "LOVPN_BROKER_TEST_REQUEST";
    if let Some(path) = std::env::var_os(CHILD_REQUEST) {
        let request: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let secret = request["private_key"].as_str().unwrap();
        let fixture = Fixture::new();
        let (socket, handle) = fixture.start(me(), 6);
        let imported = ask(&socket, request.clone());
        assert!(imported.ok);
        assert_eq!(imported.data["profile"]["name"], "laptop");
        let listed = ask(&socket, json!({"op":"list-profiles"}));
        assert!(listed.ok);
        assert_eq!(listed.data["profiles"].as_array().unwrap().len(), 1);
        let public = ask(&socket, json!({"op":"public-key", "name":"laptop"}));
        assert!(public.ok);
        let expected = lovpn_keys::ClientPrivateKey::from_base64(secret)
            .unwrap()
            .public_key()
            .to_string();
        assert_eq!(public.data["public_key"], expected);
        let status = ask(&socket, json!({"op":"status"}));
        assert!(status.ok);
        let mut invalid = request.clone();
        invalid["private_key"] = json!(format!("invalid-{secret}"));
        let failed = ask(&socket, invalid);
        assert!(!failed.ok);
        let mut extra = request.clone();
        extra["unexpected"] = json!(secret);
        let rejected = ask(&socket, extra);
        assert_eq!(rejected.code, "request.malformed");
        for response in [imported, listed, public, status, failed, rejected] {
            assert!(!serde_json::to_string(&response).unwrap().contains(secret));
        }
        handle.join().unwrap();
        assert!(fixture.fake.mutating().is_empty());
        assert!(
            fixture
                .fake
                .host()
                .log
                .iter()
                .all(|line| !line.contains(secret))
        );
        return;
    }

    // Capture the actual broker stderr in a subprocess, avoiding global stderr
    // redirection and interference with parallel tests. All keys are synthetic.
    let fixture = Fixture::new();
    let path = fixture.dir.path().join("synthetic-request.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(&serde_json::to_vec(&fixture.import_request()).unwrap())
        .unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "import_over_socket_never_echoes_or_logs_secrets",
            "--nocapture",
        ])
        .env(CHILD_REQUEST, path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&fixture.client_private));
    let logs = String::from_utf8(output.stderr).unwrap();
    assert!(!logs.contains(&fixture.client_private));
    let events: Vec<Value> = logs
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 6);
    for event in &events {
        let fields = event.as_object().unwrap();
        assert_eq!(fields.len(), 5);
        assert!(
            fields
                .keys()
                .all(|key| ["ts", "event", "op", "uid", "code"].contains(&key.as_str()))
        );
    }
    assert_eq!(events[0]["op"], "import-profile");
    assert_eq!(events[0]["code"], "ok");
    assert_eq!(events[5]["event"], "request-rejected");
}

#[test]
fn resume_requires_wall_clock_to_exceed_monotonic_plus_slack() {
    let seconds = Duration::from_secs;
    assert!(!broker::detect_resume(
        seconds(20),
        seconds(20),
        seconds(10)
    ));
    assert!(!broker::detect_resume(
        seconds(30),
        seconds(20),
        seconds(10)
    ));
    assert!(broker::detect_resume(seconds(31), seconds(20), seconds(10)));
    assert!(!broker::detect_resume(seconds(5), seconds(20), seconds(10)));
    assert!(!broker::detect_resume(
        Duration::ZERO,
        Duration::ZERO,
        Duration::ZERO
    ));
    assert!(broker::detect_resume(
        Duration::from_nanos(1),
        Duration::ZERO,
        Duration::ZERO
    ));
}
