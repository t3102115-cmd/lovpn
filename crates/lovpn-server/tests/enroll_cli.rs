#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(target_os = "linux")]
//! `lovpn-server enroll …` as a real process: token handling, the listener, and that
//! no secret reaches output, logs or disk.

use lovpn_enroll::{
    proto,
    tls::{self, Pin},
};
use lovpn_keys::ClientPrivateKey;
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Read},
    net::{SocketAddr, TcpListener},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Output, Stdio},
    time::Duration,
};

fn run(state: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lovpn-server"))
        .arg("--state-dir")
        .arg(state)
        .args(args)
        .output()
        .unwrap()
}

fn all_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn json(output: &Output) -> Value {
    assert!(output.status.success(), "{}", all_text(output));
    serde_json::from_slice(&output.stdout).unwrap()
}

fn init(dir: &Path) -> std::path::PathBuf {
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = dir.join("state");
    let out = run(
        &state,
        &[
            "setup",
            "--write-state",
            "--endpoint",
            "192.0.2.10:51820",
            "--pool",
            "10.66.0.0/24",
            "--wan-interface",
            "eth0",
            "--dns",
            "10.66.0.1",
            "--json",
        ],
    );
    assert!(out.status.success(), "{}", all_text(&out));
    state
}

#[test]
fn identity_and_token_commands_never_reprint_or_store_the_token() {
    let dir = tempfile::tempdir().unwrap();
    let state = init(dir.path());

    // No token without an identity: the pin could not be shown.
    let early = run(
        &state,
        &["--json", "enroll", "token", "create", "--name", "x"],
    );
    assert!(!early.status.success());
    assert!(all_text(&early).contains("enroll.no-identity"));

    let made = json(&run(&state, &["--json", "enroll", "tls-init"]));
    let pin = made["pin"].as_str().unwrap().to_string();
    assert!(pin.parse::<Pin>().is_ok());
    let again = run(&state, &["--json", "enroll", "tls-init"]);
    assert!(
        !again.status.success(),
        "the identity must never be replaced"
    );
    assert_eq!(json(&run(&state, &["--json", "enroll", "pin"]))["pin"], pin);
    let mode = std::fs::metadata(state.join("enroll-tls.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    let token = json(&run(
        &state,
        &[
            "--json",
            "enroll",
            "token",
            "create",
            "--name",
            "laptop",
            "--ttl-minutes",
            "5",
        ],
    ));
    let text = token["token"].as_str().unwrap().to_string();
    let id = token["token_id"].as_str().unwrap().to_string();
    assert_eq!(token["pin"], pin);
    let secret = text.splitn(3, '-').nth(2).unwrap().to_string();

    // Listing shows ids and states, never the token, its secret or its digest.
    for args in [
        &["--json", "enroll", "token", "list"][..],
        &["enroll", "token", "list"][..],
    ] {
        let listing = run(&state, args);
        assert!(listing.status.success());
        let shown = all_text(&listing);
        assert!(shown.contains(&id) && shown.contains("pending"));
        assert!(!shown.contains(&secret) && !shown.contains(&text) && !shown.contains("digest"));
    }
    // Nothing on disk holds the secret.
    for entry in std::fs::read_dir(&state).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap_or_default();
        assert!(!String::from_utf8_lossy(&bytes).contains(&secret));
    }

    for bad in ["0", "1441", "x"] {
        let out = run(
            &state,
            &[
                "enroll",
                "token",
                "create",
                "--name",
                "n",
                "--ttl-minutes",
                bad,
            ],
        );
        assert!(!out.status.success(), "ttl {bad}");
    }
    let dup = run(&state, &["enroll", "token", "create", "--name", "laptop"]);
    assert!(
        !dup.status.success(),
        "a second live token for the same name"
    );

    assert!(
        run(&state, &["enroll", "token", "revoke", &id])
            .status
            .success()
    );
    assert!(
        !run(&state, &["enroll", "token", "revoke", &id])
            .status
            .success()
    );
    assert!(
        !run(&state, &["enroll", "token", "revoke", "0000000000000000"])
            .status
            .success()
    );
}

struct Server {
    child: Child,
    stderr: std::sync::mpsc::Receiver<String>,
    addr: SocketAddr,
    pin: Pin,
}

impl Server {
    fn start(state: &Path) -> Self {
        let pin: Pin = json(&run(state, &["--json", "enroll", "pin"]))["pin"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let addr = {
            let probe = TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap()
        };
        let mut child = Command::new(env!("CARGO_BIN_EXE_lovpn-server"))
            .arg("--state-dir")
            .arg(state)
            .args([
                "enroll",
                "serve",
                "--no-apply",
                "--listen",
                &addr.to_string(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
        let first = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(first.contains("enroll-listening"), "{first}");
        Self {
            child,
            stderr: rx,
            addr,
            pin,
        }
    }

    fn enroll(&self, token: &str, key: &str) -> Result<proto::Response, lovpn_enroll::EnrollError> {
        let request = proto::encode(&proto::Request::new(token.into(), key.into())).unwrap();
        let line = tls::exchange(self.addr, self.pin, &request, Duration::from_secs(8))?;
        let response = proto::parse_response(&line)?;
        if response.ok {
            Ok(response)
        } else {
            Err(response.error())
        }
    }

    fn finish(mut self) -> (String, String) {
        std::thread::sleep(Duration::from_millis(150));
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut stdout = String::new();
        if let Some(mut out) = self.child.stdout.take() {
            let _ = out.read_to_string(&mut stdout);
        }
        let logs: Vec<String> = self.stderr.try_iter().collect();
        (stdout, logs.join("\n"))
    }
}

#[test]
fn the_listener_process_enrolls_a_client_and_leaks_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let state = init(dir.path());
    json(&run(&state, &["--json", "enroll", "tls-init"]));
    let token = json(&run(
        &state,
        &["--json", "enroll", "token", "create", "--name", "laptop"],
    ));
    let text = token["token"].as_str().unwrap().to_string();
    let secret = text.splitn(3, '-').nth(2).unwrap().to_string();
    let id = token["token_id"].as_str().unwrap().to_string();
    let server = Server::start(&state);

    let wrong = lovpn_enroll::token::Token::generate().unwrap().expose();
    let wrong_secret = wrong.splitn(3, '-').nth(2).unwrap().to_string();
    let client = ClientPrivateKey::generate()
        .unwrap()
        .public_key()
        .to_string();
    assert_eq!(
        server.enroll(&wrong, &client).unwrap_err(),
        lovpn_enroll::EnrollError::Denied
    );
    let response = server.enroll(&text, &client).unwrap();
    assert_eq!(
        response.applied,
        Some(false),
        "--no-apply never claims it applied"
    );
    assert!(lovpn_config::parse(response.profile.as_deref().unwrap()).is_ok());
    let other = ClientPrivateKey::generate()
        .unwrap()
        .public_key()
        .to_string();
    assert_eq!(
        server.enroll(&text, &other).unwrap_err(),
        lovpn_enroll::EnrollError::Denied
    );

    let (stdout, logs) = server.finish();
    for secret_text in [&text, &secret, &wrong, &wrong_secret] {
        assert!(
            !logs.contains(secret_text.as_str()),
            "token leaked into the log: {logs}"
        );
        assert!(!stdout.contains(secret_text.as_str()));
    }
    assert!(
        !logs.contains(&client) && !logs.contains(&other),
        "client keys must not be logged"
    );
    assert!(
        !logs.contains("127.0.0.1"),
        "client addresses must not be logged"
    );
    assert!(logs.contains("\"outcome\":\"redeemed\"") && logs.contains("\"outcome\":\"denied\""));
    assert!(
        logs.contains(&id),
        "the token id is the intended handle in logs"
    );

    // The peer exists, and the token is shown as redeemed.
    let peers = json(&run(&state, &["--json", "peer", "list"]));
    assert!(peers.to_string().contains("laptop"));
    let list = run(&state, &["enroll", "token", "list"]);
    assert!(all_text(&list).contains("redeemed"));
}

#[test]
fn a_wrong_pin_never_reaches_the_server_process() {
    let dir = tempfile::tempdir().unwrap();
    let state = init(dir.path());
    json(&run(&state, &["--json", "enroll", "tls-init"]));
    let token = json(&run(
        &state,
        &["--json", "enroll", "token", "create", "--name", "laptop"],
    ));
    let text = token["token"].as_str().unwrap().to_string();
    let mut server = Server::start(&state);
    server.pin = format!("sha256:{}", "cd".repeat(32)).parse().unwrap();
    let key = ClientPrivateKey::generate()
        .unwrap()
        .public_key()
        .to_string();
    assert_eq!(
        server.enroll(&text, &key).unwrap_err(),
        lovpn_enroll::EnrollError::PinMismatch
    );
    let (_, logs) = server.finish();
    assert!(
        !logs.contains("\"outcome\":\"redeemed\"") && !logs.contains("\"outcome\":\"denied\""),
        "{logs}"
    );
    assert!(!logs.contains(&text));
    let list = json(&run(&state, &["--json", "peer", "list"]));
    assert!(!list.to_string().contains("laptop"));
}
