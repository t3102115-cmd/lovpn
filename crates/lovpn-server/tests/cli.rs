#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(target_os = "linux")]

use lovpn_keys::{ClientPrivateKey, ServerPrivateKey};
use serde_json::Value;
use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
};

fn run(state: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lovpn-server"))
        .arg("--state-dir")
        .arg(state)
        .args(args)
        .output()
        .unwrap()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

const SETUP: &[&str] = &[
    "setup",
    "--endpoint",
    "192.0.2.10:51820",
    "--pool",
    "10.66.0.0/24",
    "--wan-interface",
    "eth0",
    "--dns",
    "10.66.0.1",
    "--json",
];

fn setup_args(mode: &'static str) -> Vec<&'static str> {
    let mut args = SETUP.to_vec();
    args.insert(1, mode);
    args
}

/// Generate a client key whose public half does not resemble a private key, so the
/// flow tests are deterministic (1 in 16 genuine keys would need --confirm-public-key).
fn plain_client() -> ClientPrivateKey {
    loop {
        let key = ClientPrivateKey::generate().unwrap();
        if !key.public_key().resembles_clamped_private_key() {
            return key;
        }
    }
}

fn tmp() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[test]
fn dry_run_writes_nothing_and_prints_no_key() {
    let dir = tmp();
    let state = dir.path().join("state");
    let output = run(&state, &setup_args("--dry-run"));
    assert!(output.status.success(), "{}", text(&output));
    assert!(
        !state.exists(),
        "dry run must not create the state directory"
    );
    let data: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        (data["dry_run"].clone(), data["system_changed"].clone()),
        (true.into(), false.into())
    );
    // Choosing neither mode is refused rather than guessed.
    let output = run(&state, &SETUP[..SETUP.len() - 1]);
    assert!(!output.status.success());
    assert!(!state.exists());
}

#[test]
fn offline_enrollment_flow_end_to_end() {
    let dir = tmp();
    let state = dir.path().join("state");
    let out = run(&state, &setup_args("--write-state"));
    assert!(out.status.success(), "{}", text(&out));
    let server: Value = serde_json::from_slice(&out.stdout).unwrap();
    let server_public = server["server_public_key"].as_str().unwrap().to_string();
    let server_secret = std::fs::read_to_string(state.join("server.key")).unwrap();
    let server_secret = server_secret.trim();
    assert!(ServerPrivateKey::from_base64(server_secret).is_ok());
    assert!(!text(&out).contains(server_secret));

    // Second setup cannot overwrite the identity.
    let again = run(&state, &setup_args("--write-state"));
    assert!(!again.status.success());
    assert!(!text(&again).contains(server_secret));
    assert_eq!(
        std::fs::read_to_string(state.join("server.key"))
            .unwrap()
            .trim(),
        server_secret
    );

    // Client generates keys locally; only the public key reaches the server.
    let client = plain_client();
    let client_secret = client.expose_base64().to_string();
    let client_public = client.public_key().to_string();
    let out = run(
        &state,
        &[
            "peer",
            "create",
            "--name",
            "laptop",
            "--public-key",
            &client_public,
            "--json",
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(!text(&out).contains(&client_secret));

    // Passing a PRIVATE key as the public key must fail without echoing it.
    let bad = run(
        &state,
        &[
            "peer",
            "create",
            "--name",
            "oops",
            "--public-key",
            &client_secret,
        ],
    );
    assert!(!bad.status.success());
    assert!(
        !text(&bad).contains(&client_secret),
        "secret echoed in error output"
    );

    let profile = run(&state, &["peer", "export", "laptop"]);
    assert!(profile.status.success(), "{}", text(&profile));
    let profile = String::from_utf8(profile.stdout).unwrap();
    let parsed = lovpn_config::parse(&profile).unwrap();
    assert_eq!(parsed.profile.server_public_key, server_public);
    assert_eq!(parsed.tunnel.addresses[0].to_string(), "10.66.0.2/32");
    assert!(!profile.contains(&client_secret) && !profile.contains(server_secret));

    let list = run(&state, &["peer", "list", "--json"]);
    let list: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(list["peers"][0]["status"], "active");

    let rules = run(&state, &["firewall", "show"]);
    assert!(text(&rules).contains("ip saddr != { 10.66.0.2 }"));

    // Stale generation refusal, then revoke.
    let stale = run(
        &state,
        &["peer", "revoke", "laptop", "--expected-generation", "1"],
    );
    assert!(!stale.status.success());
    let revoke = run(&state, &["peer", "revoke", "laptop", "--json"]);
    let revoke: Value = serde_json::from_slice(&revoke.stdout).unwrap();
    assert_eq!(
        revoke["enforced"], false,
        "revocation must not claim enforcement"
    );
    assert!(!run(&state, &["peer", "export", "laptop"]).status.success());
    assert!(
        text(&run(&state, &["firewall", "show"])).contains("iifname \"lovpn-srv0\" counter drop")
    );

    // Honest status: nothing observed, nothing protected.
    let status = run(&state, &["status", "--json"]);
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["protection"], "not-verified");
    assert!(
        status["host"].is_null(),
        "host is only observed with --live and a broker"
    );
    let diag = text(&run(&state, &["diagnostics"]));
    assert!(!diag.contains(server_secret) && !diag.contains(&client_secret));

    // Repair is refused; reset only plans.
    // Without a broker, apply/repair/live status/teardown fail clearly and change nothing.
    let nobroker = ["--socket", "/nonexistent/lovpn-broker.sock"];
    for args in [
        vec!["firewall", "repair"],
        vec!["apply"],
        vec!["status", "--live"],
        vec!["teardown", "--yes"],
    ] {
        let mut full = nobroker.to_vec();
        full.extend(args);
        let output = run(&state, &full);
        assert!(!output.status.success());
        assert!(
            text(&output).contains("broker.unreachable"),
            "{}",
            text(&output)
        );
    }
    let unconfirmed = run(&state, &["teardown"]);
    assert!(text(&unconfirmed).contains("teardown.confirm"));
    assert!(!run(&state, &["reset"]).status.success());
    assert!(run(&state, &["reset", "--plan"]).status.success());
    assert!(state.join("server.key").exists());
}

#[test]
fn export_to_file_never_overwrites() {
    let dir = tmp();
    let state = dir.path().join("state");
    assert!(run(&state, &setup_args("--write-state")).status.success());
    let key = ClientPrivateKey::generate()
        .unwrap()
        .public_key()
        .to_string();
    assert!(
        run(
            &state,
            &["peer", "create", "--name", "a", "--public-key", &key]
        )
        .status
        .success()
    );
    let target = dir.path().join("a.toml");
    assert!(
        run(
            &state,
            &["peer", "export", "a", "--output", target.to_str().unwrap()]
        )
        .status
        .success()
    );
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let before = std::fs::read(&target).unwrap();
    assert!(
        !run(
            &state,
            &[
                "peer",
                "export",
                "a",
                "--output",
                target.to_str().unwrap(),
                "--kill-switch",
                "off"
            ]
        )
        .status
        .success()
    );
    assert_eq!(std::fs::read(&target).unwrap(), before);
}

#[test]
fn private_looking_public_key_needs_explicit_confirmation() {
    let dir = tmp();
    let state = dir.path().join("state");
    assert!(run(&state, &setup_args("--write-state")).status.success());
    // Find a genuine key pair whose public half has the clamped shape (about 1 in 16).
    let key = loop {
        let key = ClientPrivateKey::generate().unwrap();
        if key.public_key().resembles_clamped_private_key() {
            break key.public_key().to_string();
        }
    };
    let refused = run(
        &state,
        &["peer", "create", "--name", "odd", "--public-key", &key],
    );
    assert!(!refused.status.success());
    let allowed = run(
        &state,
        &[
            "peer",
            "create",
            "--name",
            "odd",
            "--public-key",
            &key,
            "--confirm-public-key",
        ],
    );
    assert!(allowed.status.success(), "{}", text(&allowed));
}
