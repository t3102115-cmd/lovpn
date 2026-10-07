#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;
use std::{
    io::Write,
    process::{Command, Output},
};
use tempfile::NamedTempFile;

const SAMPLE: &str = include_str!("../../../examples/client.toml");
const SAMPLE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/client.toml");

/// Tests never reach a real service: the socket is pinned to a path that cannot exist.
const NO_SERVICE: &str = "/nonexistent/lovpn-test/broker.sock";

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lovpn"))
        .arg("--socket")
        .arg(NO_SERVICE)
        .args(args)
        .output()
        .unwrap()
}

fn fixture(text: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(text.as_bytes()).unwrap();
    file.flush().unwrap();
    file
}

#[test]
fn public_validation_has_no_security_claims() {
    let output = cli(&["config", "validate", SAMPLE_PATH, "--json"]);
    assert!(output.status.success());
    let data: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(data["configuration_valid"], true);
    assert_eq!(data["system_changed"], false);
    assert_eq!(data["protection"], "not-verified");
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("192.0.2.1")
    );
}

#[test]
fn sanitized_reports_never_report_protected_or_probe() {
    for args in [
        vec!["status"],
        vec!["diagnostics"],
        vec!["firewall", "status"],
    ] {
        let mut args = args;
        args.push("--json");
        let output = cli(&args);
        assert!(output.status.success());
        let data: Value = serde_json::from_slice(&output.stdout).unwrap();
        for key in ["ipv4", "ipv6", "dns", "kill_switch"] {
            assert_eq!(data[key], "not-verified");
        }
        assert_eq!(data["host_state_inspected"], false);
    }
}

#[test]
fn privacy_lists_no_runtime_connections_and_explicit_scope() {
    let output = cli(&["--json", "privacy"]);
    assert!(output.status.success());
    let data: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(data["telemetry"], false);
    assert_eq!(data["account_required"], false);
    assert_eq!(data["network_connections"], serde_json::json!([]));
    assert!(data["scope"].as_str().unwrap().contains("offline CLI"));
}

#[test]
fn parser_errors_are_structured_and_do_not_echo_secrets_or_paths() {
    let file = fixture(&format!(
        "{SAMPLE}\nprivate_key = \"SECRET_SHOULD_NEVER_APPEAR\""
    ));
    let path = file.path().to_str().unwrap();
    let output = cli(&["--json", "config", "validate", path]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(!error.contains("SECRET_SHOULD_NEVER_APPEAR"));
    assert!(!error.contains(path));
    let data: Value = serde_json::from_str(&error).unwrap();
    assert_eq!(data["error"]["code"], "config.syntax");
}

#[test]
fn missing_directory_oversized_and_non_utf8_input_are_rejected() {
    let missing = cli(&["config", "validate", "no-such-lovpn-profile.toml"]);
    assert_eq!(missing.status.code(), Some(1));
    let directory = tempfile::tempdir().unwrap();
    assert_eq!(
        cli(&["config", "validate", directory.path().to_str().unwrap()])
            .status
            .code(),
        Some(1)
    );
    let huge = fixture(&"x".repeat(lovpn_config::MAX_CONFIG_BYTES + 1));
    let output = cli(&[
        "config",
        "validate",
        huge.path().to_str().unwrap(),
        "--json",
    ]);
    let data: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(data["error"]["code"], "config.too-large");
    let mut invalid = NamedTempFile::new().unwrap();
    invalid.write_all(&[0xff, 0xfe, 0xfd]).unwrap();
    let output = cli(&[
        "config",
        "validate",
        invalid.path().to_str().unwrap(),
        "--json",
    ]);
    let data: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(data["error"]["code"], "config.encoding");
}

#[test]
fn firewall_preview_and_validate_do_not_claim_installation() {
    let output = cli(&["firewall", "show", SAMPLE_PATH, "--json"]);
    assert!(output.status.success());
    let data: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(data["installed"], false);
    assert_eq!(data["kernel_validated"], false);
    assert!(data["ruleset"].as_str().unwrap().contains("policy drop"));
    let output = cli(&["firewall", "validate", SAMPLE_PATH, "--json"]);
    assert!(output.status.success());
    let data: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(data["compiler_valid"], true);
    assert_eq!(data["kernel_validated"], false);
    let output = cli(&["firewall", "show", SAMPLE_PATH, "--reset-preview"]);
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("delete table inet lovpn_client")
    );
}

#[test]
fn unsupported_protection_is_an_error_not_success() {
    let file = fixture(&SAMPLE.replace("kill_switch = \"strict\"", "kill_switch = \"off\""));
    let output = cli(&["firewall", "show", file.path().to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(1));
    let data: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(data["error"]["code"], "firewall.disabled");
}

#[cfg(unix)]
#[test]
fn client_commands_fail_clearly_without_the_service_and_change_nothing() {
    for args in [
        vec!["connect"],
        vec!["disconnect"],
        vec!["reconnect"],
        vec!["repair"],
        vec!["reset"],
        vec!["profile", "list"],
        vec!["profile", "remove", "home"],
    ] {
        let mut args = args;
        args.push("--json");
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        let data: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(data["error"]["code"], "service.unreachable", "{args:?}");
    }
    // Status degrades honestly instead of failing or inventing a state.
    let output = cli(&["status", "--json"]);
    assert!(output.status.success());
    let data: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(data["service"], "not-running");
    assert_eq!(data["host_state_inspected"], false);
}

#[cfg(unix)]
#[test]
fn symlinks_fifos_and_group_writable_files_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = tempfile::tempdir().unwrap();
    let target = fixture(SAMPLE);
    let link = directory.path().join("symlink.toml");
    symlink(target.path(), &link).unwrap();
    assert_eq!(
        cli(&["config", "validate", link.to_str().unwrap()])
            .status
            .code(),
        Some(1)
    );
    let fifo = directory.path().join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    assert_eq!(
        cli(&["config", "validate", fifo.to_str().unwrap()])
            .status
            .code(),
        Some(1)
    );
    std::fs::set_permissions(target.path(), std::fs::Permissions::from_mode(0o666)).unwrap();
    let output = cli(&[
        "config",
        "validate",
        target.path().to_str().unwrap(),
        "--json",
    ]);
    let data: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(data["error"]["code"], "config.permissions");
}

#[cfg(unix)]
#[test]
fn identity_generate_keeps_private_key_in_a_new_private_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key_file = dir.path().join("client.key");
    let path = key_file.to_str().unwrap();
    let output = cli(&["identity", "generate", "--key-file", path, "--json"]);
    assert!(output.status.success());
    let data: Value = serde_json::from_slice(&output.stdout).unwrap();
    let public = data["public_key"].as_str().unwrap().to_string();
    let secret = std::fs::read_to_string(&key_file).unwrap();
    let secret = secret.trim();
    assert_eq!(public.len(), 44);
    assert_ne!(public, secret);
    assert_eq!(
        std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let everything = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    assert!(!everything.contains(secret) && !everything.contains(path));

    let shown = cli(&["identity", "public", "--key-file", path]);
    assert_eq!(String::from_utf8(shown.stdout).unwrap().trim(), public);

    // Never overwrites an existing identity.
    let again = cli(&["identity", "generate", "--key-file", path]);
    assert!(!again.status.success());
    assert_eq!(std::fs::read_to_string(&key_file).unwrap().trim(), secret);
    let stderr = String::from_utf8_lossy(&again.stderr).to_string();
    assert!(!stderr.contains(secret) && !stderr.contains(path));
}

#[cfg(unix)]
#[test]
fn enroll_refuses_bad_input_before_any_network_use_and_never_echoes_the_token() {
    let dir = tempfile::tempdir().unwrap();
    let pin = format!("sha256:{}", "0".repeat(64));
    let key = dir.path().join("client.key");
    let key = key.to_str().unwrap();
    let write = |name: &str, text: &str| {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        path.to_str().unwrap().to_string()
    };
    let junk = write("junk.token", "lovpn1-this-is-not-a-real-token\n");
    // 192.0.2.1 is reserved documentation space: nothing here may even try to connect.
    let base = |extra: &[&str]| {
        let mut args = vec![
            "--json",
            "enroll",
            "--server",
            "192.0.2.1:51821",
            "--name",
            "home",
        ];
        args.extend_from_slice(extra);
        cli(&args)
    };
    let code = |output: &Output| -> String {
        let data: Value = serde_json::from_slice(&output.stderr).unwrap();
        data["error"]["code"].as_str().unwrap().to_string()
    };

    let bad_pin = base(&[
        "--pin",
        "sha256:zz",
        "--token-file",
        &junk,
        "--key-file",
        key,
        "--generate-key",
    ]);
    assert_eq!(code(&bad_pin), "enroll.pin-format");
    let bad_token = base(&[
        "--pin",
        &pin,
        "--token-file",
        &junk,
        "--key-file",
        key,
        "--generate-key",
    ]);
    assert_eq!(code(&bad_token), "enroll.token-format");
    let shown = String::from_utf8_lossy(&bad_token.stderr);
    assert!(
        !shown.contains("this-is-not-a-real-token"),
        "the token must not be echoed"
    );
    assert!(
        !std::path::Path::new(key).exists(),
        "no key is created before the token is valid"
    );

    // The token is never accepted on the command line.
    let argv = base(&["--pin", &pin, "--token", "lovpn1-x", "--key-file", key]);
    assert_eq!(argv.status.code(), Some(2), "unknown flag --token");

    // A missing key file needs an explicit --generate-key (checked with a valid token).
    let valid = lovpn_enroll::token::Token::generate().unwrap().expose();
    let token_file = write("ok.token", &valid);
    let missing = base(&[
        "--pin",
        &pin,
        "--token-file",
        &token_file,
        "--key-file",
        key,
    ]);
    assert_eq!(code(&missing), "enroll.key-missing");
    assert!(!std::path::Path::new(key).exists());
}
