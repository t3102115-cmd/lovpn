#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;
use std::{
    io::Write,
    process::{Command, Output},
};
use tempfile::NamedTempFile;

const SAMPLE: &str = include_str!("../../../examples/client.toml");
const SAMPLE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/client.toml");

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lovpn"))
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

#[test]
fn missing_connect_backend_is_not_a_fake_command() {
    assert_eq!(cli(&["connect"]).status.code(), Some(2));
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
