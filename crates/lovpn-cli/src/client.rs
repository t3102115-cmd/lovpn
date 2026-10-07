//! Unprivileged client commands. They never change the machine themselves: they ask the
//! LoVPN service (`lovpn-clientd`) over its local socket and render what it observed.
use crate::{AppError, Report, input, reports};
#[cfg(unix)]
use lovpn_keys::file as key_file;
#[cfg(unix)]
use lovpn_sys::ipc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
const LONG: Duration = Duration::from_secs(60);
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;

#[derive(Deserialize)]
struct Response {
    ok: bool,
    code: String,
    message: String,
    #[serde(default)]
    data: Value,
}

fn unreachable_error() -> AppError {
    AppError::new(
        "service.unreachable",
        "The LoVPN service is not running, or you are not allowed to use it. Start lovpn-clientd (see docs/client.md). Nothing was changed.",
    )
}

#[cfg(unix)]
fn transport<Q: Serialize>(socket: &Path, request: &Q) -> Result<Response, ()> {
    ipc::call(socket, request, LONG, MAX_RESPONSE_BYTES).map_err(|_| ())
}

/// One request line over the service's named pipe, one response line back.
#[cfg(windows)]
fn transport<Q: Serialize>(socket: &Path, request: &Q) -> Result<Response, ()> {
    use std::io::{Read, Write};
    let mut pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(socket)
        .map_err(|_| ())?;
    let mut line = serde_json::to_vec(request).map_err(|_| ())?;
    line.push(b'\n');
    pipe.write_all(&line).map_err(|_| ())?;
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while response.len() as u64 <= MAX_RESPONSE_BYTES {
        match pipe.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' => break,
            Ok(1) => response.push(byte[0]),
            _ => break,
        }
    }
    serde_json::from_slice(&response).map_err(|_| ())
}

fn call<Q: Serialize>(socket: &Path, request: &Q) -> Result<Response, AppError> {
    transport(socket, request).map_err(|()| unreachable_error())
}

pub(crate) fn call_ok<Q: Serialize>(socket: &Path, request: &Q) -> Result<Value, AppError> {
    let response = call(socket, request)?;
    if response.ok {
        Ok(response.data)
    } else {
        Err(AppError::new(response.code, response.message))
    }
}

fn mark(status: &str) -> &'static str {
    match status {
        "ok" => "✓ OK  ",
        "fail" => "✗ FAIL",
        "off" => "- OFF ",
        _ => "? UNKN",
    }
}

fn state_headline(state: &str) -> &'static str {
    match state {
        "protected" => "Protected",
        "degraded" => "NOT fully protected (degraded)",
        "connecting" => "Connecting…",
        "disconnected" => "Disconnected (normal networking)",
        "blocked" => "Blocked (kill switch is on, not connected)",
        _ => "Unknown (some checks could not be observed)",
    }
}

fn explanation(state: &str, reasons: &[String]) -> String {
    match state {
        "protected" => "Every check below was observed on this machine and passed. DNS is verified as resolver configuration, not by sending DNS packets.".into(),
        "degraded" => format!("Connected as requested, but not everything checks out: {}. Run `lovpn repair`, then `lovpn status` again.", reasons.join(", ")),
        "connecting" => "Waiting for the first handshake with the server.".into(),
        "blocked" => "Network traffic is blocked on purpose. Run `lovpn connect`, or `lovpn disconnect --release-kill-switch` to restore normal networking.".into(),
        "disconnected" => "No VPN is active and nothing is being blocked.".into(),
        _ => "LoVPN will not claim protection it could not verify. Run `lovpn diagnostics`.".into(),
    }
}

fn render_status(data: &Value) -> String {
    let state = data["state"].as_str().unwrap_or("unknown");
    let reasons: Vec<String> = data["reasons"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let mut text = format!("LoVPN\n\nStatus:      {}\n", state_headline(state));
    if let Some(profile) = data["profile"].as_str() {
        text.push_str(&format!("Profile:     {profile}\n"));
    }
    if let Some(mode) = data["kill_switch"].as_str() {
        let armed = if data["kill_switch_armed"] == true {
            "armed"
        } else {
            "not armed"
        };
        text.push_str(&format!("Kill switch: {mode} ({armed})\n"));
    }
    if let Some(age) = data["handshake_age_secs"].as_u64() {
        text.push_str(&format!(
            "Handshake:   {age}s ago   Transfer: received {} B, sent {} B\n",
            data["rx_bytes"], data["tx_bytes"]
        ));
    }
    if let Some(checks) = data["checks"].as_array().filter(|c| !c.is_empty()) {
        text.push_str("\nChecks (observed from the system, not assumed):\n");
        for check in checks {
            text.push_str(&format!(
                "  {}  {:<15} {}\n",
                mark(check["status"].as_str().unwrap_or("unknown")),
                check["name"].as_str().unwrap_or("?"),
                check["detail"].as_str().unwrap_or("")
            ));
        }
    }
    text.push_str(&format!("\n{}", explanation(state, &reasons)));
    text
}

/// Live status from the service, or the honest static report when it is not running.
pub fn status(socket: &Path) -> Result<Report, AppError> {
    match transport::<_>(socket, &json!({"op": "status"})) {
        Err(_) => {
            let mut report = reports::status();
            report.data["service"] = json!("not-running");
            report.text.push_str("\n\nThe LoVPN service (lovpn-clientd) is not running or not reachable, so no live state was inspected.");
            Ok(report)
        }
        Ok(response) if response.ok => {
            let mut data = response.data;
            data["schema_version"] = json!(1);
            data["service"] = json!("running");
            data["host_state_inspected"] = json!(true);
            let text = render_status(&data);
            Ok(Report { data, text })
        }
        Ok(response) => Err(AppError::new(response.code, response.message)),
    }
}

pub fn firewall_status(socket: &Path) -> Result<Report, AppError> {
    let report = status(socket)?;
    if report.data["service"] != "running" {
        return Ok(report);
    }
    let check = report.data["checks"]
        .as_array()
        .and_then(|c| c.iter().find(|c| c["name"] == "firewall"))
        .cloned();
    let (state, detail) = match &check {
        Some(c) => (
            c["status"].as_str().unwrap_or("unknown").to_string(),
            c["detail"].as_str().unwrap_or("").to_string(),
        ),
        None => (
            if report.data["kill_switch_armed"] == true {
                "ok".into()
            } else {
                "off".into()
            },
            "no active session; see kill_switch_armed".into(),
        ),
    };
    Ok(Report {
        text: format!(
            "Kill switch firewall: {state} — {detail}\nArmed in the service record: {}",
            report.data["kill_switch_armed"]
        ),
        data: json!({"schema_version": 1, "ok": true, "firewall": state, "detail": detail, "kill_switch_armed": report.data["kill_switch_armed"], "host_state_inspected": true}),
    })
}

pub fn profile_import(
    socket: &Path,
    file: &Path,
    name: &str,
    key_path: Option<&Path>,
    expect_server_key: &str,
    delete_key_file: bool,
) -> Result<Report, AppError> {
    let text = input::read_text(file)?;
    profile_import_text(
        socket,
        &text,
        name,
        key_path,
        expect_server_key,
        delete_key_file,
    )
}

/// Import a profile given as text (the window passes file contents, not paths).
pub fn profile_import_text(
    socket: &Path,
    text: &str,
    name: &str,
    key_path: Option<&Path>,
    expect_server_key: &str,
    delete_key_file: bool,
) -> Result<Report, AppError> {
    let mut note = String::new();
    let data = match key_path {
        Some(key_path) => {
            let data = import_with_key_file(socket, text, name, key_path, expect_server_key)?;
            if delete_key_file {
                match std::fs::remove_file(key_path) {
                    Ok(()) => note.push_str(
                        "\nThe key file was deleted; the service now holds the only copy.",
                    ),
                    Err(_) => note.push_str(
                        "\nWarning: the key file could not be deleted; remove it yourself.",
                    ),
                }
            } else {
                note.push_str("\nYour key file still exists. The service has its own copy, so you can delete it (or re-run with --delete-key-file).");
            }
            data
        }
        None => call_ok(
            socket,
            &json!({"op": "import-identity-profile", "name": name, "profile": text, "expected_server_key": expect_server_key}),
        )
        .map_err(|e| {
            if e.code == "unsupported.platform" {
                AppError::new(
                    "profile.key-file-required",
                    "Give your key file with --key-file (create it with `lovpn identity generate --key-file <file>`).",
                )
            } else {
                e
            }
        })?,
    };
    Ok(Report {
        text: format!(
            "Profile '{name}' imported. The server public key matched the one you expected.{note}\nConnect with: lovpn connect {name}"
        ),
        data: json!({"schema_version": 1, "ok": true, "profile": data["profile"], "key_file_deleted": delete_key_file && key_path.is_some()}),
    })
}

#[cfg(unix)]
fn import_with_key_file(
    socket: &Path,
    profile_text: &str,
    name: &str,
    key_path: &Path,
    expect_server_key: &str,
) -> Result<Value, AppError> {
    #[derive(Serialize)]
    struct Import<'a> {
        op: &'static str,
        name: &'a str,
        profile: &'a str,
        private_key: &'a str,
        expected_server_key: &'a str,
    }
    let key = key_file::read::<lovpn_keys::Client>(key_path)
        .map_err(|e| AppError::new(e.code(), e.to_string()))?;
    let secret = key.expose_base64();
    call_ok(
        socket,
        &Import {
            op: "import-profile",
            name,
            profile: profile_text,
            private_key: &secret,
            expected_server_key: expect_server_key,
        },
    )
}

#[cfg(windows)]
fn import_with_key_file(_: &Path, _: &str, _: &str, _: &Path, _: &str) -> Result<Value, AppError> {
    Err(AppError::new(
        "profile.key-file-unsupported",
        "On Windows the service keeps your private key. Run `lovpn identity generate --name <name>`, give the printed public key to your server administrator, then import without --key-file.",
    ))
}

pub fn profile_list(socket: &Path) -> Result<Report, AppError> {
    let data = call_ok(socket, &json!({"op": "list-profiles"}))?;
    let profiles = data["profiles"].as_array().cloned().unwrap_or_default();
    let selected = data["selected"].as_str().map(String::from);
    let text = if profiles.is_empty() {
        "No profiles yet. Import one: lovpn profile import <file> --name <name> --key-file <key> --expect-server-key <key>".to_string()
    } else {
        profiles
            .iter()
            .map(|p| {
                format!(
                    "{} {:<20} kill switch: {:<8} interface: {}",
                    if p["name"].as_str() == selected.as_deref() {
                        "*"
                    } else {
                        " "
                    },
                    p["name"].as_str().unwrap_or("?"),
                    p["kill_switch"].as_str().unwrap_or("?"),
                    p["interface"].as_str().unwrap_or("?")
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    Ok(Report {
        data: json!({"schema_version": 1, "ok": true, "profiles": profiles, "selected": selected}),
        text: if selected.is_none() {
            text
        } else {
            format!("{text}\n\n* = used by `lovpn connect` without a name")
        },
    })
}

fn simple(socket: &Path, request: Value, text: &str) -> Result<Report, AppError> {
    let data = call_ok(socket, &request)?;
    Ok(Report {
        text: text.to_string(),
        data: json!({"schema_version": 1, "ok": true, "result": data}),
    })
}

pub fn profile_remove(socket: &Path, name: &str) -> Result<Report, AppError> {
    simple(
        socket,
        json!({"op": "remove-profile", "name": name}),
        &format!("Profile '{name}' removed (its key too)."),
    )
}

/// Connect, then report what was *observed*, never merely that the request succeeded.
pub fn connect(socket: &Path, profile: Option<&str>) -> Result<Report, AppError> {
    let data = call_ok(socket, &json!({"op": "connect", "profile": profile}))?;
    let report = status(socket)?;
    Ok(Report {
        text: format!(
            "Connect request completed (handshake {}).\n\n{}",
            if data["handshake_seen"] == true {
                "seen"
            } else {
                "pending"
            },
            report.text
        ),
        data: json!({"schema_version": 1, "ok": true, "connect": data, "status": report.data}),
    })
}

pub fn disconnect(socket: &Path, release: bool) -> Result<Report, AppError> {
    call_ok(socket, &json!({"op": "disconnect", "release": release}))?;
    let report = status(socket)?;
    Ok(Report {
        text: format!("Disconnected.\n\n{}", report.text),
        data: json!({"schema_version": 1, "ok": true, "status": report.data}),
    })
}

pub fn reconnect(socket: &Path) -> Result<Report, AppError> {
    let data = call_ok(socket, &json!({"op": "reconnect"}))?;
    let report = status(socket)?;
    Ok(Report {
        text: format!(
            "Reconnected (the kill switch stayed in place).\n\n{}",
            report.text
        ),
        data: json!({"schema_version": 1, "ok": true, "connect": data, "status": report.data}),
    })
}

pub fn repair(socket: &Path) -> Result<Report, AppError> {
    call_ok(socket, &json!({"op": "repair"}))?;
    let report = status(socket)?;
    Ok(Report {
        text: format!("Repair completed.\n\n{}", report.text),
        data: json!({"schema_version": 1, "ok": true, "status": report.data}),
    })
}

pub fn reset(socket: &Path) -> Result<Report, AppError> {
    simple(
        socket,
        json!({"op": "reset"}),
        "Reset: disconnected, kill switch released, selected profile forgotten. Normal networking is restored. Profiles were kept.",
    )
}

pub fn profile_use(socket: &Path, name: &str) -> Result<Report, AppError> {
    simple(
        socket,
        json!({"op": "use-profile", "name": name}),
        &format!("'{name}' is now the default server. Nothing was connected; run `lovpn connect`."),
    )
}

/// Offline-style check of a stored profile via the service's listing. Deliberately does
/// not claim reachability: WireGuard answers only authenticated peers, so only a
/// connection (with an observed handshake) proves the server is reachable.
pub fn server_test(socket: &Path, name: &str) -> Result<Report, AppError> {
    let data = call_ok(socket, &json!({"op": "list-profiles"}))?;
    let found = data["profiles"]
        .as_array()
        .and_then(|a| a.iter().find(|p| p["name"] == name))
        .cloned()
        .ok_or_else(|| {
            AppError::new(
                "profile.not-found",
                "No server with that name exists. Run `lovpn server list`.",
            )
        })?;
    let endpoint = found["endpoint"].as_str().unwrap_or("?");
    Ok(Report {
        text: format!(
            "Server '{name}': the stored profile is intact and this client supports it (endpoint {endpoint}).\nReachability is NOT tested: a VPN server stays silent to unauthenticated probes. Run `lovpn connect {name}`; a handshake in `lovpn status` proves it."
        ),
        data: json!({"schema_version": 1, "ok": true, "profile_valid": true, "reachability": "not-tested", "endpoint": endpoint}),
    })
}

/// Recent service log. Linux: the journal (the service logs there, without secrets).
#[cfg(unix)]
pub fn logs(_socket: &Path, lines: u32) -> Result<Report, AppError> {
    let lines = lines.clamp(1, 1000);
    let output = std::process::Command::new("/usr/bin/journalctl")
        .args(["-u", "lovpn-clientd", "--no-pager", "-o", "cat", "-n"])
        .arg(lines.to_string())
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|_| {
            AppError::new(
                "logs.unavailable",
                "journalctl was not found, so the log cannot be shown. The service logs to the system journal.",
            )
        })?;
    if !output.status.success() {
        return Err(AppError::new(
            "logs.denied",
            "The journal could not be read. Add your user to the systemd-journal group or run with sudo.",
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_string();
    Ok(log_report(text.lines().map(String::from).collect()))
}

/// Recent service log. Windows: asked of the service, which owns the protected log file.
#[cfg(windows)]
pub fn logs(socket: &Path, lines: u32) -> Result<Report, AppError> {
    let data = call_ok(socket, &json!({"op": "logs", "lines": lines}))?;
    Ok(log_report(
        data["lines"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
    ))
}

fn log_report(lines: Vec<String>) -> Report {
    Report {
        text: if lines.is_empty() {
            "The service has not logged anything yet.".into()
        } else {
            lines.join("\n")
        },
        data: json!({"schema_version": 1, "ok": true, "lines": lines}),
    }
}

/// Create a client identity. Linux: a new 0600 key file. Windows: held by the service.
pub fn identity_generate(
    socket: &Path,
    key_file_path: Option<&Path>,
    name: Option<&str>,
) -> Result<Report, AppError> {
    match (key_file_path, name) {
        #[cfg(unix)]
        (Some(path), _) => {
            use lovpn_keys::ClientPrivateKey;
            let key =
                ClientPrivateKey::generate().map_err(|e| AppError::new(e.code(), e.to_string()))?;
            key_file::write_new(path, &key).map_err(|e| AppError::new(e.code(), e.to_string()))?;
            let public = key.public_key().to_string();
            Ok(Report {
                data: json!({"schema_version": 1, "ok": true, "public_key": public, "private_key_written": true, "system_changed": false}),
                text: format!(
                    "Client key generated; the private key was saved to the new file (mode 0600) and is never printed.\nGive the administrator ONLY this public key:\n{public}"
                ),
            })
        }
        (_, Some(name)) => {
            let data = call_ok(socket, &json!({"op": "generate-identity", "name": name}))?;
            let public = data["public_key"].as_str().unwrap_or("").to_string();
            Ok(Report {
                data: json!({"schema_version": 1, "ok": true, "public_key": public, "private_key_written": false, "held_by": "service"}),
                text: format!(
                    "Client key created and kept by the LoVPN service; it is never shown or written to a file.\nGive the administrator ONLY this public key:\n{public}\nWhen you receive the profile: lovpn profile import <file> --name {name} --expect-server-key <key>"
                ),
            })
        }
        _ => Err(AppError::new(
            "identity.arguments",
            if cfg!(windows) {
                "Give a name: lovpn identity generate --name <name>."
            } else {
                "Give a destination: lovpn identity generate --key-file <new file>."
            },
        )),
    }
}

pub fn identity_public(
    socket: &Path,
    key_file_path: Option<&Path>,
    name: Option<&str>,
) -> Result<Report, AppError> {
    match (key_file_path, name) {
        #[cfg(unix)]
        (Some(path), _) => {
            let key = key_file::read::<lovpn_keys::Client>(path)
                .map_err(|e| AppError::new(e.code(), e.to_string()))?;
            let public = key.public_key().to_string();
            Ok(Report {
                data: json!({"schema_version": 1, "ok": true, "public_key": public}),
                text: public,
            })
        }
        (_, Some(name)) => {
            let data = call_ok(socket, &json!({"op": "public-key", "name": name}))?;
            let public = data["public_key"].as_str().unwrap_or("").to_string();
            Ok(Report {
                data: json!({"schema_version": 1, "ok": true, "public_key": public}),
                text: public,
            })
        }
        _ => Err(AppError::new(
            "identity.arguments",
            "Give --name (identity kept by the service) or, on Linux, --key-file.",
        )),
    }
}
