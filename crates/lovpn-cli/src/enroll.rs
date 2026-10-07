//! `lovpn enroll`: redeem a one-time token over pinned TLS and import the profile.
//!
//! The client sends only its PUBLIC key and the token, and only after the server's
//! certificate matched the pin the administrator gave you. The token is read from a
//! file or stdin, never from the command line. The profile that comes back is
//! validated locally; its server key is the one authenticated by the pin.
use crate::{AppError, Report, client, input};
use lovpn_enroll::{
    EnrollError, proto,
    tls::{self, Pin},
    token::Token,
};
use serde_json::json;
use std::{
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

const DEADLINE: Duration = Duration::from_secs(15);

pub struct EnrollArgs {
    pub server: SocketAddr,
    pub pin: String,
    pub name: String,
    /// File holding the token, or `-` for standard input.
    pub token_file: PathBuf,
    /// Linux: private key file (must exist unless `generate_key`).
    pub key_file: Option<PathBuf>,
    pub generate_key: bool,
    /// Use the identity the service holds under the profile name (created with
    /// `lovpn identity generate --name <name>`); its key never leaves the service.
    pub identity: bool,
    /// Also save a copy of the received public profile to this new file.
    pub output: Option<PathBuf>,
    /// Do not import into the service; only save to `output`.
    pub no_import: bool,
}

fn enroll_error(error: EnrollError) -> AppError {
    AppError::new(error.code(), error.to_string())
}

fn read_token(path: &Path) -> Result<Token, AppError> {
    let text = if path == Path::new("-") {
        let mut bytes = Vec::new();
        std::io::stdin()
            .lock()
            .take(lovpn_enroll::token::TOKEN_LEN as u64 + 8)
            .read_to_end(&mut bytes)
            .map_err(|_| enroll_error(EnrollError::TokenFormat))?;
        String::from_utf8(bytes).map_err(|_| enroll_error(EnrollError::TokenFormat))?
    } else {
        input::read_text(path)?
    };
    Token::parse(text.trim()).map_err(enroll_error)
}

#[cfg(unix)]
fn local_public_key(
    args: &EnrollArgs,
    socket: &Path,
) -> Result<(String, Option<PathBuf>), AppError> {
    use lovpn_keys::{ClientPrivateKey, file as key_file};
    match (&args.key_file, args.identity) {
        (Some(path), _) => {
            let exists = std::fs::symlink_metadata(path).is_ok();
            if !exists {
                if !args.generate_key {
                    return Err(AppError::new(
                        "enroll.key-missing",
                        "That key file does not exist. Add --generate-key to create it now (a new 0600 file; the private key is never printed or sent).",
                    ));
                }
                let key = ClientPrivateKey::generate()
                    .map_err(|e| AppError::new(e.code(), e.to_string()))?;
                key_file::write_new(path, &key)
                    .map_err(|e| AppError::new(e.code(), e.to_string()))?;
            }
            let key = key_file::read::<lovpn_keys::Client>(path)
                .map_err(|e| AppError::new(e.code(), e.to_string()))?;
            Ok((key.public_key().to_string(), Some(path.clone())))
        }
        (None, true) => service_public_key(socket, &args.name),
        (None, false) => Err(AppError::new(
            "enroll.identity",
            "Give --key-file <file> (with --generate-key to create it) or --identity.",
        )),
    }
}

#[cfg(windows)]
fn local_public_key(
    args: &EnrollArgs,
    socket: &Path,
) -> Result<(String, Option<PathBuf>), AppError> {
    if args.identity {
        service_public_key(socket, &args.name)
    } else {
        Err(AppError::new(
            "enroll.identity",
            "Give --identity; create the key first with `lovpn identity generate --name <name>` using the same name as --name.",
        ))
    }
}

fn service_public_key(socket: &Path, name: &str) -> Result<(String, Option<PathBuf>), AppError> {
    let data = client::call_ok(socket, &json!({"op": "public-key", "name": name})).map_err(|e| {
        if e.code == "profile.not-found" {
            AppError::new(
                "enroll.identity",
                "The service holds no identity named like --name. Create it first with `lovpn identity generate --name <name>` (same name as the profile).",
            )
        } else {
            e
        }
    })?;
    let public = data["public_key"].as_str().unwrap_or("").to_string();
    if public.is_empty() {
        return Err(AppError::new(
            "enroll.identity",
            "The service has no identity named like --name. Create it with `lovpn identity generate --name <name>` (same name as the profile).",
        ));
    }
    Ok((public, None))
}

pub fn run(socket: &Path, args: EnrollArgs) -> Result<Report, AppError> {
    let pin: Pin = args.pin.parse().map_err(enroll_error)?;
    let token = read_token(&args.token_file)?;
    let (public_key, key_path) = local_public_key(&args, socket)?;

    let request =
        proto::encode(&proto::Request::new(token.expose(), public_key)).map_err(enroll_error)?;
    let line = tls::exchange(args.server, pin, &request, DEADLINE).map_err(enroll_error)?;
    let response = proto::parse_response(&line).map_err(enroll_error)?;
    if !response.ok {
        return Err(enroll_error(response.error()));
    }
    let (Some(profile), Some(server_key)) = (response.profile, response.server_public_key) else {
        return Err(enroll_error(EnrollError::BadResponse));
    };
    let parsed =
        lovpn_config::parse(&profile).map_err(|_| enroll_error(EnrollError::BadResponse))?;
    if parsed.profile.server_public_key != server_key {
        return Err(enroll_error(EnrollError::BadResponse));
    }
    let applied = response.applied.unwrap_or(false);

    let mut notes = Vec::new();
    if let Some(path) = &args.output {
        write_new_file(path, &profile)?;
        notes.push("A copy of the public profile was saved to the file you named.".to_string());
    }
    let imported = if args.no_import {
        notes.push("Not imported (--no-import).".to_string());
        false
    } else {
        client::profile_import_text(socket, &profile, &args.name, key_path.as_deref(), &server_key, false)
            .map_err(|e| {
                AppError::new(
                    e.code,
                    format!(
                        "{} The enrollment itself succeeded and was recorded by the server; repeating the same command within 10 minutes returns the same profile, or re-run with --output <file> --no-import.",
                        e.message
                    ),
                )
            })?;
        true
    };
    let applied_note = if applied {
        "The server confirmed the new peer is active."
    } else {
        "The server enrolled you but did not confirm applying it; ask the administrator to run `lovpn-server apply` if you cannot connect."
    };
    Ok(Report {
        text: format!(
            "Enrolled with the pinned server. Server public key: {server_key}\n{applied_note}{}{}",
            if notes.is_empty() {
                String::new()
            } else {
                format!("\n{}", notes.join("\n"))
            },
            if imported {
                format!("\nConnect with: lovpn connect {}", args.name)
            } else {
                String::new()
            },
        ),
        data: json!({
            "schema_version": 1, "ok": true, "server_public_key": server_key,
            "applied_on_server": applied, "imported": imported, "profile_name": args.name,
            "pin_verified": true
        }),
    })
}

#[cfg(unix)]
fn write_new_file(path: &Path, contents: &str) -> Result<(), AppError> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| {
            AppError::new(
                "enroll.output",
                "Cannot create that output file (it must not exist).",
            )
        })?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| AppError::new("enroll.output", "Cannot write the output file."))
}

#[cfg(windows)]
fn write_new_file(path: &Path, contents: &str) -> Result<(), AppError> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| {
            AppError::new(
                "enroll.output",
                "Cannot create that output file (it must not exist).",
            )
        })?;
    file.write_all(contents.as_bytes())
        .map_err(|_| AppError::new("enroll.output", "Cannot write the output file."))
}
