//! Offline LoVPN inspection CLI. No network operations or privileged mutations.
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

mod input;
mod reports;

#[derive(Parser)]
#[command(
    version,
    about = "LoVPN offline security foundation — not a VPN client yet"
)]
struct Cli {
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List application network behavior; this command does not probe the network.
    Privacy,
    /// Report current implementation capabilities, not host protection.
    Status,
    /// Export a sanitized capability report; does not probe servers or inspect traffic.
    Diagnostics,
    /// Validate public schema-v1 profiles without changing the system.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Inspect a Linux laboratory policy. Never installs or removes rules.
    Firewall {
        #[command(subcommand)]
        command: FirewallCommand,
    },
    /// Create or inspect a client WireGuard identity. The private key stays local.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Show software and configuration schema versions.
    Version,
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Check syntax, field allowlists and routing/DNS/IPv6 consistency.
    Validate { file: PathBuf },
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Generate a key pair into a NEW 0600 file; prints only the public key.
    Generate {
        /// Destination file. Never overwritten; its directory must be private.
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Print the public key for an existing key file. Safe to send to the administrator.
    Public {
        #[arg(long)]
        key_file: PathBuf,
    },
}

#[derive(Subcommand)]
enum FirewallCommand {
    /// Print the generated nft batch, not the current host firewall.
    Show {
        file: PathBuf,
        /// Print removal instructions only; does not remove protection.
        #[arg(long)]
        reset_preview: bool,
    },
    /// Validate compilation only. Does not invoke nft or verify kernel state.
    Validate { file: PathBuf },
    /// Explain why this build cannot verify installed firewall protection.
    Status,
}

struct AppError {
    code: &'static str,
    message: String,
}

impl AppError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<lovpn_config::ConfigError> for AppError {
    fn from(error: lovpn_config::ConfigError) -> Self {
        Self::new(error.code(), error.to_string())
    }
}

impl From<lovpn_firewall::FirewallError> for AppError {
    fn from(error: lovpn_firewall::FirewallError) -> Self {
        Self::new(error.code(), error.to_string())
    }
}

struct Report {
    data: Value,
    text: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(report) => {
            let output = if cli.json {
                report.data.to_string()
            } else {
                report.text
            };
            match writeln!(io::stdout().lock(), "{output}") {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            }
        }
        Err(error) => {
            let output = if cli.json {
                json!({"schema_version": 1, "ok": false, "error": {"code": error.code, "message": error.message}}).to_string()
            } else {
                format!("LoVPN: {}\nTechnical code: {}", error.message, error.code)
            };
            let _ = writeln!(io::stderr().lock(), "{output}");
            ExitCode::from(1)
        }
    }
}

fn run(command: Command) -> Result<Report, AppError> {
    match command {
        Command::Privacy => Ok(reports::privacy()),
        Command::Status
        | Command::Diagnostics
        | Command::Firewall {
            command: FirewallCommand::Status,
        } => Ok(reports::status()),
        Command::Version => Ok(Report {
            data: json!({"schema_version": 1, "version": env!("CARGO_PKG_VERSION"), "config_schema_version": lovpn_config::SCHEMA_VERSION}),
            text: format!(
                "LoVPN {} (offline foundation; configuration schema 1)",
                env!("CARGO_PKG_VERSION")
            ),
        }),
        Command::Config {
            command: ConfigCommand::Validate { file },
        } => {
            input::load(&file)?;
            Ok(Report {
                data: json!({"schema_version": 1, "ok": true, "configuration_valid": true, "protection": "not-verified", "system_changed": false}),
                text: "Configuration is valid. This does not authenticate its server or prove protection.\nNo system changes were made.".into(),
            })
        }
        Command::Identity { command } => identity(command),
        Command::Firewall { command } => {
            let (file, preview) = match command {
                FirewallCommand::Show {
                    file,
                    reset_preview,
                } => (file, Some(reset_preview)),
                FirewallCommand::Validate { file } => (file, None),
                FirewallCommand::Status => return Ok(reports::status()),
            };
            let config = input::load(&file)?;
            let plan = lovpn_firewall::compile(&config)?;
            Ok(reports::firewall(&plan, preview))
        }
    }
}

#[cfg(unix)]
fn identity(command: IdentityCommand) -> Result<Report, AppError> {
    use lovpn_keys::{ClientPrivateKey, file};
    let key_error = |e: file::KeyFileError| AppError::new(e.code(), e.to_string());
    match command {
        IdentityCommand::Generate { key_file } => {
            let key =
                ClientPrivateKey::generate().map_err(|e| AppError::new(e.code(), e.to_string()))?;
            file::write_new(&key_file, &key).map_err(key_error)?;
            let public = key.public_key().to_string();
            Ok(Report {
                data: json!({"schema_version": 1, "ok": true, "public_key": public, "private_key_written": true, "system_changed": false}),
                text: format!(
                    "Client key generated; the private key was saved to the new file (mode 0600) and is never printed.\nGive the administrator ONLY this public key:\n{public}"
                ),
            })
        }
        IdentityCommand::Public { key_file } => {
            let key = file::read::<lovpn_keys::Client>(&key_file).map_err(key_error)?;
            let public = key.public_key().to_string();
            Ok(Report {
                data: json!({"schema_version": 1, "ok": true, "public_key": public}),
                text: public,
            })
        }
    }
}

#[cfg(not(unix))]
fn identity(_command: IdentityCommand) -> Result<Report, AppError> {
    Err(AppError::new(
        "identity.unsupported-platform",
        "Protected key storage is not implemented on this platform yet (Windows DPAPI/ACL storage is planned).",
    ))
}
