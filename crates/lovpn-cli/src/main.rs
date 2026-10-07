//! Offline LoVPN inspection CLI. No network operations or privileged mutations.
use clap::{Parser, Subcommand};
use serde_json::json;
use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

use lovpn_cli::{AppError, Report, client, input, reports};

#[cfg(unix)]
const DEFAULT_SOCKET: &str = "/run/lovpn-client/broker.sock";
#[cfg(windows)]
const DEFAULT_SOCKET: &str = r"\\.\pipe\lovpn-client";

#[derive(Parser)]
#[command(
    version,
    about = "LoVPN client: connect through your own server. Changes to the network are made by the lovpn-clientd service, never by this tool."
)]
struct Cli {
    #[arg(long, global = true)]
    json: bool,
    /// Socket of the LoVPN service (lovpn-clientd).
    #[arg(long, global = true, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List application network behavior; this command does not probe the network.
    Privacy,
    /// Show what the service observes: connection, routing, firewall, DNS, IPv4, IPv6.
    Status,
    /// Like status, as a sanitized report without secrets. Probes no external server.
    Diagnostics,
    /// Manage stored server profiles (the service keeps the private keys).
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Enroll with a server using a one-time token over pinned TLS, then import the
    /// profile. Sends only your PUBLIC key. Needs the token and pin from your administrator.
    Enroll(EnrollArgs),
    /// Manage servers. Same as `profile`: a profile is one server plus your key for it.
    Server {
        #[command(subcommand)]
        command: ServerCommand,
    },
    /// Show the service's log from the system journal (needs journal read access).
    Logs {
        /// Number of most recent lines.
        #[arg(long, default_value_t = 50)]
        lines: u32,
    },
    /// Connect using a profile (the last used one if omitted).
    Connect { profile: Option<String> },
    /// Disconnect. A `strict` profile keeps blocking traffic unless you release it.
    Disconnect {
        /// Also remove the kill switch and restore normal networking.
        #[arg(long)]
        release_kill_switch: bool,
    },
    /// Recreate the tunnel without lifting the kill switch.
    Reconnect,
    /// Re-apply the desired connection state (routes, firewall, DNS).
    Repair,
    /// Restore normal networking: disconnect, release the kill switch, forget the profile.
    Reset,
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

#[derive(clap::Args)]
struct EnrollArgs {
    /// The server's enrollment address, e.g. 203.0.113.5:51821.
    #[arg(long)]
    server: std::net::SocketAddr,
    /// The server's pin: `sha256:` plus 64 hex digits, from the administrator.
    #[arg(long)]
    pin: String,
    /// Short local name for the imported profile.
    #[arg(long)]
    name: String,
    /// File containing the one-time token, or `-` to read it from standard input.
    /// The token is never accepted on the command line.
    #[arg(long)]
    token_file: PathBuf,
    /// Linux: your client private key file.
    #[arg(long, conflicts_with = "identity")]
    key_file: Option<PathBuf>,
    /// Create --key-file now if it does not exist (a new 0600 file).
    #[arg(long, requires = "key_file")]
    generate_key: bool,
    /// Use the identity the service holds under --name (see `lovpn identity generate --name`).
    #[arg(long)]
    identity: bool,
    /// Also save the received public profile to this new file.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Do not import into the service (use with --output).
    #[arg(long)]
    no_import: bool,
}

#[derive(Subcommand)]
enum ProfileCommand {
    /// Import a profile from your server administrator, with its client key.
    Import {
        /// Public profile file (from `lovpn-server peer export`).
        file: PathBuf,
        /// Short local name: lowercase letters, digits, '-' or '_'.
        #[arg(long)]
        name: String,
        /// Linux: your client private key file (from `lovpn identity generate --key-file`).
        /// Windows: omit; the service uses the identity made by `lovpn identity generate --name`.
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// The server's public key, obtained from the administrator over a separate
        /// channel. The profile is refused if it names a different key.
        #[arg(long)]
        expect_server_key: String,
        /// Delete your key file after the service has stored its own copy.
        #[arg(long)]
        delete_key_file: bool,
    },
    /// List stored profiles; the one `connect` uses by default is marked.
    List,
    Remove {
        name: String,
    },
    /// Choose the profile `connect` uses by default. Does not connect.
    Use {
        name: String,
    },
}

#[derive(Subcommand)]
enum ServerCommand {
    /// Add a server from its profile file (same as `profile import`).
    Add {
        file: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long)]
        expect_server_key: String,
        #[arg(long)]
        delete_key_file: bool,
    },
    List,
    Remove {
        name: String,
    },
    /// Check that a stored server profile is intact and usable by this client.
    /// It cannot prove the server is reachable: only a connection can.
    Test {
        name: String,
    },
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
        /// Linux: destination file. Never overwritten; its directory must be private.
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// Windows: a local name; the key pair is created and kept by the service.
        #[arg(long)]
        name: Option<String>,
    },
    /// Print the public key for an existing key file. Safe to send to the administrator.
    Public {
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long)]
        name: Option<String>,
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command, &cli.socket) {
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

fn run(command: Command, socket: &std::path::Path) -> Result<Report, AppError> {
    match command {
        Command::Privacy => Ok(reports::privacy()),
        Command::Status | Command::Diagnostics => client::status(socket),
        Command::Firewall {
            command: FirewallCommand::Status,
        } => client::firewall_status(socket),
        Command::Profile { command } => profile(socket, command),
        Command::Enroll(a) => lovpn_cli::enroll::run(
            socket,
            lovpn_cli::enroll::EnrollArgs {
                server: a.server,
                pin: a.pin,
                name: a.name,
                token_file: a.token_file,
                key_file: a.key_file,
                generate_key: a.generate_key,
                identity: a.identity,
                output: a.output,
                no_import: a.no_import,
            },
        ),
        Command::Server { command } => server(socket, command),
        Command::Logs { lines } => client::logs(socket, lines),
        Command::Connect { profile } => client::connect(socket, profile.as_deref()),
        Command::Disconnect {
            release_kill_switch,
        } => client::disconnect(socket, release_kill_switch),
        Command::Reconnect => client::reconnect(socket),
        Command::Repair => client::repair(socket),
        Command::Reset => client::reset(socket),
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
        Command::Identity { command } => identity(socket, command),
        Command::Firewall { command } => {
            let (file, preview) = match command {
                FirewallCommand::Show {
                    file,
                    reset_preview,
                } => (file, Some(reset_preview)),
                FirewallCommand::Validate { file } => (file, None),
                FirewallCommand::Status => return client::firewall_status(socket),
            };
            let config = input::load(&file)?;
            let plan = lovpn_firewall::compile(&config)?;
            Ok(reports::firewall(&plan, preview))
        }
    }
}

fn identity(socket: &std::path::Path, command: IdentityCommand) -> Result<Report, AppError> {
    match command {
        IdentityCommand::Generate { key_file, name } => {
            client::identity_generate(socket, key_file.as_deref(), name.as_deref())
        }
        IdentityCommand::Public { key_file, name } => {
            client::identity_public(socket, key_file.as_deref(), name.as_deref())
        }
    }
}

fn profile(socket: &std::path::Path, command: ProfileCommand) -> Result<Report, AppError> {
    match command {
        ProfileCommand::Import {
            file,
            name,
            key_file,
            expect_server_key,
            delete_key_file,
        } => client::profile_import(
            socket,
            &file,
            &name,
            key_file.as_deref(),
            &expect_server_key,
            delete_key_file,
        ),
        ProfileCommand::List => client::profile_list(socket),
        ProfileCommand::Remove { name } => client::profile_remove(socket, &name),
        ProfileCommand::Use { name } => client::profile_use(socket, &name),
    }
}

fn server(socket: &std::path::Path, command: ServerCommand) -> Result<Report, AppError> {
    match command {
        ServerCommand::Add {
            file,
            name,
            key_file,
            expect_server_key,
            delete_key_file,
        } => client::profile_import(
            socket,
            &file,
            &name,
            key_file.as_deref(),
            &expect_server_key,
            delete_key_file,
        ),
        ServerCommand::List => client::profile_list(socket),
        ServerCommand::Remove { name } => client::profile_remove(socket, &name),
        ServerCommand::Test { name } => client::server_test(socket, &name),
    }
}
