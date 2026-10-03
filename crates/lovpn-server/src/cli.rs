use clap::{Args, Parser, Subcommand, ValueEnum};
use ipnet::Ipv4Net;
use lovpn_config::KillSwitchMode;
use lovpn_keys::{ClientPublicKey, ServerPrivateKey};
use lovpn_server::{
    ExportOptions, PeerStatus, ServerError, ServerState, SetupParams, Store,
    applier::SystemRunner,
    broker::{self, Broker, BrokerConfig, DEFAULT_SOCKET, Op, Request},
    state::{DEFAULT_INTERFACE, DEFAULT_LISTEN_PORT},
};
use serde_json::{Value, json};
use std::{
    io::{self, Write},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

const DEFAULT_STATE_DIR: &str = "/var/lib/lovpn-server";

#[derive(Parser)]
#[command(
    version,
    about = "LoVPN server: state, offline enrollment and (through the broker) applying it to the host"
)]
struct Cli {
    #[arg(long, global = true)]
    json: bool,
    /// State directory (mode 0700). Holds the server private key.
    #[arg(long, global = true, default_value = DEFAULT_STATE_DIR)]
    state_dir: PathBuf,
    /// Broker socket used by apply/status --live/teardown/firewall repair.
    #[arg(long, global = true, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Plan or initialize the server identity and state. Never touches the network.
    Setup(SetupArgs),
    /// Manage peers (offline enrollment: supply the client's PUBLIC key only).
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
    /// State summary; with --live, also what the broker observes on the host.
    Status {
        /// Ask the broker to compare the host (interface, peers, firewall) with state.
        #[arg(long)]
        live: bool,
    },
    /// Ask the broker to apply the current state to the host (needs a running broker).
    Apply {
        /// Fail without change if the state is not at this generation.
        #[arg(long)]
        expected_generation: Option<u64>,
    },
    /// Ask the broker to remove only LoVPN-owned interface, tables and forwarding
    /// change. Root only. Clients lose connectivity to this server.
    Teardown {
        /// Required: confirms you understand clients will be disconnected.
        #[arg(long)]
        yes: bool,
    },
    /// Run the privileged broker (as root, normally from systemd).
    Broker(BrokerArgs),
    /// Sanitized local report; contains no keys and probes nothing.
    Diagnostics,
    /// Inspect the server firewall policy compiled from state.
    Firewall {
        #[command(subcommand)]
        command: FirewallCommand,
    },
    /// Plan a clean reset. Deletes nothing.
    Reset {
        #[arg(long)]
        plan: bool,
    },
}

#[derive(Args)]
struct BrokerArgs {
    /// Unprivileged service user that owns the state directory.
    #[arg(
        long,
        conflicts_with = "owner_uid",
        required_unless_present = "owner_uid"
    )]
    owner_user: Option<String>,
    #[arg(long)]
    owner_uid: Option<u32>,
    /// Broker-private directory (root-owned 0700) holding the applied-generation record.
    #[arg(long, default_value = "/var/lib/lovpn-broker")]
    broker_dir: PathBuf,
}

#[derive(Args)]
struct SetupArgs {
    /// Validate and print the plan; write nothing, generate nothing persistent.
    #[arg(long, conflicts_with = "write_state")]
    dry_run: bool,
    /// Create the state directory, server key and state only (no network changes).
    #[arg(long)]
    write_state: bool,
    /// Public endpoint clients connect to: a literal IP and port.
    #[arg(long)]
    endpoint: SocketAddr,
    #[arg(long, default_value_t = DEFAULT_LISTEN_PORT)]
    listen_port: u16,
    /// Private IPv4 client pool, e.g. 10.66.0.0/24. The server uses the first host.
    #[arg(long)]
    pool: Ipv4Net,
    /// Uplink interface used for NAT.
    #[arg(long)]
    wan_interface: String,
    /// Resolver(s) reachable through the tunnel. LoVPN does not run one.
    #[arg(long, required = true, num_args = 1..)]
    dns: Vec<IpAddr>,
    #[arg(long, default_value = DEFAULT_INTERFACE)]
    interface: String,
    #[arg(long, default_value = "LoVPN server")]
    label: String,
    #[arg(long, default_value_t = 1380)]
    mtu: u16,
}

#[derive(Subcommand)]
enum PeerCommand {
    Create {
        #[arg(long)]
        name: String,
        /// The client's base64 public key (never a private key).
        #[arg(long)]
        public_key: String,
        /// Confirm the value came from `lovpn identity public` if it is refused as private-looking.
        #[arg(long)]
        confirm_public_key: bool,
        #[arg(long)]
        expected_generation: Option<u64>,
        /// Apply to the host through the broker right after the change.
        #[arg(long)]
        apply: bool,
    },
    List,
    /// Print a public client profile (no secrets) to stdout or a new file.
    Export {
        /// Peer name or numeric id.
        peer: String,
        #[arg(long, default_value = "lovpn0")]
        client_interface: String,
        #[arg(long, value_enum, default_value = "strict")]
        kill_switch: Kill,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Revoke {
        peer: String,
        #[arg(long)]
        expected_generation: Option<u64>,
        /// Enforce on the host through the broker right after the change.
        #[arg(long)]
        apply: bool,
    },
    Rotate {
        peer: String,
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        confirm_public_key: bool,
        #[arg(long)]
        expected_generation: Option<u64>,
        /// Enforce on the host through the broker right after the change.
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Kill {
    Off,
    VpnOnly,
    Strict,
}

#[derive(Subcommand)]
enum FirewallCommand {
    /// Ask the broker whether the installed LoVPN tables exist, are owned and current.
    Status,
    Show {
        #[arg(long)]
        reset_preview: bool,
    },
    Validate,
    /// Reinstall only the LoVPN firewall tables through the broker.
    Repair,
}

struct Report {
    data: Value,
    text: String,
}

struct Failure {
    code: String,
    message: String,
}

impl From<ServerError> for Failure {
    fn from(error: ServerError) -> Self {
        Self {
            code: error.code().into(),
            message: error.to_string(),
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    match run(cli) {
        Ok(report) => {
            let out = if json {
                report.data.to_string()
            } else {
                report.text
            };
            match writeln!(io::stdout().lock(), "{out}") {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            }
        }
        Err(error) => {
            let out = if json {
                json!({"schema_version": 1, "ok": false, "error": {"code": error.code, "message": error.message}}).to_string()
            } else {
                format!(
                    "lovpn-server: {}\nTechnical code: {}",
                    error.message, error.code
                )
            };
            let _ = writeln!(io::stderr().lock(), "{out}");
            ExitCode::from(1)
        }
    }
}

fn parse_key(text: &str, confirmed: bool) -> Result<ClientPublicKey, Failure> {
    let key: ClientPublicKey = text.parse().map_err(|_| ServerError::Key)?;
    if key.resembles_clamped_private_key() && !confirmed {
        return Err(ServerError::KeyLooksPrivate.into());
    }
    Ok(key)
}

fn setup_params(args: &SetupArgs) -> SetupParams {
    SetupParams {
        label: args.label.clone(),
        interface: args.interface.clone(),
        wan_interface: args.wan_interface.clone(),
        endpoint: args.endpoint,
        listen_port: args.listen_port,
        pool: args.pool,
        dns: args.dns.clone(),
        mtu: args.mtu,
    }
}

fn peer_json(peer: &lovpn_server::Peer) -> Value {
    json!({
        "id": peer.id, "name": peer.name, "public_key": peer.public_key,
        "address": peer.address.to_string(), "status": match peer.status {
            PeerStatus::Active => "active", PeerStatus::Revoked => "revoked" },
        "key_epoch": peer.key_epoch, "created_unix": peer.created_unix,
        "revoked_unix": peer.revoked_unix,
    })
}

/// Call the broker and turn a refusal into the broker's own sanitized error.
fn call_broker(
    socket: &std::path::Path,
    op: Op,
    expected_generation: Option<u64>,
) -> Result<broker::Response, Failure> {
    let request = Request {
        op,
        expected_generation,
    };
    let response = broker::call(socket, &request, std::time::Duration::from_secs(60)).map_err(|_| Failure {
        code: "broker.unreachable".into(),
        message: "Cannot reach the LoVPN broker. Is lovpn-server-broker running, and are you the service user or root? Nothing was applied.".into(),
    })?;
    if response.ok {
        Ok(response)
    } else {
        Err(Failure {
            code: response.code,
            message: response.message,
        })
    }
}

fn apply_now(socket: &std::path::Path, generation: u64) -> Result<Value, Failure> {
    Ok(call_broker(socket, Op::Apply, Some(generation))?.data)
}

fn run_broker(
    dir: &std::path::Path,
    socket: &std::path::Path,
    args: BrokerArgs,
) -> Result<Report, Failure> {
    let owner_uid = match (args.owner_uid, &args.owner_user) {
        (Some(uid), _) => uid,
        (None, Some(name)) => broker::resolve_user(name).ok_or(Failure {
            code: "broker.owner-user".into(),
            message: "The service user was not found in /etc/passwd.".into(),
        })?,
        (None, None) => unreachable!("clap requires one of the owner options"),
    };
    let config = BrokerConfig::new(
        dir.to_path_buf(),
        owner_uid,
        args.broker_dir,
        socket.to_path_buf(),
    );
    let broker =
        Broker::bind(config, std::sync::Arc::new(SystemRunner)).map_err(|error| Failure {
            code: "broker.bind".into(),
            message: error.to_string(),
        })?;
    eprintln!(
        "{}",
        json!({"event": "broker-listening", "owner_uid": owner_uid})
    );
    broker.serve()
}

fn run(cli: Cli) -> Result<Report, Failure> {
    let dir = cli.state_dir;
    let socket = cli.socket;
    match cli.command {
        Command::Setup(args) => setup(&dir, &args),
        Command::Peer { command } => peer(&dir, &socket, command),
        Command::Broker(args) => run_broker(&dir, &socket, args),
        Command::Apply {
            expected_generation,
        } => {
            let response = call_broker(&socket, Op::Apply, expected_generation)?;
            Ok(Report {
                text: "Applied the current state to the host (WireGuard interface, peers, forwarding, LoVPN firewall tables).".into(),
                data: json!({"schema_version": 1, "ok": true, "applied": true, "report": response.data}),
            })
        }
        Command::Teardown { yes } => {
            if !yes {
                return Err(Failure {
                    code: "teardown.confirm".into(),
                    message: "Teardown disconnects every client and removes LoVPN's interface, firewall tables and forwarding change. Repeat with --yes to proceed.".into(),
                });
            }
            let response = call_broker(&socket, Op::Teardown, None)?;
            Ok(Report {
                text: "Removed LoVPN-owned resources only. State and keys in the state directory were kept.".into(),
                data: json!({"schema_version": 1, "ok": true, "report": response.data}),
            })
        }
        Command::Status { live } => status(&dir, &socket, live),
        Command::Diagnostics => status(&dir, &socket, false),
        Command::Firewall { command } => firewall(&dir, &socket, command),
        Command::Reset { plan } => {
            if !plan {
                return Err(ServerError::Unsupported.into());
            }
            let text = format!(
                "Reset plan (nothing is deleted by this command):\n\
                 1. As root: `lovpn-server teardown --yes` removes nft tables 'inet {}' and 'ip {}', the WireGuard\n\
                    interface the broker created, and restores the previous ip_forward value.\n\
                 2. Stop and disable the lovpn-server-broker service (see docs/server.md).\n\
                 3. Delete {} only after backing up server.key if you need the same server identity;\n\
                    deleting it invalidates every exported client profile.",
                lovpn_firewall::server::FILTER_TABLE,
                lovpn_firewall::server::NAT_TABLE,
                dir.display()
            );
            Ok(Report {
                data: json!({"schema_version": 1, "ok": true, "plan_only": true, "system_changed": false}),
                text,
            })
        }
    }
}

fn setup(dir: &std::path::Path, args: &SetupArgs) -> Result<Report, Failure> {
    if !args.dry_run && !args.write_state {
        return Err(Failure {
            code: "setup.mode".into(),
            message: "Choose --dry-run or --write-state. Neither applies network configuration."
                .into(),
        });
    }
    let key = ServerPrivateKey::generate().map_err(|_| ServerError::Storage)?;
    let state = ServerState::new(setup_params(args), key.public_key(), now())?;
    let policy =
        lovpn_firewall::server::compile(&state.firewall_policy()).map_err(|_| ServerError::Pool)?;
    let plan = format!(
        "Planned (NOT applied by this build):\n\
         - state directory {} (0700), server.key (0600), state.json (0600)\n\
         - WireGuard interface {} listening on UDP {}, address {}/{}, MTU {}\n\
         - IPv6 policy: block; peer addresses from {}; DNS pushed to clients: {}\n\
         - nftables tables owned by LoVPN: inet {} and ip {}\n\
         - not managed: net.ipv4.ip_forward, host firewall allowance for the UDP port, DNS resolver",
        dir.display(),
        state.server.interface,
        state.server.listen_port,
        state.server_address(),
        state.server.pool.prefix_len(),
        state.server.mtu,
        state.server.pool,
        state
            .server
            .dns
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        lovpn_firewall::server::FILTER_TABLE,
        lovpn_firewall::server::NAT_TABLE,
    );
    if args.dry_run {
        return Ok(Report {
            data: json!({"schema_version": 1, "ok": true, "dry_run": true, "system_changed": false,
                "identity": "would-be-generated", "nft_statements": policy.ruleset().lines().filter(|l| !l.starts_with('#')).count()}),
            text: format!(
                "{plan}\nDry run: nothing was written and the throwaway key was discarded.\n\nFirewall preview:\n{}",
                policy.ruleset()
            ),
        });
    }
    Store::create_dir(dir)?;
    let store = Store::open(dir)?;
    store.init(&state, &key)?;
    Ok(Report {
        data: json!({"schema_version": 1, "ok": true, "state_written": true, "system_changed": false,
            "generation": state.generation, "server_public_key": state.server.public_key}),
        text: format!(
            "{plan}\nState written. Server public key (give clients this out of band): {}\nNo WireGuard, route or firewall change was made.",
            state.server.public_key
        ),
    })
}

/// Apply after a state change if requested. The state change has already been
/// committed; if applying fails, say so loudly rather than implying enforcement.
fn enforcement(
    socket: &std::path::Path,
    apply: bool,
    generation: u64,
) -> Result<(Value, String), Failure> {
    if !apply {
        return Ok((
            json!({"enforced": false}),
            "NOT yet enforced on the host: run `lovpn-server apply` (or use --apply).".into(),
        ));
    }
    match apply_now(socket, generation) {
        Ok(report) => Ok((
            json!({"enforced": true, "apply": report}),
            "Enforced on the host through the broker.".into(),
        )),
        Err(failure) => Err(Failure {
            code: failure.code,
            message: format!(
                "State generation {generation} was saved, but applying it FAILED: {} The host still runs the previous configuration.",
                failure.message
            ),
        }),
    }
}

fn peer(
    dir: &std::path::Path,
    socket: &std::path::Path,
    command: PeerCommand,
) -> Result<Report, Failure> {
    let store = Store::open(dir)?;
    match command {
        PeerCommand::Create {
            name,
            public_key,
            confirm_public_key,
            expected_generation,
            apply,
        } => {
            let key = parse_key(&public_key, confirm_public_key)?;
            let (generation, value) = store.update(expected_generation, |state| {
                let peer = state.create_peer(&name, key, now())?;
                Ok(peer_json(peer))
            })?;
            let (enforced, note) = enforcement(socket, apply, generation)?;
            Ok(Report {
                text: format!(
                    "Created peer {name}. State generation {generation}. {note}\nExport its profile with: lovpn-server peer export {name}"
                ),
                data: json!({"schema_version": 1, "ok": true, "generation": generation, "peer": value, "enforcement": enforced}),
            })
        }
        PeerCommand::List => {
            let state = store.load()?;
            let peers: Vec<Value> = state.peers.iter().map(peer_json).collect();
            let text = state
                .peers
                .iter()
                .map(|p| {
                    format!(
                        "{:>4} {:<24} {:<15} {}",
                        p.id,
                        p.name,
                        p.address,
                        if p.status == PeerStatus::Active {
                            "active"
                        } else {
                            "revoked"
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            Ok(Report {
                text: format!(
                    "Generation {}\n{}",
                    state.generation,
                    if text.is_empty() {
                        "(no peers)".into()
                    } else {
                        text
                    }
                ),
                data: json!({"schema_version": 1, "ok": true, "generation": state.generation, "peers": peers}),
            })
        }
        PeerCommand::Export {
            peer,
            client_interface,
            kill_switch,
            output,
        } => {
            let state = store.load()?;
            let options = ExportOptions {
                client_interface,
                kill_switch: match kill_switch {
                    Kill::Off => KillSwitchMode::Off,
                    Kill::VpnOnly => KillSwitchMode::VpnOnly,
                    Kill::Strict => KillSwitchMode::Strict,
                },
            };
            let profile = state.export_profile(&peer, &options)?;
            if let Some(path) = output {
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .map_err(|_| ServerError::Exists)?;
                file.write_all(profile.as_bytes())
                    .and_then(|()| file.sync_all())
                    .map_err(|_| ServerError::Storage)?;
                return Ok(Report {
                    data: json!({"schema_version": 1, "ok": true, "exported": true}),
                    text: "Profile written to a new 0600 file. It contains no secrets; verify the server public key out of band.".into(),
                });
            }
            Ok(Report {
                data: json!({"schema_version": 1, "ok": true, "profile": profile}),
                text: profile,
            })
        }
        PeerCommand::Revoke {
            peer,
            expected_generation,
            apply,
        } => {
            let (generation, ()) = store.update(expected_generation, |state| {
                state.revoke_peer(&peer, now()).map(|_| ())
            })?;
            let (enforced, note) = enforcement(socket, apply, generation)?;
            Ok(Report {
                text: format!("Revoked. State generation {generation}. {note}"),
                data: json!({"schema_version": 1, "ok": true, "generation": generation, "enforcement": enforced, "enforced": enforced["enforced"]}),
            })
        }
        PeerCommand::Rotate {
            peer,
            public_key,
            confirm_public_key,
            expected_generation,
            apply,
        } => {
            let key = parse_key(&public_key, confirm_public_key)?;
            let (generation, ()) = store.update(expected_generation, |state| {
                state.rotate_peer(&peer, key).map(|_| ())
            })?;
            let (enforced, note) = enforcement(socket, apply, generation)?;
            Ok(Report {
                text: format!(
                    "Rotated key; lease kept. State generation {generation}. {note} The old key stays blocked from re-enrollment."
                ),
                data: json!({"schema_version": 1, "ok": true, "generation": generation, "enforcement": enforced, "enforced": enforced["enforced"]}),
            })
        }
    }
}

fn status(dir: &std::path::Path, socket: &std::path::Path, live: bool) -> Result<Report, Failure> {
    let state = Store::open(dir)?.load()?;
    let active = state.active_peers().count();
    let revoked = state.peers.len() - active;
    let observation = if live {
        Some(call_broker(socket, Op::Status, None)?.data)
    } else {
        None
    };
    let in_sync = observation.as_ref().and_then(|o| o["in_sync"].as_bool());
    let live_text = match (&observation, in_sync) {
        (Some(o), Some(true)) => format!(
            "Host matches state generation {} (interface, peers and firewall observed by the broker).",
            o["state_generation"]
        ),
        (Some(o), _) => format!(
            "Host DIFFERS from state: {}. Run `lovpn-server apply`.",
            o["drift"]
        ),
        (None, _) => "Host state was not observed (use --live with a running broker).".into(),
    };
    Ok(Report {
        data: json!({
            "schema_version": 1, "ok": true, "generation": state.generation,
            "server_public_key": state.server.public_key, "interface": state.server.interface,
            "pool": state.server.pool.to_string(), "active_peers": active, "revoked_peers": revoked,
            "ipv6": state.server.ipv6,
            "host": observation, "host_in_sync": in_sync,
            // Observation of the server only: says nothing about any client's protection.
            "protection": "not-verified",
        }),
        text: format!(
            "State generation {}. Server public key: {}\nPool {} on {}; {} active, {} revoked peers.\n{live_text}",
            state.generation,
            state.server.public_key,
            state.server.pool,
            state.server.interface,
            active,
            revoked
        ),
    })
}

fn firewall(
    dir: &std::path::Path,
    socket: &std::path::Path,
    command: FirewallCommand,
) -> Result<Report, Failure> {
    match command {
        FirewallCommand::Status => {
            let o = call_broker(socket, Op::Status, None)?.data;
            let generation = &o["firewall_generation"];
            let current =
                !generation.is_null() && o["firewall_generation"] == o["state_generation"];
            Ok(Report {
                text: if current {
                    format!(
                        "LoVPN firewall tables are installed, owned by LoVPN and at generation {generation}."
                    )
                } else {
                    format!(
                        "LoVPN firewall tables are missing, foreign or stale (installed generation {generation}). Run `lovpn-server firewall repair`."
                    )
                },
                data: json!({"schema_version": 1, "ok": true, "installed": current, "installed_generation": generation, "state_generation": o["state_generation"], "verified": current}),
            })
        }
        FirewallCommand::Repair => {
            let response = call_broker(socket, Op::RepairFirewall, None)?;
            Ok(Report {
                text: "Reinstalled the LoVPN firewall tables for the current state.".into(),
                data: json!({"schema_version": 1, "ok": true, "repaired": true, "report": response.data}),
            })
        }
        FirewallCommand::Show { reset_preview } => {
            let state = Store::open(dir)?.load()?;
            let plan = lovpn_firewall::server::compile(&state.firewall_policy())
                .map_err(|_| ServerError::Pool)?;
            let text = if reset_preview {
                plan.reset_ruleset()
            } else {
                plan.ruleset()
            }
            .to_string();
            Ok(Report {
                data: json!({"schema_version": 1, "ok": true, "ruleset": text, "installed": false}),
                text,
            })
        }
        FirewallCommand::Validate => {
            let state = Store::open(dir)?.load()?;
            lovpn_firewall::server::compile(&state.firewall_policy())
                .map_err(|_| ServerError::Pool)?;
            Ok(Report {
                data: json!({"schema_version": 1, "ok": true, "compiled": true, "kernel_checked": false}),
                text: "Policy compiles. The kernel was not consulted; this is not an installation check.".into(),
            })
        }
    }
}
