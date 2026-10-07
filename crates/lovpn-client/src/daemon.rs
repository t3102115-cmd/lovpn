use clap::{Parser, ValueEnum};
use lovpn_client::{
    Engine,
    broker::{Broker, BrokerConfig, DEFAULT_SOCKET, spawn_monitor},
    dns::{DnsBackend, Kind},
    profiles::ProfileStore,
    record::RecordStore,
};
use lovpn_sys::{
    exec::SystemRunner,
    ipc::{resolve_user, unix_now},
};
use std::{
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Copy, ValueEnum)]
enum DnsMode {
    /// Manage DNS through systemd-resolved (per-link settings).
    Resolved,
    /// Do not manage DNS. Status reports DNS as unprotected.
    Unmanaged,
}

#[derive(Parser)]
#[command(
    version,
    about = "LoVPN client broker: owns the tunnel, kill switch, routing and DNS"
)]
struct Args {
    /// Service state: profiles, keys and the session record (root-owned, mode 0700).
    #[arg(long, default_value = "/var/lib/lovpn-client")]
    state_dir: PathBuf,
    #[arg(long, default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
    /// Unprivileged user allowed to control the VPN.
    #[arg(
        long,
        conflicts_with = "owner_uid",
        required_unless_present = "owner_uid"
    )]
    owner_user: Option<String>,
    #[arg(long)]
    owner_uid: Option<u32>,
    #[arg(long, value_enum, default_value = "resolved")]
    dns_backend: DnsMode,
    /// How often the monitor reconciles kernel state with the desired state.
    #[arg(long, default_value_t = 5000)]
    monitor_interval_ms: u64,
    /// How long `connect` waits for the first handshake before returning.
    #[arg(long, default_value_t = 10)]
    handshake_wait_secs: u64,
}

fn private_dir(path: &Path) -> std::io::Result<()> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        other => other,
    }
}

pub fn main() -> ExitCode {
    let args = Args::parse();
    let fail = |code: &str, message: &str| {
        eprintln!(
            "{}",
            serde_json::json!({"event": "startup-failed", "code": code, "message": message})
        );
        ExitCode::from(1)
    };
    let owner_uid = match (args.owner_uid, &args.owner_user) {
        (Some(uid), _) => uid,
        (None, Some(name)) => match resolve_user(name) {
            Some(uid) => uid,
            None => {
                return fail(
                    "owner-user",
                    "The controlling user was not found in /etc/passwd.",
                );
            }
        },
        (None, None) => return fail("owner-user", "Give --owner-user or --owner-uid."),
    };
    let profile_dir = args.state_dir.join("profiles");
    if private_dir(&args.state_dir)
        .and_then(|()| private_dir(&profile_dir))
        .is_err()
    {
        return fail("state-dir", "The state directory could not be created.");
    }
    let (profiles, records) = match (
        ProfileStore::open(&profile_dir),
        RecordStore::open(&args.state_dir),
    ) {
        (Ok(p), Ok(r)) => (p, r),
        _ => {
            return fail(
                "state-dir",
                "The state directory must be mode 0700 and owned by the service.",
            );
        }
    };
    let dns = DnsBackend::new(match args.dns_backend {
        DnsMode::Resolved => Kind::Resolved,
        DnsMode::Unmanaged => Kind::Unmanaged,
    });
    let mut engine = Engine::new(
        Arc::new(SystemRunner),
        profiles,
        records,
        dns,
        Duration::from_secs(args.handshake_wait_secs),
        Box::new(unix_now),
    );
    // Restore protection before accepting any request: re-arm the kill switch and resume a
    // session the user had asked for.
    let startup = engine.recover_on_start();
    eprintln!(
        "{}",
        serde_json::json!({"event": "recovery", "action": startup.action, "reasons": startup.reasons})
    );
    let engine = Arc::new(Mutex::new(engine));
    let broker = match Broker::bind(
        BrokerConfig {
            socket: args.socket,
            owner_uid,
        },
        Arc::clone(&engine),
    ) {
        Ok(broker) => broker,
        Err(error) => return fail("bind", &error.to_string()),
    };
    spawn_monitor(
        engine,
        Duration::from_millis(args.monitor_interval_ms.max(200)),
    );
    eprintln!(
        "{}",
        serde_json::json!({"event": "listening", "owner_uid": owner_uid})
    );
    broker.serve()
}
