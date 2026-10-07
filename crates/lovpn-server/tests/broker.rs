#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(target_os = "linux")]

use lovpn_keys::{ClientPrivateKey, ServerPrivateKey};
use lovpn_server::{
    ServerError, ServerState, SetupParams, Store,
    applier::{
        Applier, ApplyError, Cmd, CmdOutput, ExecError, Program, Runner, TableState,
        classify_table, parse_addresses, parse_link,
    },
    broker::{self, Broker, BrokerConfig, BrokerError, Op, Request},
};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

// ---------------------------------------------------------------- fake host ----

#[derive(Default)]
struct Host {
    interface: Option<String>,
    kind: String,
    addresses: Vec<(String, u64)>,
    mtu: u32,
    up: bool,
    listen_port: u16,
    peers: Vec<String>,
    tables: BTreeMap<String, String>, // "family name" -> comment ("" = foreign)
    log: Vec<String>,
    stdin_seen: Vec<String>,
    fail_step: Option<&'static str>,
}

#[derive(Clone, Default)]
struct Fake(Arc<Mutex<Host>>);

impl Fake {
    fn host(&self) -> std::sync::MutexGuard<'_, Host> {
        self.0.lock().unwrap()
    }
    fn mutating(&self) -> Vec<String> {
        self.host()
            .log
            .iter()
            .filter(|l| {
                !l.contains(" show ") && !l.contains("list table") && !l.starts_with("ip -j")
            })
            .cloned()
            .collect()
    }
}

fn out(success: bool, stdout: impl Into<String>) -> Result<CmdOutput, ExecError> {
    Ok(CmdOutput {
        success,
        stdout: stdout.into(),
    })
}

impl Runner for Fake {
    fn run(&self, cmd: &Cmd, step: &'static str) -> Result<CmdOutput, ExecError> {
        let mut host = self.0.lock().unwrap();
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        let line = format!("{:?} {}", cmd.program, args.join(" ")).to_lowercase();
        host.log.push(line);
        if host.fail_step == Some(step) {
            return out(false, "");
        }
        let stdin = cmd
            .stdin
            .as_ref()
            .map(|s| String::from_utf8_lossy(s).into_owned());
        if let Some(text) = &stdin {
            host.stdin_seen.push(text.clone());
        }
        match (cmd.program, args.as_slice()) {
            (Program::Ip, ["-j", "-d", "link", "show", ..]) => match &host.interface {
                None => out(false, ""),
                Some(_) => out(
                    true,
                    format!(
                        r#"[{{"mtu":{},"flags":[{}],"linkinfo":{{"info_kind":"{}"}}}}]"#,
                        host.mtu,
                        if host.up { "\"UP\"" } else { "" },
                        host.kind
                    ),
                ),
            },
            (Program::Ip, ["link", "add", "dev", name, "type", "wireguard"]) => {
                host.interface = Some((*name).into());
                host.kind = "wireguard".into();
                host.mtu = 1420;
                out(true, "")
            }
            (Program::Ip, ["link", "set", "dev", _, "mtu", mtu, "up"]) => {
                host.mtu = mtu.parse().unwrap();
                host.up = true;
                out(true, "")
            }
            (Program::Ip, ["link", "del", "dev", _]) => {
                host.interface = None;
                host.peers.clear();
                host.addresses.clear();
                out(true, "")
            }
            (Program::Ip, ["-j", "-4", "addr", "show", ..]) => {
                let infos: Vec<String> = host
                    .addresses
                    .iter()
                    .map(|(a, p)| format!(r#"{{"family":"inet","local":"{a}","prefixlen":{p}}}"#))
                    .collect();
                out(true, format!(r#"[{{"addr_info":[{}]}}]"#, infos.join(",")))
            }
            (Program::Ip, ["addr", op, cidr, "dev", _]) => {
                let (a, p) = cidr.split_once('/').unwrap();
                let entry = (a.to_string(), p.parse().unwrap());
                if *op == "add" {
                    host.addresses.push(entry);
                } else {
                    host.addresses.retain(|e| *e != entry);
                }
                out(true, "")
            }
            (Program::Wg, ["syncconf", ..]) => {
                let text = stdin.unwrap();
                host.listen_port = text
                    .lines()
                    .find_map(|l| l.strip_prefix("ListenPort = "))
                    .unwrap()
                    .parse()
                    .unwrap();
                host.peers = text
                    .lines()
                    .filter_map(|l| l.strip_prefix("PublicKey = "))
                    .map(String::from)
                    .collect();
                out(true, "")
            }
            (Program::Wg, ["show", _, "listen-port"]) => {
                out(true, format!("{}\n", host.listen_port))
            }
            (Program::Wg, ["show", _, "peers"]) => out(true, host.peers.join("\n")),
            (Program::Wg, ["show", _, "latest-handshakes"]) => out(
                true,
                host.peers
                    .iter()
                    .map(|p| format!("{p}\t1700000000\n"))
                    .collect::<String>(),
            ),
            (Program::Wg, ["show", _, "transfer"]) => out(
                true,
                host.peers
                    .iter()
                    .map(|p| format!("{p}\t10\t20\n"))
                    .collect::<String>(),
            ),
            (Program::Nft, ["list", "table", family, name]) => {
                match host.tables.get(&format!("{family} {name}")) {
                    None => out(false, ""),
                    Some(comment) if comment.is_empty() => out(true, "table x {\n}\n"),
                    Some(comment) => {
                        out(true, format!("table x {{\n\tcomment \"{comment}\"\n}}\n"))
                    }
                }
            }
            (Program::Nft, ["-f", "-"]) => {
                let text = stdin.unwrap();
                for line in text.lines() {
                    if let Some(rest) = line.strip_prefix("add table ")
                        && let Some((head, tail)) = rest.split_once(" { comment \"")
                    {
                        let comment = tail.trim_end_matches("\"; }").to_string();
                        host.tables.insert(head.to_string(), comment);
                    }
                }
                out(true, "")
            }
            (Program::Nft, ["delete", "table", family, name]) => {
                host.tables.remove(&format!("{family} {name}"));
                out(true, "")
            }
            _ => panic!("unexpected command: {:?}", host.log.last()),
        }
    }
}

// ------------------------------------------------------------------- helpers ----

fn tmpdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn me() -> u32 {
    rustix::process::geteuid().as_raw()
}

struct Env {
    _dir: tempfile::TempDir,
    state_dir: PathBuf,
    broker_dir: PathBuf,
    ip_forward: PathBuf,
    store: Store,
    key: ServerPrivateKey,
    fake: Fake,
}

fn env() -> Env {
    let dir = tmpdir();
    let state_dir = dir.path().join("state");
    let broker_dir = dir.path().join("broker");
    Store::create_dir(&state_dir).unwrap();
    std::fs::create_dir(&broker_dir).unwrap();
    std::fs::set_permissions(&broker_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let ip_forward = dir.path().join("ip_forward");
    std::fs::write(&ip_forward, "0\n").unwrap();
    let store = Store::open(&state_dir).unwrap();
    let key = ServerPrivateKey::generate().unwrap();
    let params = SetupParams {
        label: "T".into(),
        interface: "lovpn-srv0".into(),
        wan_interface: "eth0".into(),
        endpoint: "192.0.2.10:51820".parse().unwrap(),
        listen_port: 51820,
        pool: "10.66.0.0/24".parse().unwrap(),
        dns: vec!["10.66.0.1".parse().unwrap()],
        mtu: 1380,
    };
    let state = ServerState::new(params, key.public_key(), 1).unwrap();
    store.init(&state, &key).unwrap();
    Env {
        _dir: dir,
        state_dir,
        broker_dir,
        ip_forward,
        store,
        key,
        fake: Fake::default(),
    }
}

impl Env {
    fn applier(&self) -> Applier<'_> {
        Applier {
            runner: &self.fake,
            broker_dir: self.broker_dir.clone(),
            ip_forward_path: self.ip_forward.clone(),
        }
    }
    fn add_peer(&self, name: &str) -> String {
        let key = ClientPrivateKey::generate().unwrap().public_key();
        self.store
            .update(None, |s| s.create_peer(name, key, 1).map(|_| ()))
            .unwrap();
        key.to_string()
    }
    fn state(&self) -> ServerState {
        self.store.load().unwrap()
    }
    fn forwarding(&self) -> String {
        std::fs::read_to_string(&self.ip_forward)
            .unwrap()
            .trim()
            .into()
    }
}

// ----------------------------------------------------------------- applier ----

#[test]
fn apply_configures_interface_peers_forwarding_and_firewall_without_leaking_the_key() {
    let env = env();
    let peer = env.add_peer("laptop");
    let report = env.applier().apply(&env.state(), &env.key).unwrap();
    assert!(report.interface_created && report.forwarding_enabled_by_us);
    assert_eq!(report.peers, 1);

    let host = env.fake.host();
    assert_eq!(host.peers, vec![peer]);
    assert_eq!(host.listen_port, 51820);
    assert_eq!(host.addresses, vec![("10.66.0.1".to_string(), 24)]);
    assert!(host.up && host.mtu == 1380);
    assert_eq!(host.tables.len(), 2);
    assert!(
        host.tables.values().all(|c| c == "lovpn-owned gen=2"),
        "{:?}",
        host.tables
    );

    // The private key reaches `wg` through stdin only, never any argument.
    let secret = env.key.expose_base64().to_string();
    assert!(
        host.log.iter().all(|l| !l.contains(&secret)),
        "key found in a command line"
    );
    assert_eq!(
        host.stdin_seen
            .iter()
            .filter(|s| s.contains(&secret))
            .count(),
        1
    );
    assert!(
        host.stdin_seen.iter().all(|s| !s.contains("laptop")),
        "names never leave state"
    );
    drop(host);
    assert_eq!(env.forwarding(), "1");
}

#[test]
fn apply_is_idempotent_and_reconciles_stale_addresses() {
    let env = env();
    env.add_peer("a");
    env.applier().apply(&env.state(), &env.key).unwrap();
    env.fake.host().addresses.push(("10.99.0.9".into(), 24));
    env.fake.host().log.clear();
    let again = env.applier().apply(&env.state(), &env.key).unwrap();
    assert!(!again.interface_created);
    let mutating = env.fake.mutating();
    assert!(
        !mutating.iter().any(|l| l.contains("link add")),
        "{mutating:?}"
    );
    assert!(
        mutating.iter().any(|l| l.contains("addr del 10.99.0.9/24")),
        "{mutating:?}"
    );
    assert_eq!(
        env.fake.host().addresses,
        vec![("10.66.0.1".to_string(), 24)]
    );
}

#[test]
fn revocation_is_enforced_by_the_next_apply() {
    let env = env();
    let keep = env.add_peer("keep");
    let drop_key = env.add_peer("drop");
    env.applier().apply(&env.state(), &env.key).unwrap();
    assert_eq!(env.fake.host().peers.len(), 2);
    env.store
        .update(None, |s| s.revoke_peer("drop", 5).map(|_| ()))
        .unwrap();
    let before = env.applier().observe(&env.state()).unwrap();
    assert!(!before.in_sync && before.drift.contains(&"peers-unexpected"));
    assert_eq!(before.peers_unexpected, vec![drop_key.clone()]);
    env.applier().apply(&env.state(), &env.key).unwrap();
    assert_eq!(env.fake.host().peers, vec![keep]);
    let after = env.applier().observe(&env.state()).unwrap();
    assert!(after.in_sync, "{:?}", after.drift);
    assert_eq!(after.firewall_generation, Some(env.state().generation));
}

#[test]
fn foreign_interfaces_and_tables_are_never_modified() {
    // A same-named interface of another kind.
    let env1 = env();
    {
        let mut h = env1.fake.host();
        h.interface = Some("lovpn-srv0".into());
        h.kind = "dummy".into();
    }
    assert_eq!(
        env1.applier().apply(&env1.state(), &env1.key).err(),
        Some(ApplyError::ForeignInterface)
    );
    assert!(
        env1.fake.mutating().is_empty(),
        "{:?}",
        env1.fake.mutating()
    );

    // A WireGuard interface that LoVPN did not create (no record of ownership).
    let env2 = env();
    {
        let mut h = env2.fake.host();
        h.interface = Some("lovpn-srv0".into());
        h.kind = "wireguard".into();
    }
    assert_eq!(
        env2.applier().apply(&env2.state(), &env2.key).err(),
        Some(ApplyError::ForeignInterface)
    );
    assert!(env2.fake.mutating().is_empty());

    // A table with LoVPN's name but without its ownership marker.
    let env3 = env();
    env3.fake
        .host()
        .tables
        .insert("inet lovpn_server".into(), String::new());
    assert_eq!(
        env3.applier().apply(&env3.state(), &env3.key).err(),
        Some(ApplyError::ForeignTable)
    );
    assert!(env3.fake.mutating().is_empty());
    // Teardown skips it and reports so.
    let report = env3.applier().teardown().unwrap();
    assert_eq!(
        report.tables_skipped_foreign,
        vec!["lovpn_server".to_string()]
    );
    assert!(env3.fake.host().tables.contains_key("inet lovpn_server"));
}

#[test]
fn failed_apply_rolls_back_what_it_created() {
    let env = env();
    env.fake.host().fail_step = Some("apply-firewall");
    let error = env.applier().apply(&env.state(), &env.key).err();
    assert_eq!(error, Some(ApplyError::CommandFailed("apply-firewall")));
    assert!(
        env.fake.host().interface.is_none(),
        "interface created in this run must be removed"
    );
    assert_eq!(env.forwarding(), "0", "forwarding change must be undone");
    let record = env.applier().load_record().unwrap();
    assert!(record.interface_owned.is_none() && record.last_applied_generation == 0);
    // After the fault clears, a retry succeeds from scratch.
    env.fake.host().fail_step = None;
    assert!(env.applier().apply(&env.state(), &env.key).is_ok());
}

#[test]
fn rollback_to_an_older_state_is_refused() {
    let env = env();
    let old = env.state();
    env.add_peer("a");
    env.applier().apply(&env.state(), &env.key).unwrap();
    assert_eq!(
        env.applier().apply(&old, &env.key).err(),
        Some(ApplyError::Rollback)
    );
    assert_eq!(
        env.applier().repair_firewall(&old).err(),
        Some(ApplyError::Rollback)
    );
    // Re-applying the current generation is fine.
    assert!(env.applier().apply(&env.state(), &env.key).is_ok());
}

#[test]
fn teardown_removes_only_owned_resources_and_restores_forwarding() {
    let env = env();
    env.add_peer("a");
    env.applier().apply(&env.state(), &env.key).unwrap();
    env.fake
        .host()
        .tables
        .insert("inet unrelated".into(), "other".into());
    let report = env.applier().teardown().unwrap();
    assert!(report.interface_removed && report.forwarding_restored);
    assert_eq!(report.tables_removed.len(), 2);
    let host = env.fake.host();
    assert!(host.interface.is_none());
    assert_eq!(
        host.tables.keys().collect::<Vec<_>>(),
        vec!["inet unrelated"]
    );
    drop(host);
    assert_eq!(env.forwarding(), "0");
    // The rollback counter survives teardown.
    assert_eq!(
        env.applier().load_record().unwrap().last_applied_generation,
        env.state().generation
    );
    // Idempotent.
    assert!(env.applier().teardown().is_ok());
}

#[test]
fn observation_reports_drift_without_changing_anything() {
    let env = env();
    env.add_peer("a");
    env.applier().apply(&env.state(), &env.key).unwrap();
    assert!(env.applier().observe(&env.state()).unwrap().in_sync);
    env.fake.host().log.clear();
    env.fake.host().tables.clear();
    env.fake.host().peers.clear();
    env.fake.host().listen_port = 1;
    std::fs::write(&env.ip_forward, "0\n").unwrap();
    let observed = env.applier().observe(&env.state()).unwrap();
    for reason in [
        "peers-missing",
        "firewall-missing",
        "listen-port-mismatch",
        "forwarding-off",
    ] {
        assert!(
            observed.drift.contains(&reason),
            "{reason} not in {:?}",
            observed.drift
        );
    }
    assert!(!observed.in_sync);
    assert!(env.fake.mutating().is_empty(), "observe must be read-only");
    // A stale firewall generation is detected from the table comment.
    env.fake
        .host()
        .tables
        .insert("inet lovpn_server".into(), "lovpn-owned gen=1".into());
    env.fake
        .host()
        .tables
        .insert("ip lovpn_server_nat".into(), "lovpn-owned gen=1".into());
    assert!(
        env.applier()
            .observe(&env.state())
            .unwrap()
            .drift
            .contains(&"firewall-generation-mismatch")
    );
}

#[test]
fn broker_record_directory_must_be_private() {
    let env = env();
    std::fs::set_permissions(&env.broker_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(env.applier().load_record().err(), Some(ApplyError::Record));
    assert_eq!(
        env.applier().apply(&env.state(), &env.key).err(),
        Some(ApplyError::Record)
    );
}

#[test]
fn parsers_are_strict_and_total() {
    assert_eq!(classify_table(false, ""), TableState::Absent);
    assert_eq!(
        classify_table(true, "table inet x {\n}\n"),
        TableState::Foreign
    );
    assert_eq!(
        classify_table(true, "table x {\n\tcomment \"mine\"\n}"),
        TableState::Foreign
    );
    assert_eq!(
        classify_table(true, "x {\n\tcomment \"lovpn-owned gen=12\"\n}"),
        TableState::Owned {
            generation: Some(12)
        }
    );
    assert_eq!(
        classify_table(true, "x {\n\tcomment \"lovpn-owned\"\n}"),
        TableState::Owned { generation: None }
    );
    assert_eq!(
        classify_table(true, "x {\n\tcomment \"lovpn-ownedX\"\n}"),
        TableState::Foreign
    );
    assert!(!parse_link(true, "garbage").present);
    assert!(!parse_link(true, "[]").present);
    assert!(!parse_link(false, "[{}]").present);
    assert!(parse_addresses("not json").is_empty());
    assert_eq!(
        parse_addresses(
            r#"[{"addr_info":[{"family":"inet6","local":"fd::1","prefixlen":64},{"family":"inet","local":"10.0.0.1","prefixlen":24}]}]"#
        ),
        vec![("10.0.0.1".to_string(), 24)]
    );
}

// ------------------------------------------------------------------- broker ----

fn start_broker(
    env: &Env,
    owner_uid: u32,
    connections: usize,
) -> (PathBuf, std::thread::JoinHandle<()>) {
    let socket = env._dir.path().join("broker.sock");
    let mut config = BrokerConfig::new(
        env.state_dir.clone(),
        owner_uid,
        env.broker_dir.clone(),
        socket.clone(),
    );
    config.ip_forward_path = env.ip_forward.clone();
    let broker = Broker::bind(config, Arc::new(env.fake.clone())).unwrap();
    let handle = std::thread::spawn(move || {
        for _ in 0..connections {
            broker.serve_one();
        }
    });
    (socket, handle)
}

fn ask(socket: &Path, op: Op, expected: Option<u64>) -> broker::Response {
    broker::call(
        socket,
        &Request {
            op,
            expected_generation: expected,
        },
        Duration::from_secs(10),
    )
    .unwrap()
}

fn raw(socket: &Path, bytes: &[u8]) -> broker::Response {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let _ = stream.write_all(bytes);
    let mut reply = String::new();
    let _ = stream.read_to_string(&mut reply);
    serde_json::from_str(&reply).unwrap()
}

#[test]
fn broker_applies_observes_and_tears_down_for_an_authorized_caller() {
    if me() == 0 {
        return; // root is always authorized; the denial tests need an unprivileged user
    }
    let env = env();
    env.add_peer("a");
    let generation = env.state().generation;
    let (socket, handle) = start_broker(&env, me(), 5);
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(ask(&socket, Op::Ping, None).ok);
    // Stale expected generation fails without touching the host.
    let stale = ask(&socket, Op::Apply, Some(generation + 5));
    assert_eq!(stale.code, "state.generation-conflict");
    assert!(env.fake.mutating().is_empty());
    let applied = ask(&socket, Op::Apply, Some(generation));
    assert!(applied.ok, "{applied:?}");
    let status = ask(&socket, Op::Status, None);
    assert_eq!(status.data["in_sync"], true, "{:?}", status.data);
    // Teardown is root-only: the service-user owner is refused.
    let denied = ask(&socket, Op::Teardown, None);
    assert_eq!(denied.code, "auth.denied");
    assert!(env.fake.host().interface.is_some());
    handle.join().unwrap();
}

#[test]
fn broker_denies_callers_that_are_neither_root_nor_the_owner() {
    if me() == 0 {
        return;
    }
    let env = env();
    let (socket, handle) = start_broker(&env, me() + 1, 3);
    for op in [Op::Ping, Op::Apply, Op::Status] {
        let response = ask(&socket, op, None);
        assert_eq!(response.code, "auth.denied", "{op:?}");
    }
    assert!(
        env.fake.host().log.is_empty(),
        "denied requests must not run anything"
    );
    handle.join().unwrap();
}

#[test]
fn broker_rejects_oversized_malformed_and_unknown_requests() {
    if me() == 0 {
        return;
    }
    let env = env();
    let (socket, handle) = start_broker(&env, me(), 6);
    let mut big = vec![b'a'; 5000];
    big.push(b'\n');
    assert_eq!(raw(&socket, &big).code, "request.too-large");
    assert_eq!(raw(&socket, b"not json\n").code, "request.malformed");
    assert_eq!(
        raw(&socket, b"{\"op\":\"format-disk\"}\n").code,
        "request.malformed"
    );
    // No paths, interfaces or commands may be smuggled in as extra fields.
    assert_eq!(
        raw(&socket, b"{\"op\":\"apply\",\"interface\":\"eth0\"}\n").code,
        "request.malformed"
    );
    assert_eq!(
        raw(&socket, b"{\"op\":\"status\",\"command\":\"rm -rf /\"}\n").code,
        "request.malformed"
    );
    // A client that sends nothing is cut off by the read timeout, not waited on forever.
    assert_eq!(raw(&socket, b"").code, "request.io");
    assert!(env.fake.host().log.is_empty());
    handle.join().unwrap();
}

#[test]
fn broker_refuses_unsafe_socket_paths_and_double_start() {
    let env = env();
    let existing = env._dir.path().join("regular-file");
    std::fs::write(&existing, "keep me").unwrap();
    let config = BrokerConfig::new(
        env.state_dir.clone(),
        me(),
        env.broker_dir.clone(),
        existing.clone(),
    );
    assert_eq!(
        Broker::bind(config, Arc::new(env.fake.clone())).err(),
        Some(BrokerError::Socket)
    );
    assert_eq!(std::fs::read_to_string(&existing).unwrap(), "keep me");

    let socket = env._dir.path().join("live.sock");
    let config = BrokerConfig::new(
        env.state_dir.clone(),
        me(),
        env.broker_dir.clone(),
        socket.clone(),
    );
    let first = Broker::bind(config.clone(), Arc::new(env.fake.clone())).unwrap();
    assert_eq!(
        Broker::bind(config.clone(), Arc::new(env.fake.clone())).err(),
        Some(BrokerError::AlreadyRunning)
    );
    drop(first);
    // A stale socket file left by a crash is replaced.
    assert!(Broker::bind(config, Arc::new(env.fake.clone())).is_ok());
}

#[test]
fn broker_with_corrupt_state_fails_closed() {
    if me() == 0 {
        return;
    }
    let env = env();
    let path = env.state_dir.join("state.json");
    std::fs::write(&path, "{ corrupt").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (socket, handle) = start_broker(&env, me(), 1);
    let response = ask(&socket, Op::Apply, None);
    assert_eq!(response.code, ServerError::State.code());
    assert!(env.fake.mutating().is_empty());
    handle.join().unwrap();
}

#[test]
fn resolve_user_reads_passwd_without_nss() {
    assert_eq!(broker::resolve_user("root"), Some(0));
    assert_eq!(broker::resolve_user("definitely-not-a-user-lovpn"), None);
}

#[test]
fn apply_on_start_restores_persisted_state_after_a_reboot_and_keeps_the_rollback_guard() {
    let env = env();
    env.add_peer("laptop");
    let socket = env._dir.path().join("start.sock");
    let mut config = BrokerConfig::new(
        env.state_dir.clone(),
        me(),
        env.broker_dir.clone(),
        socket.clone(),
    );
    config.ip_forward_path = env.ip_forward.clone();
    let broker = Broker::bind(config, Arc::new(env.fake.clone())).unwrap();
    // A fresh boot: no interface, no tables. Starting the broker brings the server back.
    assert!(env.fake.host().interface.is_none());
    assert!(broker.apply_on_start());
    {
        let host = env.fake.host(); // a guard: must not be held across the next apply
        assert!(host.interface.is_some() && host.up && host.peers.len() == 1);
        assert_eq!(host.tables.len(), 2);
    }

    // The anti-rollback record still applies at startup: an older state is refused and
    // the host is left as it was.
    let older = env.state();
    env.add_peer("phone");
    assert!(broker.apply_on_start());
    let newer_generation = env.state().generation;
    std::fs::write(
        env.state_dir.join("state.json"),
        serde_json::to_vec(&older).unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(
        env.state_dir.join("state.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(!broker.apply_on_start());
    assert_eq!(
        env.fake.host().peers.len(),
        2,
        "the refused rollback changed nothing"
    );
    assert!(newer_generation > older.generation);
}

#[test]
fn apply_on_start_without_state_is_logged_not_fatal() {
    let env = env();
    std::fs::remove_file(env.state_dir.join("state.json")).unwrap();
    let socket = env._dir.path().join("empty.sock");
    let config = BrokerConfig::new(env.state_dir.clone(), me(), env.broker_dir.clone(), socket);
    let broker = Broker::bind(config, Arc::new(env.fake.clone())).unwrap();
    assert!(!broker.apply_on_start());
    assert!(env.fake.mutating().is_empty());
}
