//! Applies server state to the host and observes the result (Linux, privileged).
//!
//! Only the broker may call this. Every external action is one of three fixed
//! programs (`ip`, `wg`, `nft`) run **without a shell**, with an absolute path found
//! in a fixed directory list, a cleared environment and arguments built from values
//! that were validated when the state was created. Nothing is read from profiles or
//! requests. The WireGuard private key reaches `wg` only through its standard input.
//!
//! Ownership: LoVPN only changes an interface that its own record says it created
//! and that really is a WireGuard link, and only nftables tables carrying the
//! `lovpn-owned` comment. Anything else is reported as foreign and left alone.
use crate::{ServerError, ServerState};
use lovpn_firewall::server::{FILTER_TABLE, NAT_TABLE, OWNER_COMMENT};
use lovpn_keys::ServerPrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const DEFAULT_IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_OUTPUT: u64 = 1 << 20;
const RECORD_FILE: &str = "applied.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Program {
    Ip,
    Wg,
    Nft,
}

impl Program {
    fn name(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Wg => "wg",
            Self::Nft => "nft",
        }
    }
}

pub struct Cmd {
    pub program: Program,
    pub args: Vec<String>,
    /// Secret-bearing input (WireGuard config, nft batch). Zeroized after use.
    pub stdin: Option<Zeroizing<Vec<u8>>>,
}

pub struct CmdOutput {
    pub success: bool,
    pub stdout: String,
}

/// Sanitized: names the step, never arguments, output or secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyError {
    ToolMissing,
    CommandFailed(&'static str),
    ForeignInterface,
    ForeignTable,
    Rollback,
    Record,
    Forwarding,
    State(ServerError),
}

impl ApplyError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ToolMissing => "apply.tool-missing",
            Self::CommandFailed(_) => "apply.command-failed",
            Self::ForeignInterface => "apply.foreign-interface",
            Self::ForeignTable => "apply.foreign-table",
            Self::Rollback => "state.rollback",
            Self::Record => "apply.record",
            Self::Forwarding => "apply.forwarding",
            Self::State(error) => error.code(),
        }
    }
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolMissing => f.write_str("A required system tool (ip, wg or nft) was not found in a standard location."),
            Self::CommandFailed(step) => write!(f, "A network configuration step failed ({step}); changes made in this run were rolled back where possible. Run diagnostics for details."),
            Self::ForeignInterface => f.write_str("An interface with the LoVPN name exists but LoVPN did not create it (or it is not WireGuard). It was not modified."),
            Self::ForeignTable => f.write_str("An nftables table with a LoVPN table name exists without the LoVPN ownership marker. It was not modified."),
            Self::Rollback => f.write_str("The state is older than what was already applied (possible rollback to an old backup). Refusing to apply."),
            Self::Record => f.write_str("The broker's own record could not be read or written safely."),
            Self::Forwarding => f.write_str("IPv4 forwarding could not be read or enabled."),
            Self::State(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ApplyError {}

impl From<ServerError> for ApplyError {
    fn from(error: ServerError) -> Self {
        Self::State(error)
    }
}

/// Executes fixed commands. Tests substitute a fake.
pub trait Runner: Send + Sync {
    fn run(&self, cmd: &Cmd, step: &'static str) -> Result<CmdOutput, ApplyError>;
}

pub struct SystemRunner;

fn find_program(program: Program) -> Option<PathBuf> {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .iter()
        .map(|dir| Path::new(dir).join(program.name()))
        .find(|path| path.is_file())
}

impl Runner for SystemRunner {
    fn run(&self, cmd: &Cmd, step: &'static str) -> Result<CmdOutput, ApplyError> {
        let path = find_program(cmd.program).ok_or(ApplyError::ToolMissing)?;
        let failed = |_| ApplyError::CommandFailed(step);
        let mut child = Command::new(path)
            .args(&cmd.args)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(if cmd.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(failed)?;
        let stdin_thread = cmd.stdin.as_ref().and_then(|input| {
            let mut pipe = child.stdin.take()?;
            let data = Zeroizing::new(input.to_vec());
            Some(std::thread::spawn(move || {
                let _ = pipe.write_all(&data);
            }))
        });
        let stdout = child.stdout.take();
        let reader = std::thread::spawn(move || {
            let mut text = Vec::new();
            if let Some(out) = stdout {
                let mut limited = out.take(MAX_OUTPUT);
                let _ = limited.read_to_end(&mut text);
                let _ = std::io::copy(&mut limited.into_inner(), &mut std::io::sink());
            }
            text
        });
        let start = Instant::now();
        let status = loop {
            match child.try_wait().map_err(failed)? {
                Some(status) => break status,
                None if start.elapsed() > COMMAND_TIMEOUT => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ApplyError::CommandFailed(step));
                }
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        };
        if let Some(thread) = stdin_thread {
            let _ = thread.join();
        }
        let stdout = reader.join().map_err(|_| ApplyError::CommandFailed(step))?;
        Ok(CmdOutput {
            success: status.success(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
        })
    }
}

/// The broker's own durable record. Lives in a directory the unprivileged service
/// user cannot write, so it also gives rollback protection to the owner-writable
/// state.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Record {
    pub schema_version: u32,
    /// Highest state generation ever applied; never decreases, survives teardown.
    pub last_applied_generation: u64,
    /// Interface name this broker created and may modify or delete.
    pub interface_owned: Option<String>,
    /// `ip_forward` value to restore on teardown, if we changed it.
    pub previous_ip_forward: Option<String>,
}

pub struct Applier<'a> {
    pub runner: &'a dyn Runner,
    pub broker_dir: PathBuf,
    pub ip_forward_path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApplyReport {
    pub generation: u64,
    pub interface_created: bool,
    pub forwarding_enabled_by_us: bool,
    pub peers: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct TeardownReport {
    pub interface_removed: bool,
    pub tables_removed: Vec<String>,
    pub tables_skipped_foreign: Vec<String>,
    pub forwarding_restored: bool,
}

fn run_ok(
    runner: &dyn Runner,
    program: Program,
    args: &[&str],
    step: &'static str,
) -> Result<String, ApplyError> {
    let cmd = Cmd {
        program,
        args: args.iter().map(ToString::to_string).collect(),
        stdin: None,
    };
    let out = runner.run(&cmd, step)?;
    if out.success {
        Ok(out.stdout)
    } else {
        Err(ApplyError::CommandFailed(step))
    }
}

fn run_ok_stdin(
    runner: &dyn Runner,
    program: Program,
    args: &[&str],
    input: Zeroizing<Vec<u8>>,
    step: &'static str,
) -> Result<(), ApplyError> {
    let cmd = Cmd {
        program,
        args: args.iter().map(ToString::to_string).collect(),
        stdin: Some(input),
    };
    if runner.run(&cmd, step)?.success {
        Ok(())
    } else {
        Err(ApplyError::CommandFailed(step))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableState {
    Absent,
    Foreign,
    Owned { generation: Option<u64> },
}

/// Classify `nft list table` output. Pure and unit-tested.
pub fn classify_table(success: bool, listing: &str) -> TableState {
    if !success {
        return TableState::Absent;
    }
    for line in listing.lines() {
        let line = line.trim();
        let text = line
            .strip_prefix("comment \"")
            .and_then(|rest| rest.strip_suffix('"'));
        if let Some(text) = text
            && (text == OWNER_COMMENT || text.starts_with(&format!("{OWNER_COMMENT} ")))
        {
            let generation = text
                .split_whitespace()
                .find_map(|word| word.strip_prefix("gen="))
                .and_then(|value| value.parse().ok());
            return TableState::Owned { generation };
        }
    }
    TableState::Foreign
}

fn table_state(runner: &dyn Runner, family: &str, name: &str) -> Result<TableState, ApplyError> {
    let cmd = Cmd {
        program: Program::Nft,
        args: ["list", "table", family, name].map(String::from).to_vec(),
        stdin: None,
    };
    let out = runner.run(&cmd, "inspect-firewall")?;
    Ok(classify_table(out.success, &out.stdout))
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct LinkObservation {
    pub present: bool,
    pub wireguard: bool,
    pub mtu: Option<u32>,
    pub up: bool,
}

pub fn parse_link(success: bool, json: &str) -> LinkObservation {
    if !success {
        return LinkObservation::default();
    }
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(json) else {
        return LinkObservation::default();
    };
    let Some(link) = items.first() else {
        return LinkObservation::default();
    };
    LinkObservation {
        present: true,
        wireguard: link["linkinfo"]["info_kind"] == "wireguard",
        mtu: link["mtu"].as_u64().and_then(|v| u32::try_from(v).ok()),
        up: link["flags"]
            .as_array()
            .is_some_and(|flags| flags.iter().any(|f| f == "UP")),
    }
}

/// `(local address, prefix length)` pairs of IPv4 addresses on a link.
pub fn parse_addresses(json: &str) -> Vec<(String, u64)> {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    items
        .iter()
        .flat_map(|link| link["addr_info"].as_array().cloned().unwrap_or_default())
        .filter(|a| a["family"] == "inet")
        .filter_map(|a| Some((a["local"].as_str()?.to_string(), a["prefixlen"].as_u64()?)))
        .collect()
}

fn observe_link(runner: &dyn Runner, interface: &str) -> Result<LinkObservation, ApplyError> {
    let cmd = Cmd {
        program: Program::Ip,
        args: ["-j", "-d", "link", "show", "dev", interface]
            .map(String::from)
            .to_vec(),
        stdin: None,
    };
    let out = runner.run(&cmd, "inspect-interface")?;
    Ok(parse_link(out.success, &out.stdout))
}

/// WireGuard configuration for `wg syncconf`: contains the private key, so it is only
/// ever handed to `wg` through stdin and zeroized afterwards.
pub fn wireguard_config(state: &ServerState, key: &ServerPrivateKey) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::new());
    text.push_str("[Interface]\nPrivateKey = ");
    text.push_str(&key.expose_base64());
    text.push_str(&format!("\nListenPort = {}\n", state.server.listen_port));
    for peer in state.active_peers() {
        text.push_str(&format!(
            "\n[Peer]\nPublicKey = {}\nAllowedIPs = {}/32\n",
            peer.public_key, peer.address
        ));
    }
    text
}

fn record_path(dir: &Path) -> PathBuf {
    dir.join(RECORD_FILE)
}

impl Applier<'_> {
    pub fn load_record(&self) -> Result<Record, ApplyError> {
        let path = record_path(&self.broker_dir);
        let dir = std::fs::metadata(&self.broker_dir).map_err(|_| ApplyError::Record)?;
        if !dir.is_dir()
            || dir.mode() & 0o077 != 0
            || dir.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(ApplyError::Record);
        }
        match std::fs::read(&path) {
            Ok(bytes) if bytes.len() < 4096 => {
                let record: Record =
                    serde_json::from_slice(&bytes).map_err(|_| ApplyError::Record)?;
                if record.schema_version != 1 {
                    return Err(ApplyError::Record);
                }
                Ok(record)
            }
            Ok(_) => Err(ApplyError::Record),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Record {
                schema_version: 1,
                ..Record::default()
            }),
            Err(_) => Err(ApplyError::Record),
        }
    }

    fn save_record(&self, record: &Record) -> Result<(), ApplyError> {
        let temp = self.broker_dir.join("applied.json.tmp");
        let _ = std::fs::remove_file(&temp);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|_| ApplyError::Record)?;
        let json = serde_json::to_vec_pretty(record).map_err(|_| ApplyError::Record)?;
        file.write_all(&json)
            .and_then(|()| file.sync_all())
            .map_err(|_| ApplyError::Record)?;
        std::fs::rename(&temp, record_path(&self.broker_dir)).map_err(|_| ApplyError::Record)?;
        std::fs::File::open(&self.broker_dir)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| ApplyError::Record)
    }

    /// Reconcile the host with `state`. Idempotent. On failure, resources created in
    /// this run are removed again.
    pub fn apply(
        &self,
        state: &ServerState,
        key: &ServerPrivateKey,
    ) -> Result<ApplyReport, ApplyError> {
        state.validate()?;
        let mut record = self.load_record()?;
        if state.generation < record.last_applied_generation {
            return Err(ApplyError::Rollback);
        }
        for (family, name) in [("inet", FILTER_TABLE), ("ip", NAT_TABLE)] {
            if table_state(self.runner, family, name)? == TableState::Foreign {
                return Err(ApplyError::ForeignTable);
            }
        }
        let interface = state.server.interface.as_str();
        let link = observe_link(self.runner, interface)?;
        let owned = record.interface_owned.as_deref() == Some(interface);
        if link.present && (!link.wireguard || !owned) {
            return Err(ApplyError::ForeignInterface);
        }
        let mut created = false;
        let mut forwarding_changed = false;
        let result = (|| -> Result<(), ApplyError> {
            if !link.present {
                // Journal intent first: a crash after creation must still be recoverable.
                record.interface_owned = Some(interface.to_string());
                self.save_record(&record)?;
                run_ok(
                    self.runner,
                    Program::Ip,
                    &["link", "add", "dev", interface, "type", "wireguard"],
                    "create-interface",
                )?;
                created = true;
            }
            let config = wireguard_config(state, key);
            run_ok_stdin(
                self.runner,
                Program::Wg,
                &["syncconf", interface, "/dev/stdin"],
                Zeroizing::new(config.as_bytes().to_vec()),
                "configure-wireguard",
            )?;
            self.reconcile_addresses(state)?;
            let mtu = state.server.mtu.to_string();
            run_ok(
                self.runner,
                Program::Ip,
                &["link", "set", "dev", interface, "mtu", &mtu, "up"],
                "bring-up-interface",
            )?;
            forwarding_changed = self.enable_forwarding(&mut record)?;
            let plan = lovpn_firewall::server::compile(&state.firewall_policy())
                .map_err(|_| ApplyError::State(ServerError::Pool))?;
            run_ok_stdin(
                self.runner,
                Program::Nft,
                &["-f", "-"],
                Zeroizing::new(plan.ruleset().as_bytes().to_vec()),
                "apply-firewall",
            )
        })();
        if let Err(error) = result {
            if created {
                let _ = run_ok(
                    self.runner,
                    Program::Ip,
                    &["link", "del", "dev", interface],
                    "rollback-interface",
                );
                record.interface_owned = None;
            }
            if forwarding_changed {
                let _ = self.restore_forwarding(&mut record);
            }
            let _ = self.save_record(&record);
            return Err(error);
        }
        record.last_applied_generation = state.generation;
        self.save_record(&record)?;
        Ok(ApplyReport {
            generation: state.generation,
            interface_created: created,
            forwarding_enabled_by_us: record.previous_ip_forward.is_some(),
            peers: state.active_peers().count(),
        })
    }

    fn reconcile_addresses(&self, state: &ServerState) -> Result<(), ApplyError> {
        let interface = state.server.interface.as_str();
        let prefix = state.server.pool.prefix_len();
        let desired = state.server_address().to_string();
        let listing = run_ok(
            self.runner,
            Program::Ip,
            &["-j", "-4", "addr", "show", "dev", interface],
            "inspect-address",
        )?;
        let present = parse_addresses(&listing);
        for (local, length) in &present {
            if *local != desired || *length != u64::from(prefix) {
                run_ok(
                    self.runner,
                    Program::Ip,
                    &[
                        "addr",
                        "del",
                        &format!("{local}/{length}"),
                        "dev",
                        interface,
                    ],
                    "remove-stale-address",
                )?;
            }
        }
        if !present
            .iter()
            .any(|(l, p)| *l == desired && *p == u64::from(prefix))
        {
            run_ok(
                self.runner,
                Program::Ip,
                &[
                    "addr",
                    "add",
                    &format!("{desired}/{prefix}"),
                    "dev",
                    interface,
                ],
                "add-address",
            )?;
        }
        Ok(())
    }

    fn enable_forwarding(&self, record: &mut Record) -> Result<bool, ApplyError> {
        let current =
            std::fs::read_to_string(&self.ip_forward_path).map_err(|_| ApplyError::Forwarding)?;
        if current.trim() == "1" {
            return Ok(false);
        }
        if record.previous_ip_forward.is_none() {
            record.previous_ip_forward = Some(current.trim().to_string());
            self.save_record(record)?;
        }
        std::fs::write(&self.ip_forward_path, "1\n").map_err(|_| ApplyError::Forwarding)?;
        Ok(true)
    }

    fn restore_forwarding(&self, record: &mut Record) -> Result<bool, ApplyError> {
        let Some(previous) = record.previous_ip_forward.take() else {
            return Ok(false);
        };
        std::fs::write(&self.ip_forward_path, format!("{previous}\n"))
            .map_err(|_| ApplyError::Forwarding)?;
        Ok(true)
    }

    /// Re-install only the firewall tables (the `firewall repair` operation).
    pub fn repair_firewall(&self, state: &ServerState) -> Result<(), ApplyError> {
        let record = self.load_record()?;
        if state.generation < record.last_applied_generation {
            return Err(ApplyError::Rollback);
        }
        for (family, name) in [("inet", FILTER_TABLE), ("ip", NAT_TABLE)] {
            if table_state(self.runner, family, name)? == TableState::Foreign {
                return Err(ApplyError::ForeignTable);
            }
        }
        let plan = lovpn_firewall::server::compile(&state.firewall_policy())
            .map_err(|_| ApplyError::State(ServerError::Pool))?;
        run_ok_stdin(
            self.runner,
            Program::Nft,
            &["-f", "-"],
            Zeroizing::new(plan.ruleset().as_bytes().to_vec()),
            "apply-firewall",
        )
    }

    /// Remove only what the record and ownership markers prove is LoVPN's.
    pub fn teardown(&self) -> Result<TeardownReport, ApplyError> {
        let mut record = self.load_record()?;
        let mut report = TeardownReport {
            interface_removed: false,
            tables_removed: Vec::new(),
            tables_skipped_foreign: Vec::new(),
            forwarding_restored: false,
        };
        for (family, name) in [("inet", FILTER_TABLE), ("ip", NAT_TABLE)] {
            match table_state(self.runner, family, name)? {
                TableState::Absent => {}
                TableState::Foreign => report.tables_skipped_foreign.push(name.to_string()),
                TableState::Owned { .. } => {
                    run_ok(
                        self.runner,
                        Program::Nft,
                        &["delete", "table", family, name],
                        "remove-firewall",
                    )?;
                    report.tables_removed.push(name.to_string());
                }
            }
        }
        if let Some(interface) = record.interface_owned.clone() {
            let link = observe_link(self.runner, &interface)?;
            if link.present && link.wireguard {
                run_ok(
                    self.runner,
                    Program::Ip,
                    &["link", "del", "dev", &interface],
                    "remove-interface",
                )?;
                report.interface_removed = true;
            }
            record.interface_owned = None;
        }
        report.forwarding_restored = self.restore_forwarding(&mut record)?;
        self.save_record(&record)?;
        Ok(report)
    }

    /// Read-only observation compared against `state`. Never mutates anything.
    pub fn observe(&self, state: &ServerState) -> Result<Observation, ApplyError> {
        let record = self.load_record()?;
        let interface = state.server.interface.as_str();
        let link = observe_link(self.runner, interface)?;
        let owned = record.interface_owned.as_deref() == Some(interface);
        let mut reasons: Vec<&'static str> = Vec::new();
        let mut observed_peers: Vec<ObservedPeer> = Vec::new();
        let mut address_ok = false;
        let mut listen_port = None;
        if !link.present {
            reasons.push("interface-missing");
        } else if !link.wireguard || !owned {
            reasons.push("interface-foreign");
        } else {
            if !link.up {
                reasons.push("interface-down");
            }
            if link.mtu != Some(u32::from(state.server.mtu)) {
                reasons.push("mtu-mismatch");
            }
            let listing = run_ok(
                self.runner,
                Program::Ip,
                &["-j", "-4", "addr", "show", "dev", interface],
                "inspect-address",
            )?;
            let addresses = parse_addresses(&listing);
            address_ok = addresses.len() == 1
                && addresses[0].0 == state.server_address().to_string()
                && addresses[0].1 == u64::from(state.server.pool.prefix_len());
            if !address_ok {
                reasons.push("address-mismatch");
            }
            let port = run_ok(
                self.runner,
                Program::Wg,
                &["show", interface, "listen-port"],
                "inspect-wireguard",
            )?;
            listen_port = port.trim().parse::<u16>().ok();
            if listen_port != Some(state.server.listen_port) {
                reasons.push("listen-port-mismatch");
            }
            observed_peers = self.observe_peers(interface)?;
        }
        let desired: BTreeSet<&str> = state
            .active_peers()
            .map(|p| p.public_key.as_str())
            .collect();
        let seen: BTreeSet<&str> = observed_peers
            .iter()
            .map(|p| p.public_key.as_str())
            .collect();
        let missing: Vec<String> = desired.difference(&seen).map(ToString::to_string).collect();
        let unexpected: Vec<String> = seen.difference(&desired).map(ToString::to_string).collect();
        if link.present && link.wireguard && owned {
            if !missing.is_empty() {
                reasons.push("peers-missing");
            }
            if !unexpected.is_empty() {
                reasons.push("peers-unexpected");
            }
        }
        let filter = table_state(self.runner, "inet", FILTER_TABLE)?;
        let nat = table_state(self.runner, "ip", NAT_TABLE)?;
        let firewall_generation = match (filter, nat) {
            (TableState::Owned { generation: a }, TableState::Owned { generation: b })
                if a == b =>
            {
                a
            }
            _ => None,
        };
        match (filter, nat) {
            (TableState::Absent, _) | (_, TableState::Absent) => reasons.push("firewall-missing"),
            (TableState::Foreign, _) | (_, TableState::Foreign) => reasons.push("firewall-foreign"),
            _ if firewall_generation != Some(state.generation) => {
                reasons.push("firewall-generation-mismatch")
            }
            _ => {}
        }
        let forwarding = std::fs::read_to_string(&self.ip_forward_path)
            .ok()
            .map(|v| v.trim() == "1");
        if forwarding != Some(true) {
            reasons.push("forwarding-off");
        }
        if record.last_applied_generation != state.generation {
            reasons.push("state-not-applied");
        }
        Ok(Observation {
            interface_present: link.present,
            interface_owned: owned,
            address_ok,
            listen_port,
            peers: observed_peers,
            peers_missing: missing,
            peers_unexpected: unexpected,
            firewall_generation,
            ip_forward: forwarding,
            last_applied_generation: record.last_applied_generation,
            state_generation: state.generation,
            in_sync: reasons.is_empty(),
            drift: reasons,
        })
    }

    fn observe_peers(&self, interface: &str) -> Result<Vec<ObservedPeer>, ApplyError> {
        let keys = run_ok(
            self.runner,
            Program::Wg,
            &["show", interface, "peers"],
            "inspect-wireguard",
        )?;
        let handshakes = run_ok(
            self.runner,
            Program::Wg,
            &["show", interface, "latest-handshakes"],
            "inspect-wireguard",
        )?;
        let transfer = run_ok(
            self.runner,
            Program::Wg,
            &["show", interface, "transfer"],
            "inspect-wireguard",
        )?;
        let column = |text: &str, key: &str, index: usize| -> u64 {
            text.lines()
                .find_map(|line| {
                    let mut parts = line.split('\t');
                    (parts.next() == Some(key))
                        .then(|| parts.nth(index - 1).and_then(|v| v.trim().parse().ok()))
                })
                .flatten()
                .unwrap_or(0)
        };
        Ok(keys
            .lines()
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .map(|key| ObservedPeer {
                public_key: key.to_string(),
                latest_handshake_unix: column(&handshakes, key, 1),
                rx_bytes: column(&transfer, key, 1),
                tx_bytes: column(&transfer, key, 2),
            })
            .collect())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ObservedPeer {
    pub public_key: String,
    /// Unix seconds; 0 means no handshake yet.
    pub latest_handshake_unix: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    pub interface_present: bool,
    pub interface_owned: bool,
    pub address_ok: bool,
    pub listen_port: Option<u16>,
    pub peers: Vec<ObservedPeer>,
    pub peers_missing: Vec<String>,
    pub peers_unexpected: Vec<String>,
    pub firewall_generation: Option<u64>,
    pub ip_forward: Option<bool>,
    pub last_applied_generation: u64,
    pub state_generation: u64,
    /// True only if every observed property matches `state`. This is observation of
    /// the *server's* configuration, not a statement about any client's protection.
    pub in_sync: bool,
    pub drift: Vec<&'static str>,
}
