//! A stateful fake host for the client engine: links, routes, policy rules, nftables,
//! WireGuard and systemd-resolved. Unprivileged; supports failure injection.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]
use lovpn_client::{
    Engine,
    dns::{DnsBackend, Kind},
    profiles::ProfileStore,
    record::RecordStore,
};
use lovpn_keys::{ClientPrivateKey, ServerPrivateKey};
use lovpn_sys::exec::{Cmd, CmdOutput, ExecError, Program, Runner};
use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex, atomic::AtomicU64},
    time::Duration,
};

pub const MARK: &str = "0x4c6f";
pub const TABLE: &str = "19567";
pub const NOW: u64 = 1_000_000;

#[derive(Clone, Debug, PartialEq)]
pub struct SimRule {
    pub priority: u64,
    pub not_mark: bool,
    pub table: Option<String>,
    pub unreachable: bool,
}

pub struct Link {
    pub kind: String,
    pub up: bool,
    pub mtu: u32,
    pub addresses: Vec<String>,
}

pub struct Host {
    pub link: Option<(String, Link)>,
    pub tunnel_default: bool,
    pub foreign_route: bool,
    pub rules4: Vec<SimRule>,
    pub rules6: Vec<SimRule>,
    pub uplink_up: bool,
    pub v6_main: bool,
    pub tables: BTreeMap<String, String>,
    pub handshake_ts: u64,
    pub wg_peer: Option<String>,
    pub wg_fwmark: Option<String>,
    pub dns: BTreeMap<String, (Vec<String>, Vec<String>, bool)>,
    pub resolved_ok: bool,
    pub log: Vec<String>,
    pub stdin_seen: Vec<String>,
    pub fail_step: Option<&'static str>,
    pub blind_step: Option<&'static str>,
    pub nudges: u32,
}

impl Default for Host {
    fn default() -> Self {
        Self {
            link: None,
            tunnel_default: false,
            foreign_route: false,
            rules4: Vec::new(),
            rules6: Vec::new(),
            uplink_up: true,
            v6_main: true,
            tables: BTreeMap::new(),
            handshake_ts: 0,
            wg_peer: None,
            wg_fwmark: None,
            dns: BTreeMap::new(),
            resolved_ok: true,
            log: Vec::new(),
            stdin_seen: Vec::new(),
            fail_step: None,
            blind_step: None,
            nudges: 0,
        }
    }
}

#[derive(Clone, Default)]
pub struct Fake(pub Arc<Mutex<Host>>);

impl Fake {
    pub fn host(&self) -> std::sync::MutexGuard<'_, Host> {
        self.0.lock().unwrap()
    }

    /// Every command that is not a read-only inspection.
    pub fn mutating(&self) -> Vec<String> {
        self.host()
            .log
            .iter()
            .filter(|l| {
                !(l.contains(" show ")
                    || l.contains("list table")
                    || l.contains("route get")
                    || l.contains(" rule show")
                    || l.starts_with("resolvectl status")
                    || (l.starts_with("resolvectl dns ") && l.split(' ').count() == 3)
                    || (l.starts_with("resolvectl domain ") && l.split(' ').count() == 3)
                    || (l.starts_with("resolvectl default-route ") && l.split(' ').count() == 3))
            })
            .cloned()
            .collect()
    }

    pub fn clear_log(&self) {
        self.host().log.clear();
    }
}

fn ok(stdout: impl Into<String>) -> Result<CmdOutput, ExecError> {
    Ok(CmdOutput {
        success: true,
        stdout: stdout.into(),
    })
}

fn no() -> Result<CmdOutput, ExecError> {
    Ok(CmdOutput {
        success: false,
        stdout: String::new(),
    })
}

fn rule_json(rules: &[SimRule]) -> String {
    let items: Vec<String> = rules
        .iter()
        .map(|r| {
            let mut fields = vec![
                format!("\"priority\":{}", r.priority),
                "\"src\":\"all\"".to_string(),
            ];
            if r.not_mark {
                fields.push("\"not\":null".into());
                fields.push(format!("\"fwmark\":\"{MARK}\""));
            }
            if let Some(table) = &r.table {
                fields.push(format!("\"table\":\"{table}\""));
            }
            if r.unreachable {
                fields.push("\"action\":\"unreachable\"".into());
            }
            format!("{{{}}}", fields.join(","))
        })
        .collect();
    format!("[{}]", items.join(","))
}

impl Host {
    fn iface(&self) -> Option<&str> {
        self.link.as_ref().map(|(n, _)| n.as_str())
    }

    fn route_get_unmarked_v4(&self) -> Option<String> {
        let mut rules = self.rules4.clone();
        rules.sort_by_key(|r| r.priority);
        for rule in rules.iter().filter(|r| r.not_mark) {
            if rule.table.as_deref() == Some(TABLE) {
                if self.tunnel_default
                    && let Some(name) = self.iface()
                {
                    return Some(name.to_string());
                }
            } else if rule.unreachable {
                return None;
            }
        }
        self.uplink_up.then(|| "eth0".to_string())
    }

    fn route_table_json(&self) -> String {
        let mut routes = Vec::new();
        if self.tunnel_default
            && let Some(name) = self.iface()
        {
            routes.push(format!(r#"{{"dst":"default","dev":"{name}"}}"#));
        }
        if self.foreign_route {
            routes.push(r#"{"dst":"10.0.0.0/8","dev":"eth0"}"#.into());
        }
        format!("[{}]", routes.join(","))
    }

    fn route_get_v6(&self) -> Option<String> {
        if self.rules6.iter().any(|r| r.unreachable) {
            return None;
        }
        self.v6_main.then(|| "eth0".to_string())
    }
}

impl Runner for Fake {
    fn run(&self, cmd: &Cmd, step: &'static str) -> Result<CmdOutput, ExecError> {
        let mut h = self.0.lock().unwrap();
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        let program = match cmd.program {
            Program::Ip => "ip",
            Program::Wg => "wg",
            Program::Nft => "nft",
            Program::Resolvectl => "resolvectl",
        };
        h.log.push(format!("{program} {}", args.join(" ")));
        if h.blind_step == Some(step) {
            return Err(ExecError::ToolMissing);
        }
        if h.fail_step == Some(step) {
            return no();
        }
        let stdin = cmd
            .stdin
            .as_ref()
            .map(|s| String::from_utf8_lossy(s).into_owned());
        if let Some(text) = &stdin {
            h.stdin_seen.push(text.clone());
        }
        match (cmd.program, args.as_slice()) {
            // ---- links
            (Program::Ip, ["-j", "-d", "link", "show", "dev", name]) => match &h.link {
                Some((n, l)) if n == name => ok(format!(
                    r#"[{{"mtu":{},"flags":[{}],"linkinfo":{{"info_kind":"{}"}}}}]"#,
                    l.mtu,
                    if l.up { "\"UP\"" } else { "" },
                    l.kind
                )),
                _ => no(),
            },
            (Program::Ip, ["link", "add", "dev", name, "type", "wireguard"]) => {
                h.link = Some((
                    (*name).into(),
                    Link {
                        kind: "wireguard".into(),
                        up: false,
                        mtu: 1420,
                        addresses: vec![],
                    },
                ));
                ok("")
            }
            (Program::Ip, ["link", "set", "dev", _, "mtu", mtu, "up"]) => {
                if let Some((_, l)) = h.link.as_mut() {
                    l.mtu = mtu.parse().unwrap();
                    l.up = true;
                }
                ok("")
            }
            (Program::Ip, ["link", "del", "dev", name]) => {
                if h.iface() == Some(name) {
                    h.link = None;
                    h.tunnel_default = false; // routes die with the link
                    h.handshake_ts = 0;
                }
                ok("")
            }
            (Program::Ip, ["-j", "-4", "addr", "show", "dev", _]) => {
                let infos: Vec<String> = h
                    .link
                    .iter()
                    .flat_map(|(_, l)| l.addresses.iter())
                    .map(|a| {
                        let (ip, p) = a.split_once('/').unwrap();
                        format!(r#"{{"family":"inet","local":"{ip}","prefixlen":{p}}}"#)
                    })
                    .collect();
                ok(format!(r#"[{{"addr_info":[{}]}}]"#, infos.join(",")))
            }
            (Program::Ip, ["addr", op, cidr, "dev", _]) => {
                if let Some((_, l)) = h.link.as_mut() {
                    if *op == "add" {
                        l.addresses.push((*cidr).into());
                    } else {
                        l.addresses.retain(|a| a != cidr);
                    }
                }
                ok("")
            }
            // ---- routes and rules
            (Program::Ip, ["route", "replace", "default", "dev", _, "table", t]) if *t == TABLE => {
                h.tunnel_default = true;
                ok("")
            }
            (Program::Ip, ["route", "flush", "table", t]) if *t == TABLE => {
                h.tunnel_default = false;
                ok("")
            }
            (Program::Ip, ["-j", "route", "show", "table", t]) if *t == TABLE => {
                ok(h.route_table_json())
            }
            (Program::Ip, ["route", "del", "default", "dev", _, "table", t]) if *t == TABLE => {
                h.tunnel_default = false;
                ok("")
            }
            (Program::Ip, ["-j", "rule", "show"]) => ok(rule_json(&h.rules4)),
            (Program::Ip, ["-j", "-6", "rule", "show"]) => ok(rule_json(&h.rules6)),
            (Program::Ip, ["rule", "add", "priority", p, "not", "fwmark", m, rest @ ..])
                if *m == MARK =>
            {
                let rule = SimRule {
                    priority: p.parse().unwrap(),
                    not_mark: true,
                    table: (rest.first() == Some(&"table")).then(|| rest[1].to_string()),
                    unreachable: rest == ["unreachable"],
                };
                h.rules4.push(rule);
                ok("")
            }
            (Program::Ip, ["-6", "rule", "add", "priority", p, "unreachable"]) => {
                h.rules6.push(SimRule {
                    priority: p.parse().unwrap(),
                    not_mark: false,
                    table: None,
                    unreachable: true,
                });
                ok("")
            }
            (Program::Ip, ["rule", "del", "priority", p]) => {
                let p: u64 = p.parse().unwrap();
                h.rules4.retain(|r| r.priority != p);
                ok("")
            }
            (Program::Ip, ["-6", "rule", "del", "priority", p]) => {
                let p: u64 = p.parse().unwrap();
                h.rules6.retain(|r| r.priority != p);
                ok("")
            }
            (Program::Ip, ["-j", "route", "get", _, "mark", m]) if *m == MARK => {
                if h.uplink_up {
                    ok(r#"[{"dev":"eth0"}]"#)
                } else {
                    no()
                }
            }
            (Program::Ip, ["-j", "route", "get", _]) => match h.route_get_unmarked_v4() {
                Some(dev) => ok(format!(r#"[{{"dev":"{dev}"}}]"#)),
                None => no(),
            },
            (Program::Ip, ["-j", "-6", "route", "get", _]) => match h.route_get_v6() {
                Some(dev) => ok(format!(r#"[{{"dev":"{dev}"}}]"#)),
                None => no(),
            },
            // ---- wireguard
            (Program::Wg, ["syncconf", name, "/dev/stdin"]) => {
                if h.iface() != Some(name) {
                    return no();
                }
                let text = stdin.unwrap();
                h.wg_fwmark = text
                    .lines()
                    .find_map(|l| l.strip_prefix("FwMark = "))
                    .map(String::from);
                h.wg_peer = text
                    .lines()
                    .find_map(|l| l.strip_prefix("PublicKey = "))
                    .map(String::from);
                ok("")
            }
            (Program::Wg, ["show", _, "latest-handshakes"]) => match (&h.wg_peer, h.link.is_some())
            {
                (Some(peer), true) => ok(format!("{peer}\t{}\n", h.handshake_ts)),
                _ => no(),
            },
            (Program::Wg, ["show", _, "transfer"]) => match (&h.wg_peer, h.link.is_some()) {
                (Some(peer), true) => ok(format!("{peer}\t1234\t5678\n")),
                _ => no(),
            },
            (Program::Wg, ["set", _, "peer", _, "persistent-keepalive", _]) => {
                h.nudges += 1;
                ok("")
            }
            // ---- nftables
            (Program::Nft, ["list", "table", "inet", "lovpn_client"]) => {
                match h.tables.get("inet lovpn_client") {
                    None => no(),
                    Some(c) if c.is_empty() => ok("table inet lovpn_client {\n}\n"),
                    Some(c) => ok(format!(
                        "table inet lovpn_client {{\n\tcomment \"{c}\"\n}}\n"
                    )),
                }
            }
            (Program::Nft, ["-f", "-"]) => {
                let text = stdin.unwrap();
                for line in text.lines() {
                    if let Some(rest) = line.strip_prefix("add table ")
                        && let Some((head, tail)) = rest.split_once(" { comment \"")
                    {
                        h.tables
                            .insert(head.to_string(), tail.trim_end_matches("\"; }").to_string());
                    }
                }
                ok("")
            }
            (Program::Nft, ["delete", "table", "inet", "lovpn_client"]) => {
                h.tables.remove("inet lovpn_client");
                ok("")
            }
            // ---- resolved
            (Program::Resolvectl, ["status", "--no-pager"]) => {
                if h.resolved_ok {
                    ok("Global\n")
                } else {
                    no()
                }
            }
            (Program::Resolvectl, ["dns", name, servers @ ..]) if !servers.is_empty() => {
                h.dns.entry((*name).into()).or_default().0 =
                    servers.iter().map(|s| s.to_string()).collect();
                ok("")
            }
            (Program::Resolvectl, ["domain", name, d]) => {
                h.dns.entry((*name).into()).or_default().1 = vec![d.to_string()];
                ok("")
            }
            (Program::Resolvectl, ["default-route", name, v]) => {
                h.dns.entry((*name).into()).or_default().2 = *v == "yes";
                ok("")
            }
            (Program::Resolvectl, ["flush-caches"]) => ok(""),
            (Program::Resolvectl, ["revert", name]) => {
                h.dns.remove(*name);
                ok("")
            }
            (Program::Resolvectl, ["dns", name]) => match h.dns.get(*name) {
                Some((d, _, _)) => ok(format!("Link 3 ({name}): {}\n", d.join(" "))),
                None => ok(format!("Link 3 ({name}):\n")),
            },
            (Program::Resolvectl, ["domain", name]) => match h.dns.get(*name) {
                Some((_, d, _)) => ok(format!("Link 3 ({name}): {}\n", d.join(" "))),
                None => ok(format!("Link 3 ({name}):\n")),
            },
            (Program::Resolvectl, ["default-route", name]) => match h.dns.get(*name) {
                Some((_, _, r)) => ok(format!(
                    "Link 3 ({name}): {}\n",
                    if *r { "yes" } else { "no" }
                )),
                None => ok(format!("Link 3 ({name}): no\n")),
            },
            _ => panic!("unexpected command: {:?}", h.log.last()),
        }
    }
}

// ------------------------------------------------------------------- fixtures ----

pub struct Lab {
    pub dir: tempfile::TempDir,
    pub fake: Fake,
    pub engine: Engine,
    pub server_public: String,
    pub client_private: String,
    pub clock: Arc<AtomicU64>,
}

pub fn private_dir(path: &std::path::Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

pub fn profile_text(server_public: &str, kill_switch: &str, extra: &str) -> String {
    format!(
        "schema_version = 1\n\n[profile]\nname = \"Test Server\"\nendpoint = \"192.0.2.1:51820\"\nserver_public_key = \"{server_public}\"\n\n[tunnel]\ninterface = \"lovpn0\"\naddresses = [\"10.66.0.2/32\"]\nmtu = 1380\nrouting = \"full\"\nroutes = [\"0.0.0.0/0\"]\nipv6 = \"block\"\n{extra}\n[dns]\nservers = [\"10.66.0.1\"]\n\n[firewall]\nkill_switch = \"{kill_switch}\"\n"
    )
}

impl Lab {
    pub fn new() -> Self {
        Self::with_dns(Kind::Resolved)
    }

    pub fn with_dns(kind: Kind) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let profiles = state.join("profiles");
        private_dir(&state);
        private_dir(&profiles);
        // resolv.conf -> resolved's directory, as on a systemd-resolved host.
        let resolve_dir = dir.path().join("resolve");
        std::fs::create_dir_all(&resolve_dir).unwrap();
        std::fs::write(
            resolve_dir.join("stub-resolv.conf"),
            "nameserver 127.0.0.53\n",
        )
        .unwrap();
        let resolv_conf = dir.path().join("resolv.conf");
        std::os::unix::fs::symlink(resolve_dir.join("stub-resolv.conf"), &resolv_conf).unwrap();
        let mut dns = DnsBackend::new(kind);
        dns.resolv_conf = resolv_conf;
        dns.resolved_dir = std::fs::canonicalize(&resolve_dir).unwrap();
        let fake = Fake::default();
        let clock = Arc::new(AtomicU64::new(NOW));
        let clock_for_engine = Arc::clone(&clock);
        let engine = Engine::new(
            Arc::new(fake.clone()),
            ProfileStore::open(&profiles).unwrap(),
            RecordStore::open(&state).unwrap(),
            dns,
            Duration::ZERO,
            Box::new(move || clock_for_engine.load(std::sync::atomic::Ordering::SeqCst)),
        );
        Self {
            dir,
            fake,
            engine,
            server_public: ServerPrivateKey::generate()
                .unwrap()
                .public_key()
                .to_string(),
            client_private: ClientPrivateKey::generate()
                .unwrap()
                .expose_base64()
                .to_string(),
            clock,
        }
    }

    pub fn import(&mut self, name: &str, kill_switch: &str) {
        let text = profile_text(&self.server_public, kill_switch, "");
        self.engine
            .import_profile(name, &text, &self.client_private, &self.server_public)
            .unwrap();
    }

    pub fn advance(&self, secs: u64) {
        self.clock
            .fetch_add(secs, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn now(&self) -> u64 {
        self.clock.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn state_dir(&self) -> PathBuf {
        self.dir.path().join("state")
    }
}
