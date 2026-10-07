//! The connection engine: connect, disconnect, reconnect, repair, reset and observe.
//!
//! Ordering rules that matter for leaks:
//! 1. the kill switch is installed *before* the tunnel interface exists;
//! 2. routing rules make unmarked traffic fail (not fall back to the main table) when
//!    the tunnel has no route, so even a vanished interface does not leak;
//! 3. reconnecting deletes only the interface: firewall and rules stay in place;
//! 4. an unexpected loss (crash, interface deleted) never removes protection; only an
//!    explicit disconnect does, and `strict` keeps the firewall even then, until the user
//!    releases it.
//!
//! Protection is *observed*: [`Engine::observe`] derives the state from the kernel, never
//! from what was last requested.
pub use crate::model::{
    Check, CheckStatus, ConnectReport, HANDSHAKE_MAX_AGE_SECS, State, Status, TickAction,
    TickReport, derive_state,
};
use crate::{
    ClientError,
    dns::{DnsBackend, DnsObservation},
    plan,
    profiles::{ProfileInfo, ProfileStore, kill_switch_name},
    record::{Desired, RecordStore, SessionRecord},
};
use lovpn_config::{ClientConfig, KillSwitchMode};
use lovpn_firewall::{OWNER_COMMENT, TABLE_NAME};
use lovpn_keys::{ClientPrivateKey, ClientPublicKey, ServerPublicKey};
use lovpn_sys::{
    exec::{Cmd, CmdOutput, Program, Runner},
    inspect::{
        self, LinkObservation, Rule, TableState, parse_addresses, parse_link, parse_route_get,
        parse_routes_checked, parse_rules,
    },
};
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

const PROBE_V4: &str = "1.1.1.1";
const PROBE_V6: &str = "2001:db8::1";

pub struct Engine {
    runner: Arc<dyn Runner>,
    profiles: ProfileStore,
    records: RecordStore,
    dns: DnsBackend,
    handshake_wait: Duration,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

fn mode_of(config: &ClientConfig) -> &'static str {
    kill_switch_name(config.firewall.kill_switch)
}

fn check(name: &'static str, status: CheckStatus, detail: impl Into<String>) -> Check {
    Check {
        name,
        status,
        detail: detail.into(),
    }
}

impl Engine {
    pub fn new(
        runner: Arc<dyn Runner>,
        profiles: ProfileStore,
        records: RecordStore,
        dns: DnsBackend,
        handshake_wait: Duration,
        clock: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            runner,
            profiles,
            records,
            dns,
            handshake_wait,
            clock,
        }
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    // ------------------------------------------------------------ plumbing ----

    fn exec(&self, cmd: &Cmd, step: &'static str) -> Result<CmdOutput, ClientError> {
        Ok(self.runner.run(cmd, step)?)
    }

    fn exec_ok(
        &self,
        program: Program,
        args: &[&str],
        step: &'static str,
    ) -> Result<String, ClientError> {
        let out = self.exec(&Cmd::new(program, args), step)?;
        if out.success {
            Ok(out.stdout)
        } else {
            Err(ClientError::CommandFailed(step))
        }
    }

    fn exec_stdin(
        &self,
        program: Program,
        args: &[&str],
        input: Zeroizing<Vec<u8>>,
        step: &'static str,
    ) -> Result<(), ClientError> {
        let out = self.exec(&Cmd::new(program, args).with_stdin(input), step)?;
        if out.success {
            Ok(())
        } else {
            Err(ClientError::CommandFailed(step))
        }
    }

    fn firewall_state(&self) -> Result<TableState, ClientError> {
        let out = self.exec(
            &Cmd::new(Program::Nft, &["list", "table", "inet", TABLE_NAME]),
            "inspect-firewall",
        )?;
        Ok(inspect::classify_table(
            out.success,
            &out.stdout,
            OWNER_COMMENT,
        ))
    }

    fn link(&self, interface: &str) -> Result<LinkObservation, ClientError> {
        let out = self.exec(
            &Cmd::new(Program::Ip, &["-j", "-d", "link", "show", "dev", interface]),
            "inspect-interface",
        )?;
        Ok(parse_link(out.success, &out.stdout))
    }

    fn rules(&self, v6: bool) -> Result<Vec<Rule>, ClientError> {
        let args: &[&str] = if v6 {
            &["-j", "-6", "rule", "show"]
        } else {
            &["-j", "rule", "show"]
        };
        let out = self.exec(&Cmd::new(Program::Ip, args), "inspect-rules")?;
        Ok(if out.success {
            parse_rules(&out.stdout)
        } else {
            Vec::new()
        })
    }

    fn save(&self, record: &mut SessionRecord) -> Result<(), ClientError> {
        record.updated_unix = self.now();
        self.records.save(record)
    }

    // ------------------------------------------------------------- profiles ----

    pub fn list_profiles(&self) -> Result<Vec<ProfileInfo>, ClientError> {
        self.profiles.list()
    }

    /// The profile `connect` uses when none is named.
    pub fn selected_profile(&self) -> Result<Option<String>, ClientError> {
        Ok(self.records.load()?.profile)
    }

    /// Choose the default profile without touching the network. Refused while a session
    /// is desired, because the record's profile is what repair and recovery act on.
    pub fn use_profile(&self, name: &str) -> Result<(), ClientError> {
        let mut record = self.records.load()?;
        if record.desired == Desired::Connected {
            return Err(ClientError::SwitchWhileConnected);
        }
        if !self.profiles.list()?.iter().any(|p| p.name == name) {
            return Err(ClientError::ProfileNotFound);
        }
        record.profile = Some(name.to_string());
        self.save(&mut record)
    }

    pub fn import_profile(
        &self,
        name: &str,
        profile_text: &str,
        private_key: &str,
        expected_server_key: &str,
    ) -> Result<ProfileInfo, ClientError> {
        let key =
            ClientPrivateKey::from_base64(private_key).map_err(|_| ClientError::KeyInvalid)?;
        let expected: ServerPublicKey = expected_server_key
            .parse()
            .map_err(|_| ClientError::ServerKeyMismatch)?;
        self.profiles.import(name, profile_text, &key, &expected)
    }

    pub fn remove_profile(&self, name: &str) -> Result<(), ClientError> {
        let record = self.records.load()?;
        if record.profile.as_deref() == Some(name) && record.desired == Desired::Connected {
            return Err(ClientError::NotConnected); // refuse: disconnect first
        }
        self.profiles.remove(name)
    }

    /// The public key matching a stored profile's private key (never the private key).
    pub fn public_key_of(&self, name: &str) -> Result<ClientPublicKey, ClientError> {
        let (_, key) = self.profiles.load(name)?;
        Ok(key.public_key())
    }

    // -------------------------------------------------------------- connect ----

    pub fn connect(&mut self, name: Option<&str>) -> Result<ConnectReport, ClientError> {
        let mut record = self.records.load()?;
        let name = match name {
            Some(n) => n.to_string(),
            None => record
                .profile
                .clone()
                .ok_or(ClientError::NoProfileSelected)?,
        };
        let (config, key) = self.profiles.load(&name)?;
        plan::check_supported(&config)?;
        if !self.dns.available(self.runner.as_ref()) {
            return Err(ClientError::DnsUnsupported);
        }
        self.preflight(&config, &record)?;
        let interface = config.tunnel.interface.clone();
        let mode = mode_of(&config);

        // A different profile while connected: drop the old tunnel but keep the firewall.
        if record.desired == Desired::Connected && record.profile.as_deref() != Some(&name) {
            self.remove_tunnel(&mut record)?;
        }

        // Intent first: if we crash from here on, the record explains what to clean up.
        record.profile = Some(name.clone());
        record.desired = Desired::Connected;
        record.mode = Some(mode.to_string());
        record.generation += 1;
        record.kill_switch_armed = config.firewall.kill_switch != KillSwitchMode::Off;
        record.interface_owned = Some(interface.clone());
        record.routing_installed = true;
        record.dns_interface = Some(interface);
        self.save(&mut record)?;

        if let Err(error) = self.apply_session(&config, &key, &mut record) {
            // Failed connect must not strand a non-strict user offline.
            let _ = self.abort_connect(&mut record, config.firewall.kill_switch);
            return Err(error);
        }
        let handshake_seen = self.wait_for_handshake(&config.tunnel.interface);
        Ok(ConnectReport {
            profile: name,
            handshake_seen,
            kill_switch_armed: record.kill_switch_armed,
        })
    }

    fn abort_connect(
        &self,
        record: &mut SessionRecord,
        mode: KillSwitchMode,
    ) -> Result<(), ClientError> {
        self.remove_tunnel(record)?;
        record.desired = Desired::Disconnected;
        if mode != KillSwitchMode::Strict {
            self.remove_firewall(record)?;
        }
        self.save(record)
    }

    fn preflight(&self, config: &ClientConfig, record: &SessionRecord) -> Result<(), ClientError> {
        if self.firewall_state()? == TableState::Foreign {
            return Err(ClientError::ForeignTable);
        }
        let interface = &config.tunnel.interface;
        let link = self.link(interface)?;
        let owned = record.interface_owned.as_deref() == Some(interface.as_str());
        if link.present && (!link.wireguard || !owned) {
            return Err(ClientError::ForeignInterface);
        }
        for v6 in [false, true] {
            if self.rule_state(v6)? == RuleState::Foreign {
                return Err(ClientError::ForeignRule);
            }
        }
        Ok(())
    }

    /// Idempotent: bring the kernel to the state the profile requires. Used by connect,
    /// repair and the monitor.
    fn apply_session(
        &self,
        config: &ClientConfig,
        key: &ClientPrivateKey,
        record: &mut SessionRecord,
    ) -> Result<(), ClientError> {
        let interface = config.tunnel.interface.as_str();
        let profile = record.profile.clone();

        // 1. Kill switch first, so there is never a window with the tunnel half-built.
        if config.firewall.kill_switch == KillSwitchMode::Off {
            self.remove_firewall(record)?;
        } else {
            let installed = self.firewall_state()?;
            let current = matches!(installed, TableState::Owned { generation: Some(g) } if g == record.firewall_generation)
                && record.firewall_profile == profile;
            if !current {
                let generation = record.generation;
                let plan = lovpn_firewall::compile_owned(config, generation)
                    .map_err(|_| ClientError::ProfileInvalid)?;
                record.firewall_generation = generation;
                record.firewall_profile = profile;
                self.save(record)?;
                self.exec_stdin(
                    Program::Nft,
                    &["-f", "-"],
                    Zeroizing::new(plan.ruleset().as_bytes().to_vec()),
                    "install-kill-switch",
                )?;
            }
        }

        // 2. Interface and WireGuard.
        let link = self.link(interface)?;
        if !link.present {
            self.exec_ok(
                Program::Ip,
                &["link", "add", "dev", interface, "type", "wireguard"],
                "create-interface",
            )?;
        }
        let wg = plan::wireguard_config(config, key);
        self.exec_stdin(
            Program::Wg,
            &["syncconf", interface, "/dev/stdin"],
            Zeroizing::new(wg.as_bytes().to_vec()),
            "configure-wireguard",
        )?;
        self.reconcile_addresses(config)?;
        let mtu = config.tunnel.mtu.to_string();
        self.exec_ok(
            Program::Ip,
            &["link", "set", "dev", interface, "mtu", &mtu, "up"],
            "bring-up-interface",
        )?;

        // 3. Routing: tunnel default route plus fail-closed rules.
        let table = plan::route_table();
        self.exec_ok(
            Program::Ip,
            &[
                "route", "replace", "default", "dev", interface, "table", &table,
            ],
            "install-route",
        )?;
        self.ensure_rules()?;

        // 4. DNS through the tunnel.
        self.dns
            .apply(self.runner.as_ref(), interface, &config.dns.servers)?;
        Ok(())
    }

    fn reconcile_addresses(&self, config: &ClientConfig) -> Result<(), ClientError> {
        let interface = config.tunnel.interface.as_str();
        let desired = plan::tunnel_addresses(config);
        let listing = self.exec_ok(
            Program::Ip,
            &["-j", "-4", "addr", "show", "dev", interface],
            "inspect-address",
        )?;
        let present = parse_addresses(&listing);
        let rendered: Vec<String> = present.iter().map(|(a, p)| format!("{a}/{p}")).collect();
        for stale in rendered.iter().filter(|a| !desired.contains(a)) {
            self.exec_ok(
                Program::Ip,
                &["addr", "del", stale, "dev", interface],
                "remove-stale-address",
            )?;
        }
        for wanted in desired.iter().filter(|a| !rendered.contains(a)) {
            self.exec_ok(
                Program::Ip,
                &["addr", "add", wanted, "dev", interface],
                "add-address",
            )?;
        }
        Ok(())
    }

    fn rule_state(&self, v6: bool) -> Result<RuleState, ClientError> {
        let rules = self.rules(v6)?;
        let mut state = RuleState::Absent;
        let wanted: &[(u64, Want)] = if v6 {
            &[(plan::RULE_LOOKUP_PRIORITY, Want::V6Block)]
        } else {
            &[
                (plan::RULE_LOOKUP_PRIORITY, Want::Lookup),
                (plan::RULE_BLOCK_PRIORITY, Want::Unreachable),
            ]
        };
        let mut ours = 0;
        for (priority, want) in wanted {
            match rules.iter().find(|r| r.priority == *priority) {
                None => {}
                Some(rule) if want.matches(rule) => ours += 1,
                Some(_) => return Ok(RuleState::Foreign),
            }
        }
        if ours == wanted.len() {
            state = RuleState::Complete;
        } else if ours > 0 {
            state = RuleState::Partial;
        }
        Ok(state)
    }

    fn ensure_rules(&self) -> Result<(), ClientError> {
        let (mark, table) = (plan::fwmark_hex(), plan::route_table());
        let (lookup, block) = (
            plan::RULE_LOOKUP_PRIORITY.to_string(),
            plan::RULE_BLOCK_PRIORITY.to_string(),
        );
        let v4 = self.rules(false)?;
        if !v4.iter().any(|r| r.priority == plan::RULE_LOOKUP_PRIORITY) {
            self.exec_ok(
                Program::Ip,
                &[
                    "rule", "add", "priority", &lookup, "not", "fwmark", &mark, "table", &table,
                ],
                "install-rule",
            )?;
        }
        if !v4.iter().any(|r| r.priority == plan::RULE_BLOCK_PRIORITY) {
            self.exec_ok(
                Program::Ip,
                &[
                    "rule",
                    "add",
                    "priority",
                    &block,
                    "not",
                    "fwmark",
                    &mark,
                    "unreachable",
                ],
                "install-rule",
            )?;
        }
        let v6 = self.rules(true)?;
        if !v6.iter().any(|r| r.priority == plan::RULE_LOOKUP_PRIORITY) {
            self.exec_ok(
                Program::Ip,
                &["-6", "rule", "add", "priority", &lookup, "unreachable"],
                "install-rule",
            )?;
        }
        if self.rule_state(false)? == RuleState::Foreign
            || self.rule_state(true)? == RuleState::Foreign
        {
            return Err(ClientError::ForeignRule);
        }
        Ok(())
    }

    fn wait_for_handshake(&self, interface: &str) -> bool {
        let deadline = std::time::Instant::now() + self.handshake_wait;
        loop {
            if self.latest_handshake(interface).is_some_and(|t| t > 0) {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn latest_handshake(&self, interface: &str) -> Option<u64> {
        let out = self
            .exec(
                &Cmd::new(Program::Wg, &["show", interface, "latest-handshakes"]),
                "inspect-wireguard",
            )
            .ok()
            .filter(|o| o.success)?;
        out.stdout
            .lines()
            .next()
            .and_then(|line| line.split('\t').nth(1))
            .and_then(|t| t.trim().parse().ok())
    }

    // ----------------------------------------------------------- teardown ----

    /// Remove DNS, routing and the interface, never the firewall.
    fn remove_tunnel(&self, record: &mut SessionRecord) -> Result<(), ClientError> {
        if let Some(interface) = record.dns_interface.clone() {
            self.dns.revert(self.runner.as_ref(), &interface);
        }
        self.remove_routing(record)?;
        self.remove_interface(record)?;
        record.routing_installed = false;
        record.dns_interface = None;
        Ok(())
    }

    fn remove_routing(&self, record: &SessionRecord) -> Result<(), ClientError> {
        let table = plan::route_table();
        // The table number is reserved by LoVPN, but a number alone is not proof of
        // ownership. Never flush it: inspect first and remove only the exact default
        // route on the interface this record proves that LoVPN created. A corrupt or
        // missing record therefore cannot destroy another application's routes.
        if record.routing_installed {
            let interface = record
                .interface_owned
                .as_deref()
                .ok_or(ClientError::Record)?;
            let listing = self.exec_ok(
                Program::Ip,
                &["-j", "route", "show", "table", &table],
                "inspect-route-table",
            )?;
            let routes = parse_routes_checked(&listing)
                .ok_or(ClientError::CommandFailed("inspect-route-table"))?;
            if routes
                .iter()
                .any(|(destination, dev)| destination != "default" || dev != interface)
                || routes.len() > 1
            {
                return Err(ClientError::ForeignRoute);
            }
            if routes.len() == 1 {
                self.exec_ok(
                    Program::Ip,
                    &["route", "del", "default", "dev", interface, "table", &table],
                    "remove-route",
                )?;
            }
        }
        // Only delete rules that match LoVPN's exact signature.
        for v6 in [false, true] {
            for rule in self.rules(v6)? {
                let ours = if v6 {
                    Want::V6Block.matches(&rule)
                } else {
                    Want::Lookup.matches(&rule) || Want::Unreachable.matches(&rule)
                };
                if ours
                    && (rule.priority == plan::RULE_LOOKUP_PRIORITY
                        || rule.priority == plan::RULE_BLOCK_PRIORITY)
                {
                    let priority = rule.priority.to_string();
                    let args: Vec<&str> = if v6 {
                        vec!["-6", "rule", "del", "priority", &priority]
                    } else {
                        vec!["rule", "del", "priority", &priority]
                    };
                    self.exec_ok(Program::Ip, &args, "remove-rule")?;
                }
            }
        }
        Ok(())
    }

    fn remove_interface(&self, record: &mut SessionRecord) -> Result<(), ClientError> {
        if let Some(interface) = record.interface_owned.clone() {
            let link = self.link(&interface)?;
            if link.present && link.wireguard {
                self.exec_ok(
                    Program::Ip,
                    &["link", "del", "dev", &interface],
                    "remove-interface",
                )?;
            }
            record.interface_owned = None;
        }
        Ok(())
    }

    fn remove_firewall(&self, record: &mut SessionRecord) -> Result<(), ClientError> {
        match self.firewall_state()? {
            TableState::Owned { .. } => {
                self.exec_ok(
                    Program::Nft,
                    &["delete", "table", "inet", TABLE_NAME],
                    "remove-kill-switch",
                )?;
            }
            TableState::Foreign | TableState::Absent => {}
        }
        record.kill_switch_armed = false;
        record.firewall_profile = None;
        Ok(())
    }

    /// Disconnect. `strict` keeps the kill switch armed afterwards unless `release`.
    pub fn disconnect(&mut self, release: bool) -> Result<(), ClientError> {
        let mut record = self.records.load()?;
        let connected_record = record.clone();
        record.desired = Desired::Disconnected;
        record.generation += 1;
        self.save(&mut record)?; // intent first
        if let Err(error) = self.remove_tunnel(&mut record) {
            // Cleanup failed. Keep the session desired so the monitor can repair a
            // partially torn-down tunnel instead of treating it as intentionally idle.
            let mut recovery = connected_record;
            recovery.generation = record.generation;
            let _ = self.save(&mut recovery);
            return Err(error);
        }
        let keep = record.mode.as_deref() == Some("strict") && !release && record.kill_switch_armed;
        if !keep && let Err(error) = self.remove_firewall(&mut record) {
            let mut recovery = record.clone();
            recovery.desired = Desired::Connected;
            recovery.generation = record.generation;
            let _ = self.save(&mut recovery);
            return Err(error);
        }
        self.save(&mut record)
    }

    /// Reconnect without a leak window: only the interface is recreated.
    pub fn reconnect(&mut self) -> Result<ConnectReport, ClientError> {
        let mut record = self.records.load()?;
        let name = record
            .profile
            .clone()
            .ok_or(ClientError::NoProfileSelected)?;
        self.remove_interface(&mut record)?;
        self.save(&mut record)?;
        self.connect(Some(&name))
    }

    /// Return to normal networking: disconnect, release the kill switch, forget the
    /// selected profile. Works even if the record is unreadable (then it only removes
    /// LoVPN-marked tables and exact-signature rules and replaces the record).
    pub fn reset(&mut self) -> Result<(), ClientError> {
        let mut record = match self.records.load() {
            Ok(record) => record,
            Err(_) => SessionRecord {
                schema_version: 1,
                ..SessionRecord::default()
            },
        };
        self.remove_tunnel(&mut record)?;
        self.remove_firewall(&mut record)?;
        let generation = record.generation + 1;
        let mut fresh = SessionRecord {
            schema_version: 1,
            generation,
            ..SessionRecord::default()
        };
        self.save(&mut fresh)
    }

    /// Re-apply the desired state idempotently (the `repair` operation).
    pub fn repair(&mut self) -> Result<(), ClientError> {
        let mut record = self.records.load()?;
        if record.desired != Desired::Connected {
            return Err(ClientError::NotConnected);
        }
        let name = record
            .profile
            .clone()
            .ok_or(ClientError::NoProfileSelected)?;
        let (config, key) = self.profiles.load(&name)?;
        self.preflight(&config, &record)?;
        record.interface_owned = Some(config.tunnel.interface.clone());
        record.routing_installed = true;
        record.dns_interface = Some(config.tunnel.interface.clone());
        self.apply_session(&config, &key, &mut record)?;
        self.save(&mut record)
    }

    // ------------------------------------------------------------- monitor ----

    /// One reconciliation step. `resumed` is set when the caller saw the wall clock jump
    /// ahead of the monotonic clock (system suspend). Never removes protection.
    pub fn tick(&mut self, resumed: bool) -> TickReport {
        let record = match self.records.load() {
            Ok(r) => r,
            Err(_) => {
                return TickReport {
                    action: TickAction::Failed,
                    reasons: vec!["record-unreadable".into()],
                };
            }
        };
        if record.desired == Desired::Disconnected {
            return self.tick_disconnected(&record);
        }
        let Some(name) = record.profile.clone() else {
            return TickReport {
                action: TickAction::Idle,
                reasons: vec![],
            };
        };
        let status = self.observe();
        let hard: Vec<String> = status
            .checks
            .iter()
            .filter(|c| {
                c.status == CheckStatus::Fail && c.name != "handshake" && c.name != "dns-unmanaged"
            })
            .map(|c| c.name.to_string())
            .collect();
        let dns_unmanaged = status.reasons.iter().any(|r| r == "dns-unmanaged");
        let hard: Vec<String> = hard
            .into_iter()
            .filter(|n| !(n == "dns" && dns_unmanaged))
            .collect();
        if !hard.is_empty() {
            return match self.repair() {
                Ok(()) => TickReport {
                    action: TickAction::Repaired,
                    reasons: hard,
                },
                Err(_) => TickReport {
                    action: TickAction::Failed,
                    reasons: hard,
                },
            };
        }
        let handshake_bad = status
            .checks
            .iter()
            .any(|c| c.name == "handshake" && c.status != CheckStatus::Ok);
        if (resumed || handshake_bad)
            && let Ok((config, _)) = self.profiles.load(&name)
        {
            let interface = config.tunnel.interface.as_str();
            let keepalive = plan::KEEPALIVE_SECS.to_string();
            // Setting persistent-keepalive makes WireGuard send a keepalive now, which
            // triggers a handshake if the session is stale (after resume/roaming).
            let nudged = self.exec(
                &Cmd::new(
                    Program::Wg,
                    &[
                        "set",
                        interface,
                        "peer",
                        &config.profile.server_public_key,
                        "persistent-keepalive",
                        &keepalive,
                    ],
                ),
                "nudge-handshake",
            );
            if nudged.is_ok_and(|o| o.success) {
                return TickReport {
                    action: TickAction::Nudged,
                    reasons: vec![if resumed { "resumed" } else { "handshake" }.into()],
                };
            }
        }
        TickReport {
            action: TickAction::Healthy,
            reasons: vec![],
        }
    }

    fn tick_disconnected(&mut self, record: &SessionRecord) -> TickReport {
        if !record.kill_switch_armed {
            return TickReport {
                action: TickAction::Idle,
                reasons: vec![],
            };
        }
        // Armed while disconnected (strict): keep the firewall in place; restore it if it
        // was removed behind our back.
        match self.firewall_state() {
            Ok(TableState::Owned { .. }) => TickReport {
                action: TickAction::Healthy,
                reasons: vec![],
            },
            Ok(TableState::Foreign) => TickReport {
                action: TickAction::Failed,
                reasons: vec!["firewall-foreign".into()],
            },
            Ok(TableState::Absent) => match self.restore_firewall(record) {
                Ok(()) => TickReport {
                    action: TickAction::Repaired,
                    reasons: vec!["firewall-missing".into()],
                },
                Err(_) => TickReport {
                    action: TickAction::Failed,
                    reasons: vec!["firewall-missing".into()],
                },
            },
            Err(_) => TickReport {
                action: TickAction::Failed,
                reasons: vec!["firewall-unobservable".into()],
            },
        }
    }

    fn restore_firewall(&self, record: &SessionRecord) -> Result<(), ClientError> {
        let name = record
            .firewall_profile
            .clone()
            .or_else(|| record.profile.clone())
            .ok_or(ClientError::NoProfileSelected)?;
        let (config, _) = self.profiles.load(&name)?;
        let plan = lovpn_firewall::compile_owned(&config, record.firewall_generation)
            .map_err(|_| ClientError::ProfileInvalid)?;
        self.exec_stdin(
            Program::Nft,
            &["-f", "-"],
            Zeroizing::new(plan.ruleset().as_bytes().to_vec()),
            "install-kill-switch",
        )
    }

    /// Called once when the service starts: restore the kill switch immediately, then
    /// resume a session the user had asked for. Never lowers protection.
    pub fn recover_on_start(&mut self) -> TickReport {
        let record = match self.records.load() {
            Ok(r) => r,
            Err(_) => {
                return TickReport {
                    action: TickAction::Failed,
                    reasons: vec!["record-unreadable".into()],
                };
            }
        };
        if record.kill_switch_armed
            && matches!(self.firewall_state(), Ok(TableState::Absent))
            && self.restore_firewall(&record).is_err()
        {
            return TickReport {
                action: TickAction::Failed,
                reasons: vec!["firewall-restore-failed".into()],
            };
        }
        if record.desired == Desired::Connected {
            return match self.repair() {
                Ok(()) => TickReport {
                    action: TickAction::Repaired,
                    reasons: vec!["restart".into()],
                },
                Err(_) => TickReport {
                    action: TickAction::Failed,
                    reasons: vec!["restart-repair-failed".into()],
                },
            };
        }
        TickReport {
            action: TickAction::Idle,
            reasons: vec![],
        }
    }

    // ------------------------------------------------------------- observe ----

    /// Derive the protection state from the kernel. Nothing here is taken on trust from
    /// the record except *what was asked for*.
    pub fn observe(&self) -> Status {
        let record = self.records.load().unwrap_or_else(|_| SessionRecord {
            schema_version: 1,
            ..SessionRecord::default()
        });
        let mut status = Status {
            state: State::Unknown,
            desired: record.desired,
            profile: record.profile.clone(),
            kill_switch: record.mode.clone(),
            kill_switch_armed: record.kill_switch_armed,
            checks: Vec::new(),
            reasons: Vec::new(),
            handshake_age_secs: None,
            rx_bytes: 0,
            tx_bytes: 0,
            generation: record.generation,
        };
        if record.desired == Desired::Disconnected {
            let firewall = self.firewall_state();
            status.state = match (record.kill_switch_armed, &firewall) {
                (true, Ok(TableState::Owned { .. })) => State::Blocked,
                (true, _) => {
                    status.reasons.push("kill-switch-missing".into());
                    State::Unknown
                }
                (false, _) => State::Disconnected,
            };
            return status;
        }
        let Some(name) = record.profile.clone() else {
            status.reasons.push("no-profile".into());
            return status;
        };
        let Ok((config, _)) = self.profiles.load(&name) else {
            status.reasons.push("profile-unreadable".into());
            return status;
        };
        self.observe_connected(&config, &record, &mut status);
        status
    }

    fn observe_connected(
        &self,
        config: &ClientConfig,
        record: &SessionRecord,
        status: &mut Status,
    ) {
        let interface = config.tunnel.interface.as_str();
        let mut checks: Vec<Check> = Vec::new();

        // Interface ownership and state.
        let owned = record.interface_owned.as_deref() == Some(interface);
        checks.push(match self.link(interface) {
            Err(_) => check("interface", CheckStatus::Unknown, "could not inspect"),
            Ok(l) if !l.present => check("interface", CheckStatus::Fail, "missing"),
            Ok(l) if !l.wireguard || !owned => check(
                "interface",
                CheckStatus::Fail,
                "not a LoVPN-owned WireGuard link",
            ),
            Ok(l) if !l.up => check("interface", CheckStatus::Fail, "down"),
            Ok(_) => check("interface", CheckStatus::Ok, "present, owned, up"),
        });

        // Handshake freshness (and transfer counters).
        let handshake = self.latest_handshake(interface);
        checks.push(match handshake {
            None => check("handshake", CheckStatus::Unknown, "could not inspect"),
            Some(0) => check("handshake", CheckStatus::Fail, "no handshake yet"),
            Some(t) => {
                let age = self.now().saturating_sub(t);
                status.handshake_age_secs = Some(age);
                if age <= HANDSHAKE_MAX_AGE_SECS {
                    check("handshake", CheckStatus::Ok, format!("{age}s ago"))
                } else {
                    check(
                        "handshake",
                        CheckStatus::Fail,
                        format!("stale ({age}s ago)"),
                    )
                }
            }
        });
        if let Ok(out) = self.exec(
            &Cmd::new(Program::Wg, &["show", interface, "transfer"]),
            "inspect-wireguard",
        ) && out.success
            && let Some(line) = out.stdout.lines().next()
        {
            let mut parts = line.split('\t').skip(1);
            status.rx_bytes = parts
                .next()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            status.tx_bytes = parts
                .next()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
        }

        // Endpoint recursion: the marked flow to the server must NOT enter the tunnel.
        let endpoint = config.profile.endpoint.ip().to_string();
        let mark = plan::fwmark_hex();
        checks.push(
            match self.exec(
                &Cmd::new(
                    Program::Ip,
                    &["-j", "route", "get", &endpoint, "mark", &mark],
                ),
                "inspect-route",
            ) {
                Err(_) => check("endpoint-route", CheckStatus::Unknown, "could not inspect"),
                Ok(out) => match parse_route_get(out.success, &out.stdout) {
                    None => check(
                        "endpoint-route",
                        CheckStatus::Fail,
                        "server unreachable (no uplink route)",
                    ),
                    Some(dev) if dev == interface => check(
                        "endpoint-route",
                        CheckStatus::Fail,
                        "server route enters the tunnel (recursion)",
                    ),
                    Some(_) => check(
                        "endpoint-route",
                        CheckStatus::Ok,
                        "server reached outside the tunnel",
                    ),
                },
            },
        );

        // IPv4: rules in place and a public destination resolves to the tunnel.
        let rules4 = self.rule_state(false);
        let route4 = self.exec(
            &Cmd::new(Program::Ip, &["-j", "route", "get", PROBE_V4]),
            "inspect-route",
        );
        checks.push(match (rules4, route4) {
            (Ok(RuleState::Complete), Ok(out)) => match parse_route_get(out.success, &out.stdout) {
                Some(dev) if dev == interface => check(
                    "ipv4",
                    CheckStatus::Ok,
                    "unmarked traffic routes into the tunnel",
                ),
                Some(_) => check(
                    "ipv4",
                    CheckStatus::Fail,
                    "unmarked traffic routes outside the tunnel",
                ),
                None => check(
                    "ipv4",
                    CheckStatus::Fail,
                    "no route (tunnel has no default route)",
                ),
            },
            (Ok(_), Ok(_)) => check(
                "ipv4",
                CheckStatus::Fail,
                "routing rules missing or incomplete",
            ),
            _ => check("ipv4", CheckStatus::Unknown, "could not inspect"),
        });

        // IPv6: the profile blocks it; verify nothing can route.
        let rules6 = self.rule_state(true);
        let route6 = self.exec(
            &Cmd::new(Program::Ip, &["-j", "-6", "route", "get", PROBE_V6]),
            "inspect-route",
        );
        checks.push(match (rules6, route6) {
            (Ok(RuleState::Complete), Ok(out))
                if parse_route_get(out.success, &out.stdout).is_none() =>
            {
                check("ipv6", CheckStatus::Ok, "blocked (unreachable)")
            }
            (Ok(RuleState::Complete), Ok(_)) => {
                check("ipv6", CheckStatus::Fail, "IPv6 can still be routed")
            }
            (Ok(_), Ok(_)) => check("ipv6", CheckStatus::Fail, "IPv6 block rule missing"),
            _ => check("ipv6", CheckStatus::Unknown, "could not inspect"),
        });

        // Kill switch: installed, owned, current.
        checks.push(if config.firewall.kill_switch == KillSwitchMode::Off {
            check("firewall", CheckStatus::Off, "kill switch is off")
        } else {
            match self.firewall_state() {
                Err(_) => check("firewall", CheckStatus::Unknown, "could not inspect"),
                Ok(TableState::Owned {
                    generation: Some(g),
                }) if g == record.firewall_generation
                    && record.firewall_profile == record.profile =>
                {
                    check(
                        "firewall",
                        CheckStatus::Ok,
                        format!("installed, generation {g}"),
                    )
                }
                Ok(TableState::Owned { .. }) => {
                    check("firewall", CheckStatus::Fail, "installed but stale")
                }
                Ok(TableState::Foreign) => check(
                    "firewall",
                    CheckStatus::Fail,
                    "a foreign table holds LoVPN's name",
                ),
                Ok(TableState::Absent) => check("firewall", CheckStatus::Fail, "missing"),
            }
        });

        // DNS: resolver state observed (configured on the tunnel link), not packet-tested.
        checks.push(
            match self
                .dns
                .observe(self.runner.as_ref(), interface, &config.dns.servers)
            {
                DnsObservation::Ok => check(
                    "dns",
                    CheckStatus::Ok,
                    "resolvers configured on the tunnel link, default route",
                ),
                DnsObservation::Unmanaged => {
                    status.reasons.push("dns-unmanaged".into());
                    check("dns", CheckStatus::Fail, "DNS is not managed by LoVPN")
                }
                DnsObservation::Mismatch(reason) => check("dns", CheckStatus::Fail, reason),
                DnsObservation::Unknown => check("dns", CheckStatus::Unknown, "could not inspect"),
            },
        );

        for c in &checks {
            match c.status {
                CheckStatus::Fail
                    if c.name != "dns" || !status.reasons.iter().any(|r| r == "dns-unmanaged") =>
                {
                    status.reasons.push(c.name.to_string());
                }
                CheckStatus::Unknown => status.reasons.push(format!("{}-unknown", c.name)),
                _ => {}
            }
        }
        let recent = self.now().saturating_sub(record.updated_unix) < 20;
        status.state = derive_state(&checks, handshake == Some(0), recent);
        status.checks = checks;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuleState {
    Absent,
    Partial,
    Complete,
    /// Something else owns LoVPN's reserved priority.
    Foreign,
}

#[derive(Clone, Copy)]
enum Want {
    Lookup,
    Unreachable,
    V6Block,
}

impl Want {
    fn matches(self, rule: &Rule) -> bool {
        let mark = plan::fwmark_hex();
        match self {
            Self::Lookup => {
                rule.priority == plan::RULE_LOOKUP_PRIORITY
                    && rule.negated_fwmark.as_deref() == Some(mark.as_str())
                    && rule.table.as_deref() == Some(plan::route_table().as_str())
            }
            Self::Unreachable => {
                rule.priority == plan::RULE_BLOCK_PRIORITY
                    && rule.negated_fwmark.as_deref() == Some(mark.as_str())
                    && rule.action.as_deref() == Some("unreachable")
            }
            Self::V6Block => {
                rule.priority == plan::RULE_LOOKUP_PRIORITY
                    && rule.negated_fwmark.is_none()
                    && rule.table.is_none()
                    && rule.action.as_deref() == Some("unreachable")
            }
        }
    }
}

impl crate::protocol::ClientEngine for Engine {
    fn observe(&self) -> Status {
        Engine::observe(self)
    }
    fn list_profiles(&self) -> Result<Vec<ProfileInfo>, ClientError> {
        Engine::list_profiles(self)
    }
    fn selected_profile(&self) -> Result<Option<String>, ClientError> {
        Engine::selected_profile(self)
    }
    fn use_profile(&mut self, name: &str) -> Result<(), ClientError> {
        Engine::use_profile(self, name)
    }
    fn import_profile(
        &mut self,
        name: &str,
        profile: &str,
        private_key: &str,
        expected_server_key: &str,
    ) -> Result<ProfileInfo, ClientError> {
        Engine::import_profile(self, name, profile, private_key, expected_server_key)
    }
    fn remove_profile(&mut self, name: &str) -> Result<(), ClientError> {
        Engine::remove_profile(self, name)
    }
    fn public_key_of(&self, name: &str) -> Result<ClientPublicKey, ClientError> {
        Engine::public_key_of(self, name)
    }
    fn connect(&mut self, profile: Option<&str>) -> Result<ConnectReport, ClientError> {
        Engine::connect(self, profile)
    }
    fn disconnect(&mut self, release: bool) -> Result<(), ClientError> {
        Engine::disconnect(self, release)
    }
    fn reconnect(&mut self) -> Result<ConnectReport, ClientError> {
        Engine::reconnect(self)
    }
    fn repair(&mut self) -> Result<(), ClientError> {
        Engine::repair(self)
    }
    fn reset(&mut self) -> Result<(), ClientError> {
        Engine::reset(self)
    }
}
