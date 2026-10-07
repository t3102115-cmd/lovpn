//! The Windows connection engine: connect, disconnect, reconnect, repair, reset, observe.
//!
//! Same ordering rules as the Linux client, for the same reasons:
//! 1. the firewall (kill switch, DNS guard, IPv6 block) is installed *before* the adapter
//!    exists, so nothing can leak while the tunnel comes up;
//! 2. tunnel traffic is permitted only after the adapter, routes and DNS are in place;
//! 3. an unexpected loss (crash, adapter vanished) never removes protection; only an
//!    explicit disconnect does, and `strict` keeps blocking until the user releases it;
//! 4. protection is *observed* from the system on every status call, never assumed.
use crate::{
    WinError, dns,
    driver::{Adapter, Driver},
    ip::{self, Route},
    policy::{self, PolicyInput},
    profiles::ProfileStore,
    record::{EndpointRoute, Record, RecordStore},
    wfp,
};
use lovpn_client::{
    ClientError,
    model::{
        Check, CheckStatus, ConnectReport, Desired, HANDSHAKE_MAX_AGE_SECS, ProfileInfo, State,
        Status, TickAction, TickReport, derive_state, kill_switch_name,
    },
    plan,
};
use lovpn_config::{ClientConfig, KillSwitchMode};
use lovpn_keys::{ClientPrivateKey, ClientPublicKey, ServerPublicKey};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const PROBE_V4: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const ENDPOINT_METRIC: u32 = 1;
const TUNNEL_METRIC: u32 = 5;

thread_local! {
    static LAST_FAILURE: std::cell::Cell<Option<WinError>> = const { std::cell::Cell::new(None) };
}

/// The step and Win32 error behind the most recent failure on this thread, taken once.
/// For the service log only: users see the static step name, never OS text.
pub fn take_last_failure() -> Option<WinError> {
    LAST_FAILURE.with(std::cell::Cell::take)
}

impl From<WinError> for ClientError {
    fn from(error: WinError) -> Self {
        LAST_FAILURE.with(|c| c.set(Some(error)));
        ClientError::CommandFailed(error.step)
    }
}

pub struct Engine {
    profiles: ProfileStore,
    records: RecordStore,
    driver: Driver,
    wfp: wfp::Engine,
    service_path: String,
    log_path: PathBuf,
    adapter: Option<Adapter>,
    handshake_wait: Duration,
}

fn check(name: &'static str, status: CheckStatus, detail: impl Into<String>) -> Check {
    Check {
        name,
        status,
        detail: detail.into(),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn mode_of(config: &ClientConfig) -> &'static str {
    kill_switch_name(config.firewall.kill_switch)
}

fn v4_endpoint(config: &ClientConfig) -> Result<SocketAddrV4, ClientError> {
    match config.profile.endpoint {
        SocketAddr::V4(v4) => Ok(v4),
        SocketAddr::V6(_) => Err(ClientError::UnsupportedEndpoint),
    }
}

/// The first IPv4 tunnel address in the profile.
fn tunnel_address(config: &ClientConfig) -> Result<(Ipv4Addr, u8), ClientError> {
    config
        .tunnel
        .addresses
        .iter()
        .find_map(|a| match a.addr() {
            IpAddr::V4(v4) => Some((v4, a.prefix_len())),
            IpAddr::V6(_) => None,
        })
        .ok_or(ClientError::ProfileInvalid)
}

fn dns_servers(config: &ClientConfig) -> Vec<Ipv4Addr> {
    config
        .dns
        .servers
        .iter()
        .filter_map(|s| match s {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        })
        .collect()
}

impl Engine {
    pub fn new(
        state_dir: PathBuf,
        driver_dll: &std::path::Path,
        service_path: String,
    ) -> Result<Self, ClientError> {
        let log_path = state_dir.join("logs").join("service.log");
        Ok(Self {
            profiles: ProfileStore::open(state_dir.join("profiles"))?,
            records: RecordStore::open(state_dir)?,
            log_path,
            driver: Driver::load(driver_dll)?,
            wfp: wfp::Engine::open()?,
            service_path,
            adapter: None,
            handshake_wait: Duration::from_secs(12),
        })
    }

    /// Graceful service stop: remove what only a running service can own (the adapter and
    /// the host route to the server). The firewall policy and the desired state stay, so
    /// a strict profile keeps blocking and the next start resumes.
    pub fn shutdown_tunnel(&mut self) {
        if let Ok(mut record) = self.records.load() {
            if self.remove_tunnel(&mut record).is_ok() {
                let _ = self.save(&mut record);
            }
        } else {
            self.adapter = None;
        }
    }

    pub fn set_handshake_wait(&mut self, wait: Duration) {
        self.handshake_wait = wait;
    }

    fn save(&self, record: &mut Record) -> Result<(), ClientError> {
        record.updated_unix = now();
        self.records.save(record)
    }

    // ------------------------------------------------------------- profiles ----

    pub fn list_profiles(&self) -> Result<Vec<ProfileInfo>, ClientError> {
        self.profiles.list()
    }

    pub fn selected_profile(&self) -> Result<Option<String>, ClientError> {
        Ok(self.records.load()?.profile)
    }

    pub fn use_profile(&self, name: &str) -> Result<(), ClientError> {
        let mut record = self.records.load()?;
        if record.desired == Desired::Connected {
            return Err(ClientError::SwitchWhileConnected);
        }
        if record.nrpt.is_some() {
            return Err(ClientError::CommandFailed("nrpt-restoration-pending"));
        }
        if !self.profiles.list()?.iter().any(|p| p.name == name) {
            return Err(ClientError::ProfileNotFound);
        }
        record.profile = Some(name.to_string());
        self.save(&mut record)
    }

    pub fn generate_identity(&self, name: &str) -> Result<ClientPublicKey, ClientError> {
        self.profiles.generate_identity(name)
    }

    pub fn import_profile(
        &self,
        name: &str,
        profile_text: &str,
        private_key: Option<&str>,
        expected_server_key: &str,
    ) -> Result<ProfileInfo, ClientError> {
        let expected: ServerPublicKey = expected_server_key
            .parse()
            .map_err(|_| ClientError::ServerKeyMismatch)?;
        let key = private_key
            .map(|k| ClientPrivateKey::from_base64(k).map_err(|_| ClientError::KeyInvalid))
            .transpose()?;
        self.profiles
            .import(name, profile_text, key.as_ref(), &expected)
    }

    pub fn remove_profile(&self, name: &str) -> Result<(), ClientError> {
        let record = self.records.load()?;
        if record.profile.as_deref() == Some(name)
            && (record.desired == Desired::Connected || record.nrpt.is_some())
        {
            return Err(ClientError::NotConnected);
        }
        self.profiles.remove(name)
    }

    pub fn public_key_of(&self, name: &str) -> Result<ClientPublicKey, ClientError> {
        self.profiles.public_key_of(name)
    }

    // ------------------------------------------------------------- firewall ----

    fn policy_input(
        &self,
        config: &ClientConfig,
        generation: u64,
        tunnel: Option<u64>,
        kill_switch: bool,
    ) -> Result<PolicyInput, ClientError> {
        Ok(PolicyInput {
            generation,
            tunnel_interface: tunnel,
            endpoint: v4_endpoint(config)?,
            service_path: self.service_path.clone(),
            kill_switch,
            dns_guard: true,
            block_ipv6: true,
        })
    }

    /// Install the policy for the current state and stamp its generation in the record.
    fn set_policy(
        &self,
        record: &mut Record,
        config: &ClientConfig,
        tunnel: Option<u64>,
        kill_switch: bool,
    ) -> Result<(), ClientError> {
        record.generation += 1;
        record.firewall_generation = record.generation;
        record.kill_switch_armed = kill_switch;
        self.save(record)?;
        let input = self.policy_input(config, record.generation, tunnel, kill_switch)?;
        self.wfp.replace(&policy::compile(&input))?;
        Ok(())
    }

    // --------------------------------------------------------------- tunnel ----

    fn remove_endpoint_route(&self, record: &mut Record) {
        if let Some(route) = record.endpoint_route.take() {
            let _ = ip::delete_route(&Route {
                interface: route.luid,
                destination: route.destination,
                prefix: 32,
                next_hop: route.next_hop,
            });
        }
    }

    /// Restore owned NRPT intent before any teardown or firewall release. Failed
    /// restoration retains intent and attempts a conservative blocking policy.
    fn restore_dns(&self, record: &mut Record) -> Result<(), ClientError> {
        let result = crate::record::restore_nrpt(
            record,
            |journal| {
                dns::restore(journal)
                    .map(|_| ())
                    .map_err(|_| ClientError::CommandFailed("nrpt-restore"))
            },
            |restored| self.records.save(restored),
        );
        if result.is_err() {
            // Do not rely on a profile still being readable when recovery fails.
            // Keep journal intent and install a conservative tunnel-less policy.
            record.generation = record.generation.saturating_add(1);
            record.firewall_generation = record.generation;
            record.kill_switch_armed = true;
            let input = PolicyInput {
                generation: record.generation,
                tunnel_interface: None,
                endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1),
                service_path: self.service_path.clone(),
                kill_switch: true,
                dns_guard: true,
                block_ipv6: true,
            };
            // Even a failed record write must not prevent a best-effort containment.
            let _ = self.save(record);
            self.wfp.replace(&policy::compile(&input))?;
        }
        result
    }

    /// NRPT first, then the adapter (including its routes/baseline DNS) and host route.
    fn remove_tunnel(&mut self, record: &mut Record) -> Result<(), ClientError> {
        self.restore_dns(record)?;
        self.adapter = None;
        self.remove_endpoint_route(record);
        Ok(())
    }

    fn add_endpoint_route(
        &self,
        record: &mut Record,
        endpoint: Ipv4Addr,
        tunnel: Option<u64>,
    ) -> Result<(), ClientError> {
        let egress = match ip::best_egress(endpoint) {
            Ok(e) if Some(e.luid) != tunnel => e,
            _ => ip::physical_default(tunnel)?.ok_or(ClientError::CommandFailed("no-uplink"))?,
        };
        let route = EndpointRoute {
            luid: egress.luid,
            destination: endpoint,
            next_hop: egress.next_hop,
        };
        // Intent first: a crash after the route is added can still be cleaned up.
        record.endpoint_route = Some(route);
        self.save(record)?;
        ip::add_route(
            &Route {
                interface: route.luid,
                destination: endpoint,
                prefix: 32,
                next_hop: route.next_hop,
            },
            ENDPOINT_METRIC,
        )?;
        Ok(())
    }

    fn apply_session(
        &mut self,
        config: &ClientConfig,
        key: &ClientPrivateKey,
        record: &mut Record,
    ) -> Result<(), ClientError> {
        let endpoint = v4_endpoint(config)?;
        let kill = config.firewall.kill_switch != KillSwitchMode::Off;
        let server: ServerPublicKey = config
            .profile
            .server_public_key
            .parse()
            .map_err(|_| ClientError::ProfileInvalid)?;
        let (address, prefix) = tunnel_address(config)?;

        // 1. Fail closed first: the policy exists before the tunnel does.
        self.set_policy(record, config, None, kill)?;
        // 2. The route that keeps the transport outside the tunnel.
        self.add_endpoint_route(record, *endpoint.ip(), None)?;
        // 3. Adapter, key, peer, up.
        let adapter = self.driver.create_adapter(&config.tunnel.interface)?;
        adapter.configure(key, &server, endpoint, &[(Ipv4Addr::UNSPECIFIED, 0)])?;
        adapter.set_up(true)?;
        let luid = adapter.luid();
        self.adapter = Some(adapter);
        // 4. Addressing, MTU, split-default routes and DNS (the stack needs a moment).
        // Interface settings first (this also turns duplicate-address detection off), then
        // the address, so the address is usable immediately.
        retry(|| ip::configure_interface(luid, u32::from(config.tunnel.mtu)))?;
        retry(|| ip::add_address(luid, address, prefix))?;
        for dest in [Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(128, 0, 0, 0)] {
            ip::add_route(
                &Route {
                    interface: luid,
                    destination: dest,
                    prefix: 1,
                    next_hop: None,
                },
                TUNNEL_METRIC,
            )?;
        }
        ip::set_dns(luid, &dns_servers(config))?;
        if !config.dns.scopes.is_empty() {
            // Resolver /32 routes override physical on-link routes, so scoped resolvers
            // cannot accidentally follow a more-specific route outside the tunnel.
            for server in config.dns.scopes.iter().flat_map(|scope| &scope.servers) {
                ip::add_route(
                    &Route {
                        interface: luid,
                        destination: *server,
                        prefix: 32,
                        next_hop: None,
                    },
                    TUNNEL_METRIC,
                )?;
                if ip::best_egress(*server)?.luid != luid {
                    return Err(ClientError::CommandFailed("nrpt-resolver-route"));
                }
            }
            let journal = dns::new_journal(&config.dns.scopes)
                .map_err(|_| ClientError::CommandFailed("nrpt-journal"))?;
            record.schema_version = 2;
            record.nrpt = Some(journal);
            // Durable intent precedes the first NRPT mutation, including partial apply.
            self.save(record)?;
            if let Some(journal) = &record.nrpt {
                dns::apply(journal, true).map_err(|_| ClientError::CommandFailed("nrpt-apply"))?;
            }
        }
        // 5. Only now may tunnel traffic through the firewall.
        self.set_policy(record, config, Some(luid), kill)?;
        Ok(())
    }

    fn wait_for_handshake(&self) -> bool {
        let deadline = std::time::Instant::now() + self.handshake_wait;
        loop {
            if let Some(adapter) = &self.adapter
                && adapter
                    .observe()
                    .is_ok_and(|o| o.handshake_age_secs.is_some())
            {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

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
        v4_endpoint(&config)?;
        self.remove_tunnel(&mut record)?;

        record.profile = Some(name.clone());
        record.desired = Desired::Connected;
        record.mode = Some(mode_of(&config).to_string());
        self.save(&mut record)?;

        if let Err(error) = self.apply_session(&config, &key, &mut record) {
            self.abort_connect(&mut record, &config)?;
            return Err(error);
        }
        let handshake_seen = self.wait_for_handshake();
        Ok(ConnectReport {
            profile: name,
            handshake_seen,
            kill_switch_armed: record.kill_switch_armed,
        })
    }

    /// A failed connect must not strand a non-strict user offline; `strict` stays blocked.
    fn abort_connect(
        &mut self,
        record: &mut Record,
        config: &ClientConfig,
    ) -> Result<(), ClientError> {
        // Cleanup failure retains the journal and contains the partial tunnel,
        // including for non-strict/off profiles; never continue to firewall release.
        self.remove_tunnel(record)?;
        if config.firewall.kill_switch == KillSwitchMode::Strict {
            // Keep blocking: back to the tunnel-less, block-all policy.
            self.set_policy(record, config, None, true)?;
            record.desired = Desired::Disconnected;
        } else {
            self.wfp.remove_all()?;
            record.kill_switch_armed = false;
            record.desired = Desired::Disconnected;
        }
        self.save(record)
    }

    pub fn disconnect(&mut self, release: bool) -> Result<(), ClientError> {
        let mut record = self.records.load()?;
        self.remove_tunnel(&mut record)?;
        let strict = record.mode.as_deref() == Some("strict");
        record.desired = Desired::Disconnected;
        if release || !strict {
            self.wfp.remove_all()?;
            record.kill_switch_armed = false;
        } else if let Some(name) = record.profile.clone() {
            // Strict: stay blocked, with no tunnel, until the user releases it.
            let (config, _) = self.profiles.load(&name)?;
            self.set_policy(&mut record, &config, None, true)?;
        }
        self.save(&mut record)
    }

    pub fn reconnect(&mut self) -> Result<ConnectReport, ClientError> {
        let record = self.records.load()?;
        if record.desired != Desired::Connected {
            return Err(ClientError::NotConnected);
        }
        let name = record.profile.ok_or(ClientError::NoProfileSelected)?;
        self.connect(Some(&name))
    }

    pub fn reset(&mut self) -> Result<(), ClientError> {
        let mut record = self.records.load()?;
        self.remove_tunnel(&mut record)?;
        self.wfp.remove_all()?;
        record.desired = Desired::Disconnected;
        record.kill_switch_armed = false;
        record.profile = None;
        record.mode = None;
        self.save(&mut record)
    }

    pub fn repair(&mut self) -> Result<(), ClientError> {
        let mut record = self.records.load()?;
        self.restore_dns(&mut record)?;
        if record.desired == Desired::Connected {
            self.reconnect().map(|_| ())
        } else if record.kill_switch_armed {
            self.ensure_blocking(record)
        } else {
            Ok(())
        }
    }

    /// Strict mode while disconnected: make sure the block-all policy is really installed.
    fn ensure_blocking(&mut self, mut record: Record) -> Result<(), ClientError> {
        let name = record
            .profile
            .clone()
            .ok_or(ClientError::NoProfileSelected)?;
        let (config, _) = self.profiles.load(&name)?;
        self.set_policy(&mut record, &config, None, true)
    }

    // -------------------------------------------------------- monitor/recovery ----

    /// One monitor step. `resumed` is true after sleep/resume or a long stall: rebuild the
    /// tunnel, since sockets and routes may be stale.
    pub fn tick(&mut self, resumed: bool) -> TickReport {
        let mut record = match self.records.load() {
            Ok(r) => r,
            Err(_) => {
                return TickReport {
                    action: TickAction::Failed,
                    reasons: vec!["record".into()],
                };
            }
        };
        if record.desired == Desired::Disconnected {
            if self.restore_dns(&mut record).is_err() {
                return TickReport {
                    action: TickAction::Failed,
                    reasons: vec!["nrpt-restore".into()],
                };
            }
            if record.kill_switch_armed && !self.policy_intact(&record, None) {
                return match self.ensure_blocking(record) {
                    Ok(()) => TickReport {
                        action: TickAction::Repaired,
                        reasons: vec!["kill-switch-restored".into()],
                    },
                    Err(_) => TickReport {
                        action: TickAction::Failed,
                        reasons: vec!["kill-switch-missing".into()],
                    },
                };
            }
            return TickReport {
                action: TickAction::Idle,
                reasons: vec![],
            };
        }
        let status = self.observe();
        if status.state == State::Protected && !resumed {
            return TickReport {
                action: TickAction::Healthy,
                reasons: vec![],
            };
        }
        if status.state == State::Connecting && !resumed {
            return TickReport {
                action: TickAction::Healthy,
                reasons: vec!["connecting".into()],
            };
        }
        let reasons = status.reasons.clone();
        // Only the uplink changed (Wi-Fi/Ethernet switch): move the host route, no rebuild.
        if !resumed && reasons == ["endpoint-route"] && self.fix_endpoint_route().is_ok() {
            return TickReport {
                action: TickAction::Repaired,
                reasons,
            };
        }
        match self.reconnect() {
            Ok(_) => TickReport {
                action: TickAction::Repaired,
                reasons,
            },
            Err(_) => TickReport {
                action: TickAction::Failed,
                reasons,
            },
        }
    }

    fn fix_endpoint_route(&mut self) -> Result<(), ClientError> {
        let mut record = self.records.load()?;
        let name = record
            .profile
            .clone()
            .ok_or(ClientError::NoProfileSelected)?;
        let (config, _) = self.profiles.load(&name)?;
        let tunnel = self.adapter.as_ref().map(Adapter::luid);
        self.remove_endpoint_route(&mut record);
        self.add_endpoint_route(&mut record, *v4_endpoint(&config)?.ip(), tunnel)
    }

    /// Startup: clean up what a crashed predecessor left, then resume the desired state.
    /// The persistent firewall policy stayed in place the whole time.
    pub fn recover_on_start(&mut self) -> TickReport {
        let Ok(mut record) = self.records.load() else {
            return TickReport {
                action: TickAction::Failed,
                reasons: vec!["record".into()],
            };
        };
        if self.remove_tunnel(&mut record).is_err() {
            return TickReport {
                action: TickAction::Failed,
                reasons: vec!["nrpt-restore".into()],
            };
        }
        let _ = self.save(&mut record);
        if let Some(name) = record.profile.as_deref()
            && let Ok((config, _)) = self.profiles.load(name)
        {
            self.driver.remove_stale(&config.tunnel.interface);
        }
        match record.desired {
            Desired::Connected => match self.reconnect() {
                Ok(_) => TickReport {
                    action: TickAction::Repaired,
                    reasons: vec!["resumed".into()],
                },
                Err(_) => TickReport {
                    action: TickAction::Failed,
                    reasons: vec!["resume-failed".into()],
                },
            },
            Desired::Disconnected => self.tick(false),
        }
    }

    // ----------------------------------------------------------- observation ----

    fn tunnel_luid(&self) -> Option<u64> {
        self.adapter.as_ref().map(Adapter::luid)
    }

    /// Are the installed filters exactly the compiled policy for this state?
    fn policy_intact(&self, record: &Record, tunnel: Option<u64>) -> bool {
        self.policy_verification(record, tunnel)
            .is_ok_and(|reason| reason.is_none())
    }

    fn policy_verification(
        &self,
        record: &Record,
        tunnel: Option<u64>,
    ) -> Result<Option<&'static str>, WinError> {
        let Some(name) = record.profile.as_deref() else {
            return Ok(Some("wfp-mismatch-profile-missing"));
        };
        let Ok((config, _)) = self.profiles.load(name) else {
            return Ok(Some("wfp-mismatch-profile-unreadable"));
        };
        let Ok(input) = self.policy_input(
            &config,
            record.firewall_generation,
            tunnel,
            record.kill_switch_armed,
        ) else {
            return Ok(Some("wfp-mismatch-policy-input"));
        };
        self.wfp.verification_diagnostic(&policy::compile(&input))
    }

    pub fn observe(&self) -> Status {
        let loaded = self.records.load();
        let invalid_record = loaded.is_err();
        let record = loaded.unwrap_or_else(|_| Record {
            schema_version: 1,
            ..Record::default()
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
        if invalid_record {
            status.reasons.push("record".into());
            return status;
        }
        if record.desired == Desired::Disconnected {
            if record.nrpt.is_some() {
                status.reasons.push("nrpt-restoration-pending".into());
                status.checks.push(check(
                    "dns-scopes",
                    CheckStatus::Fail,
                    "restoration pending; protection must remain",
                ));
                return status;
            }
            status.state = match (
                record.kill_switch_armed,
                self.policy_verification(&record, None),
            ) {
                (true, Ok(None)) => State::Blocked,
                (true, verification) => {
                    status.reasons.push("kill-switch-missing".into());
                    let (result, reason) = match verification {
                        Ok(Some(reason)) => (CheckStatus::Fail, reason),
                        Err(error) => (CheckStatus::Unknown, error.step),
                        Ok(None) => (CheckStatus::Unknown, "wfp-inspection-unavailable"),
                    };
                    status.checks.push(check("firewall", result, reason));
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

    fn observe_connected(&self, config: &ClientConfig, record: &Record, status: &mut Status) {
        let mut checks: Vec<Check> = Vec::new();
        let tunnel = self.tunnel_luid();
        let endpoint = v4_endpoint(config).ok();

        // Adapter presence and driver state.
        let observation = self.adapter.as_ref().map(Adapter::observe);
        checks.push(match &observation {
            None => check("interface", CheckStatus::Fail, "missing"),
            Some(Err(_)) => check("interface", CheckStatus::Unknown, "could not inspect"),
            Some(Ok(_)) => check("interface", CheckStatus::Ok, "present, owned, up"),
        });
        let mut no_handshake_yet = false;
        checks.push(match &observation {
            Some(Ok(o)) => {
                status.rx_bytes = o.rx_bytes;
                status.tx_bytes = o.tx_bytes;
                match o.handshake_age_secs {
                    None => {
                        no_handshake_yet = true;
                        check("handshake", CheckStatus::Fail, "no handshake yet")
                    }
                    Some(age) => {
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
                }
            }
            Some(Err(_)) => check("handshake", CheckStatus::Unknown, "could not inspect"),
            None => check("handshake", CheckStatus::Fail, "no tunnel"),
        });

        // The transport must leave through the physical uplink, never through the tunnel,
        // and our recorded host route must still match where the uplink is now.
        checks.push(match (endpoint, tunnel) {
            (Some(ep), Some(t)) => match ip::best_egress(*ep.ip()) {
                Err(_) => check("endpoint-route", CheckStatus::Unknown, "could not inspect"),
                Ok(e) if e.luid == t => check(
                    "endpoint-route",
                    CheckStatus::Fail,
                    "server route enters the tunnel (recursion)",
                ),
                Ok(e) => {
                    let recorded = record.endpoint_route;
                    let current_ok =
                        recorded.is_some_and(|r| r.luid == e.luid && r.next_hop == e.next_hop);
                    // A server reached through a gateway follows the default route when the
                    // uplink changes; an on-link server has no gateway to compare, and its
                    // loss shows up as the route entering the tunnel (checked above).
                    let uplink_moved = recorded.is_some_and(|r| {
                        r.next_hop.is_some()
                            && ip::physical_default(Some(t))
                                .ok()
                                .flatten()
                                .is_some_and(|u| u.luid != r.luid || u.next_hop != r.next_hop)
                    });
                    if current_ok && !uplink_moved {
                        check(
                            "endpoint-route",
                            CheckStatus::Ok,
                            "server reached outside the tunnel",
                        )
                    } else {
                        check(
                            "endpoint-route",
                            CheckStatus::Fail,
                            "uplink changed; route is stale",
                        )
                    }
                }
            },
            _ => check("endpoint-route", CheckStatus::Fail, "no tunnel"),
        });

        // IPv4: a public destination resolves to the tunnel.
        checks.push(match tunnel {
            None => check("ipv4", CheckStatus::Fail, "no tunnel"),
            Some(t) => match ip::best_egress(PROBE_V4) {
                Err(_) => check("ipv4", CheckStatus::Unknown, "could not inspect"),
                Ok(e) if e.luid == t => check(
                    "ipv4",
                    CheckStatus::Ok,
                    "unmarked traffic routes into the tunnel",
                ),
                Ok(_) => check(
                    "ipv4",
                    CheckStatus::Fail,
                    "traffic routes outside the tunnel",
                ),
            },
        });

        // Verify actions, conditions and metadata in one read-only WFP transaction.
        // Every guard depends on the complete policy: an altered permit can bypass an
        // otherwise genuine DNS/IPv6 block, so checking block names alone is unsafe.
        let verification = self
            .policy_input(
                config,
                record.firewall_generation,
                tunnel,
                record.kill_switch_armed,
            )
            .ok()
            .map(|input| self.wfp.verification_diagnostic(&policy::compile(&input)));
        let intact = verification
            .as_ref()
            .and_then(|result| result.as_ref().ok().map(|reason| reason.is_none()));
        let mismatch = verification
            .as_ref()
            .and_then(|result| match result {
                Ok(Some(reason)) => Some(*reason),
                Err(error) => Some(error.step),
                _ => None,
            })
            .unwrap_or("wfp-inspection-unavailable");
        checks.push(match intact {
            None => check("ipv6", CheckStatus::Unknown, mismatch),
            Some(true) => check("ipv6", CheckStatus::Ok, "blocked by firewall policy"),
            Some(false) => check("ipv6", CheckStatus::Fail, mismatch),
        });
        checks.push(if config.firewall.kill_switch == KillSwitchMode::Off {
            check("firewall", CheckStatus::Off, "kill switch is off")
        } else if intact.is_none() {
            check("firewall", CheckStatus::Unknown, mismatch)
        } else if intact == Some(true) {
            check(
                "firewall",
                CheckStatus::Ok,
                format!("installed, generation {}", record.firewall_generation),
            )
        } else {
            check("firewall", CheckStatus::Fail, mismatch)
        });

        // DNS: resolvers configured on the tunnel and DNS elsewhere blocked by the firewall.
        let guard = intact.map(|valid| (valid, valid));
        let expected: Vec<String> = dns_servers(config)
            .iter()
            .map(Ipv4Addr::to_string)
            .collect();
        checks.push(match (tunnel, guard) {
            (None, _) => check("dns", CheckStatus::Fail, "no tunnel"),
            (Some(_), None) => check("dns", CheckStatus::Unknown, mismatch),
            (Some(t), Some((udp, tcp))) => match ip::dns_servers(t) {
                Err(_) => check("dns", CheckStatus::Unknown, "could not inspect"),
                Ok(have) if have != expected => check(
                    "dns",
                    CheckStatus::Fail,
                    "tunnel resolvers differ from the profile",
                ),
                Ok(_) if !(udp && tcp) => check("dns", CheckStatus::Fail, mismatch),
                Ok(_) => check(
                    "dns",
                    CheckStatus::Ok,
                    "baseline tunnel resolvers set; DNS outside tunnel blocked",
                ),
            },
        });

        if !config.dns.scopes.is_empty() || record.nrpt.is_some() {
            checks.push(match &record.nrpt {
                None => check("dns-scopes", CheckStatus::Fail, "NRPT ownership journal missing"),
                Some(journal) if journal.scopes != config.dns.scopes => check("dns-scopes", CheckStatus::Fail, "NRPT intent differs from profile"),
                Some(journal) => {
                    let routed = tunnel.is_some_and(|luid| journal.scopes.iter().flat_map(|scope| &scope.servers)
                        .all(|server| ip::best_egress(*server).is_ok_and(|egress| egress.luid == luid)));
                    match dns::observe(journal) {
                        Ok(observed) if observed.owned_rules == journal.scopes.len() && observed.effective_scopes == journal.scopes.len() && routed =>
                            check("dns-scopes", CheckStatus::Ok, "owned NRPT suffix policies effective; resolvers route through tunnel"),
                        Ok(_) => check("dns-scopes", CheckStatus::Fail, "NRPT policy or resolver routing mismatch"),
                        Err(_) => check("dns-scopes", CheckStatus::Unknown, "could not verify effective NRPT policy"),
                    }
                }
            });
        }

        for c in &checks {
            match c.status {
                CheckStatus::Fail => status.reasons.push(c.name.to_string()),
                CheckStatus::Unknown => status.reasons.push(format!("{}-unknown", c.name)),
                _ => {}
            }
        }
        let recent = now().saturating_sub(record.updated_unix) < 20;
        status.state = derive_state(&checks, no_handshake_yet, recent);
        status.checks = checks;
    }
}

/// The IP stack needs a moment after the adapter appears; retry briefly, then give up.
fn retry<T>(mut f: impl FnMut() -> Result<T, WinError>) -> Result<T, WinError> {
    let mut last = None;
    for _ in 0..20 {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(last.unwrap_or(WinError::new("retry", 0)))
}

impl lovpn_client::protocol::ClientEngine for Engine {
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
        Engine::import_profile(self, name, profile, Some(private_key), expected_server_key)
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
    fn generate_identity(&mut self, name: &str) -> Result<ClientPublicKey, ClientError> {
        Engine::generate_identity(self, name)
    }
    fn import_identity_profile(
        &mut self,
        name: &str,
        profile: &str,
        expected_server_key: &str,
    ) -> Result<ProfileInfo, ClientError> {
        Engine::import_profile(self, name, profile, None, expected_server_key)
    }
    fn logs(&self, lines: u32) -> Result<Vec<String>, ClientError> {
        let text = std::fs::read_to_string(&self.log_path).unwrap_or_default();
        let all: Vec<&str> = text.lines().collect();
        let take = (lines.clamp(1, 1000)) as usize;
        Ok(all[all.len().saturating_sub(take)..]
            .iter()
            .map(|l| (*l).to_string())
            .collect())
    }
}
