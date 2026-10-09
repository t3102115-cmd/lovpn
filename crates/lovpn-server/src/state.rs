//! Pure server state model. No filesystem, network or process access.
use crate::ServerError;
use ipnet::Ipv4Net;
use lovpn_config::KillSwitchMode;
use lovpn_firewall::server::ServerPolicy;
use lovpn_keys::{ClientPublicKey, ServerPublicKey};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const STATE_SCHEMA: u32 = 1;
pub const MAX_PEERS: usize = 1024;
pub const DEFAULT_LISTEN_PORT: u16 = 51820;
pub const DEFAULT_INTERFACE: &str = "lovpn-srv0";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerState {
    pub schema_version: u32,
    /// Incremented by exactly one on every committed change.
    pub generation: u64,
    pub server: ServerSettings,
    pub next_peer_id: u32,
    pub peers: Vec<Peer>,
    /// Client keys replaced by rotation; never accepted again.
    pub retired_keys: Vec<String>,
    /// Online-enrollment tokens (digests only). Absent in pre-M2c state files.
    #[serde(default)]
    pub enrollment: crate::enroll::EnrollmentState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
    pub label: String,
    pub interface: String,
    pub wan_interface: String,
    pub endpoint: SocketAddr,
    pub listen_port: u16,
    pub pool: Ipv4Net,
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
    /// Only `block` exists; the field makes the policy explicit and migratable.
    pub ipv6: String,
    /// Public key only. The private key lives in a separate 0600 file.
    pub public_key: String,
    pub created_unix: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeerStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    /// Never reused.
    pub id: u32,
    pub name: String,
    pub public_key: String,
    pub address: Ipv4Addr,
    pub status: PeerStatus,
    /// Number of key rotations applied to this peer.
    pub key_epoch: u32,
    pub created_unix: u64,
    pub revoked_unix: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct SetupParams {
    pub label: String,
    pub interface: String,
    pub wan_interface: String,
    pub endpoint: SocketAddr,
    pub listen_port: u16,
    pub pool: Ipv4Net,
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
}

#[derive(Clone, Debug)]
pub struct ExportOptions {
    pub client_interface: String,
    pub kill_switch: KillSwitchMode,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            client_interface: "lovpn0".into(),
            kill_switch: KillSwitchMode::Strict,
        }
    }
}

pub fn valid_interface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}

pub(crate) fn valid_peer_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.bytes().all(|c| c.is_ascii_digit())
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 80
        && label.trim() == label
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " -_.()".contains(c))
}

fn private_pool(pool: Ipv4Net) -> bool {
    const PRIVATE: &[(Ipv4Addr, u8)] = &[
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
        (Ipv4Addr::new(100, 64, 0, 0), 10),
    ];
    pool.addr() == pool.network()
        && (16..=29).contains(&pool.prefix_len())
        && PRIVATE
            .iter()
            .any(|(net, len)| Ipv4Net::new(*net, *len).is_ok_and(|private| private.contains(&pool)))
}

impl ServerState {
    pub fn new(
        params: SetupParams,
        public_key: ServerPublicKey,
        now_unix: u64,
    ) -> Result<Self, ServerError> {
        let state = Self {
            schema_version: STATE_SCHEMA,
            generation: 1,
            server: ServerSettings {
                label: params.label,
                interface: params.interface,
                wan_interface: params.wan_interface,
                endpoint: params.endpoint,
                listen_port: params.listen_port,
                pool: params.pool,
                dns: params.dns,
                mtu: params.mtu,
                ipv6: "block".into(),
                public_key: public_key.to_string(),
                created_unix: now_unix,
            },
            next_peer_id: 1,
            peers: Vec::new(),
            retired_keys: Vec::new(),
            enrollment: crate::enroll::EnrollmentState::default(),
        };
        state.validate()?;
        Ok(state)
    }

    /// Address the server uses inside the tunnel: the first host of the pool.
    pub fn server_address(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.server.pool.network()).wrapping_add(1))
    }

    pub fn server_public_key(&self) -> Result<ServerPublicKey, ServerError> {
        self.server
            .public_key
            .parse()
            .map_err(|_| ServerError::State)
    }

    /// Revalidate everything, including state loaded from disk.
    pub fn validate(&self) -> Result<(), ServerError> {
        if self.schema_version != STATE_SCHEMA {
            return Err(ServerError::Version);
        }
        let s = &self.server;
        if !valid_label(&s.label) {
            return Err(ServerError::Label);
        }
        // The owned tunnel must be recognisably LoVPN's, so a state file written by the
        // unprivileged service user cannot make the root broker create or reconfigure
        // some other interface. (The WAN name is the uplink and is not created by us.)
        if !valid_interface(&s.interface)
            || !s.interface.starts_with("lovpn")
            || !valid_interface(&s.wan_interface)
            || s.interface == s.wan_interface
        {
            return Err(ServerError::Interface);
        }
        if !private_pool(s.pool) {
            return Err(ServerError::Pool);
        }
        if s.listen_port == 0 {
            return Err(ServerError::Endpoint);
        }
        if s.dns.is_empty() || s.dns.len() > 4 || s.dns.iter().any(IpAddr::is_ipv6) {
            return Err(ServerError::Dns);
        }
        if !(1280..=1420).contains(&s.mtu) {
            return Err(ServerError::Mtu);
        }
        if s.ipv6 != "block" {
            return Err(ServerError::Ipv6);
        }
        let server_key = self.server_public_key()?;
        if self.peers.len() > MAX_PEERS || self.retired_keys.len() > MAX_PEERS * 8 {
            return Err(ServerError::State);
        }
        let mut seen_keys = vec![server_key.to_string()];
        let mut seen_addresses = vec![self.server_address()];
        let mut max_id = 0;
        for (index, peer) in self.peers.iter().enumerate() {
            let key: ClientPublicKey = peer.public_key.parse().map_err(|_| ServerError::State)?;
            if !valid_peer_name(&peer.name)
                || self.peers[..index].iter().any(|other| other.id == peer.id)
                || (peer.status == PeerStatus::Active
                    && self.peers[..index]
                        .iter()
                        .any(|o| o.status == PeerStatus::Active && o.name == peer.name))
                || peer.id == 0
                || !(peer.status == PeerStatus::Revoked) == peer.revoked_unix.is_some()
                || !s.pool.contains(&peer.address)
                || peer.address == s.pool.network()
                || peer.address == s.pool.broadcast()
                || seen_addresses.contains(&peer.address)
                || seen_keys.contains(&key.to_string())
            {
                return Err(ServerError::State);
            }
            seen_keys.push(key.to_string());
            seen_addresses.push(peer.address);
            max_id = max_id.max(peer.id);
        }
        for retired in &self.retired_keys {
            let key: ClientPublicKey = retired.parse().map_err(|_| ServerError::State)?;
            if seen_keys.contains(&key.to_string()) {
                return Err(ServerError::State);
            }
            seen_keys.push(key.to_string());
        }
        if self.next_peer_id <= max_id {
            return Err(ServerError::State);
        }
        self.enrollment.validate(self)?;
        // Every profile this server exports must pass the client validator.
        let probe_address = Ipv4Addr::from(u32::from(s.pool.network()).wrapping_add(2));
        self.render_profile(&ExportOptions::default(), probe_address, &server_key)
            .map(|_| ())
            .map_err(|_| ServerError::Endpoint)
    }

    fn key_in_use(&self, key: &ClientPublicKey) -> bool {
        let text = key.to_string();
        self.peers.iter().any(|p| p.public_key == text) || self.retired_keys.contains(&text)
    }

    fn check_new_key(&self, key: &ClientPublicKey) -> Result<(), ServerError> {
        if key.as_bytes() == self.server_public_key()?.as_bytes() {
            return Err(ServerError::Key);
        }
        if self.key_in_use(key) {
            return Err(ServerError::DuplicateKey);
        }
        Ok(())
    }

    fn free_address(&self) -> Result<Ipv4Addr, ServerError> {
        let pool = self.server.pool;
        let first = u32::from(pool.network()) + 2; // .1 is the server
        let last = u32::from(pool.broadcast()) - 1;
        (first..=last)
            .map(Ipv4Addr::from)
            .find(|candidate| self.peers.iter().all(|p| p.address != *candidate))
            .ok_or(ServerError::PoolExhausted)
    }

    pub fn create_peer(
        &mut self,
        name: &str,
        key: ClientPublicKey,
        now_unix: u64,
    ) -> Result<&Peer, ServerError> {
        if !valid_peer_name(name) {
            return Err(ServerError::Name);
        }
        if self.peers.len() >= MAX_PEERS {
            return Err(ServerError::TooManyPeers);
        }
        if self
            .peers
            .iter()
            .any(|p| p.status == PeerStatus::Active && p.name == name)
        {
            return Err(ServerError::DuplicateName);
        }
        self.check_new_key(&key)?;
        let address = self.free_address()?;
        let id = self.next_peer_id;
        self.next_peer_id = id.checked_add(1).ok_or(ServerError::TooManyPeers)?;
        self.peers.push(Peer {
            id,
            name: name.into(),
            public_key: key.to_string(),
            address,
            status: PeerStatus::Active,
            key_epoch: 0,
            created_unix: now_unix,
            revoked_unix: None,
        });
        self.peers.last().ok_or(ServerError::State)
    }

    fn active_index(&self, selector: &str) -> Result<usize, ServerError> {
        let id = selector.parse::<u32>().ok();
        self.peers
            .iter()
            .position(|p| {
                p.status == PeerStatus::Active
                    && match id {
                        Some(id) => p.id == id,
                        None => p.name == selector,
                    }
            })
            .ok_or(ServerError::NotFound)
    }

    pub fn find_active(&self, selector: &str) -> Result<&Peer, ServerError> {
        Ok(&self.peers[self.active_index(selector)?])
    }

    pub fn revoke_peer(&mut self, selector: &str, now_unix: u64) -> Result<&Peer, ServerError> {
        let index = self.active_index(selector)?;
        let peer = &mut self.peers[index];
        peer.status = PeerStatus::Revoked;
        peer.revoked_unix = Some(now_unix);
        Ok(&self.peers[index])
    }

    /// Replace a peer's public key, keeping its lease. The old key is retired.
    pub fn rotate_peer(
        &mut self,
        selector: &str,
        key: ClientPublicKey,
    ) -> Result<&Peer, ServerError> {
        let index = self.active_index(selector)?;
        self.check_new_key(&key)?;
        let old = self.peers[index].public_key.clone();
        if self.retired_keys.len() >= MAX_PEERS * 8 {
            return Err(ServerError::TooManyPeers);
        }
        self.retired_keys.push(old);
        let peer = &mut self.peers[index];
        peer.public_key = key.to_string();
        peer.key_epoch = peer.key_epoch.saturating_add(1);
        Ok(&self.peers[index])
    }

    pub fn active_peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers.iter().filter(|p| p.status == PeerStatus::Active)
    }

    pub fn firewall_policy(&self) -> ServerPolicy {
        ServerPolicy {
            interface: self.server.interface.clone(),
            wan_interface: self.server.wan_interface.clone(),
            pool: self.server.pool,
            leases: self.active_peers().map(|p| p.address).collect(),
            generation: self.generation,
        }
    }

    /// Public, secret-free client profile; revalidated by `lovpn-config`.
    pub fn export_profile(
        &self,
        selector: &str,
        options: &ExportOptions,
    ) -> Result<String, ServerError> {
        let peer = self.find_active(selector)?;
        self.render_profile(options, peer.address, &self.server_public_key()?)
    }

    fn render_profile(
        &self,
        options: &ExportOptions,
        client_address: Ipv4Addr,
        server_key: &ServerPublicKey,
    ) -> Result<String, ServerError> {
        if !valid_interface(&options.client_interface) {
            return Err(ServerError::Interface);
        }
        let s = &self.server;
        let dns = s
            .dns
            .iter()
            .map(|ip| format!("\"{ip}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let kill = match options.kill_switch {
            KillSwitchMode::Off => "off",
            KillSwitchMode::VpnOnly => "vpn-only",
            KillSwitchMode::Strict => "strict",
        };
        // Every interpolated value is a typed address/number or passed a strict
        // character allowlist above, so no TOML injection is possible.
        let text = format!(
            "# LoVPN public client profile. Contains NO private key.\n\
             # Verify the server public key out of band before use.\n\
             schema_version = 1\n\n\
             [profile]\nname = \"{label}\"\nendpoint = \"{endpoint}\"\nserver_public_key = \"{server_key}\"\n\n\
             [tunnel]\ninterface = \"{iface}\"\naddresses = [\"{client_address}/32\"]\nmtu = {mtu}\nrouting = \"full\"\nroutes = [\"0.0.0.0/0\"]\nipv6 = \"block\"\n\n\
             [dns]\nservers = [{dns}]\n\n\
             [firewall]\nkill_switch = \"{kill}\"\n",
            label = s.label,
            endpoint = s.endpoint,
            iface = options.client_interface,
            mtu = s.mtu,
        );
        lovpn_config::parse(&text).map_err(|_| ServerError::Export)?;
        Ok(text)
    }
}
