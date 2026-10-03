//! Broker-owned profile storage (Unix).
//!
//! Layout inside the profile directory (mode 0700, owned by the service):
//! `<name>.toml` (public profile, 0600) and `<name>.key` (client private key, 0600).
//! Keeping the key here, rather than in the user's home, means a compromised user
//! session cannot read it, and the broker can reconnect without asking for it again.
//! The key still never leaves this machine and is never logged or echoed.
//!
//! Import requires the *expected server public key*, obtained out of band: a profile
//! whose server key differs is refused, because that is exactly what a tampered
//! profile looks like.
use crate::ClientError;
use lovpn_config::{ClientConfig, KillSwitchMode};
use lovpn_keys::{ClientPrivateKey, ServerPublicKey, file};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub const MAX_PROFILES: usize = 64;

pub struct ProfileStore {
    dir: PathBuf,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ProfileInfo {
    pub name: String,
    pub endpoint: SocketAddr,
    pub server_public_key: String,
    pub kill_switch: &'static str,
    pub interface: String,
}

pub fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.len() <= 32
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

pub fn kill_switch_name(mode: KillSwitchMode) -> &'static str {
    match mode {
        KillSwitchMode::Off => "off",
        KillSwitchMode::VpnOnly => "vpn-only",
        KillSwitchMode::Strict => "strict",
    }
}

fn io<T>(_: T) -> ClientError {
    ClientError::Storage
}

impl ProfileStore {
    pub fn open(dir: &Path) -> Result<Self, ClientError> {
        let meta = std::fs::symlink_metadata(dir).map_err(io)?;
        if meta.file_type().is_symlink()
            || !meta.is_dir()
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.mode() & 0o077 != 0
        {
            return Err(ClientError::Permissions);
        }
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    fn profile_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.toml"))
    }

    fn key_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.key"))
    }

    fn sync_dir(&self) -> Result<(), ClientError> {
        std::fs::File::open(&self.dir)
            .and_then(|d| d.sync_all())
            .map_err(io)
    }

    fn read_profile(&self, name: &str) -> Result<ClientConfig, ClientError> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits() as i32)
            .open(self.profile_path(name))
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    ClientError::ProfileNotFound
                } else {
                    ClientError::Storage
                }
            })?;
        let meta = file.metadata().map_err(io)?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.mode() & 0o177 != 0
        {
            return Err(ClientError::Permissions);
        }
        let mut text = String::new();
        (&mut file)
            .take(lovpn_config::MAX_CONFIG_BYTES as u64 + 1)
            .read_to_string(&mut text)
            .map_err(io)?;
        lovpn_config::parse(&text).map_err(|_| ClientError::ProfileInvalid)
    }

    /// Validate and store a profile with its private key.
    pub fn import(
        &self,
        name: &str,
        profile_text: &str,
        key: &ClientPrivateKey,
        expected_server_key: &ServerPublicKey,
    ) -> Result<ProfileInfo, ClientError> {
        if !valid_name(name) {
            return Err(ClientError::ProfileName);
        }
        let config = lovpn_config::parse(profile_text).map_err(|_| ClientError::ProfileInvalid)?;
        let server_key: ServerPublicKey = config
            .profile
            .server_public_key
            .parse()
            .map_err(|_| ClientError::ProfileInvalid)?;
        if server_key != *expected_server_key {
            return Err(ClientError::ServerKeyMismatch);
        }
        crate::plan::check_supported(&config)?;
        if self.profile_path(name).exists() || self.key_path(name).exists() {
            return Err(ClientError::ProfileExists);
        }
        if self.list()?.len() >= MAX_PROFILES {
            return Err(ClientError::TooManyProfiles);
        }
        file::write_new(&self.key_path(name), key).map_err(io)?;
        let temp = self.dir.join(format!("{name}.toml.tmp"));
        let _ = std::fs::remove_file(&temp);
        let written = (|| -> Result<(), ClientError> {
            let mut handle = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)
                .map_err(io)?;
            handle
                .write_all(profile_text.as_bytes())
                .and_then(|()| handle.sync_all())
                .map_err(io)?;
            std::fs::rename(&temp, self.profile_path(name)).map_err(io)?;
            self.sync_dir()
        })();
        if let Err(error) = written {
            let _ = std::fs::remove_file(&temp);
            let _ = std::fs::remove_file(self.key_path(name));
            return Err(error);
        }
        Ok(info(name, &config))
    }

    pub fn list(&self) -> Result<Vec<ProfileInfo>, ClientError> {
        let mut names: Vec<String> = std::fs::read_dir(&self.dir)
            .map_err(io)?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let file = entry.file_name().into_string().ok()?;
                let name = file.strip_suffix(".toml")?.to_string();
                (valid_name(&name) && self.key_path(&name).exists()).then_some(name)
            })
            .collect();
        names.sort();
        names
            .iter()
            .map(|name| Ok(info(name, &self.read_profile(name)?)))
            .collect()
    }

    pub fn load(&self, name: &str) -> Result<(ClientConfig, ClientPrivateKey), ClientError> {
        if !valid_name(name) {
            return Err(ClientError::ProfileName);
        }
        let config = self.read_profile(name)?;
        let key = file::read::<lovpn_keys::Client>(&self.key_path(name)).map_err(|error| match error {
            file::KeyFileError::Permissions => ClientError::Permissions,
            file::KeyFileError::Invalid(_) => ClientError::KeyInvalid,
            _ => ClientError::Storage,
        })?;
        Ok((config, key))
    }

    pub fn remove(&self, name: &str) -> Result<(), ClientError> {
        if !valid_name(name) {
            return Err(ClientError::ProfileName);
        }
        if !self.profile_path(name).exists() {
            return Err(ClientError::ProfileNotFound);
        }
        std::fs::remove_file(self.profile_path(name)).map_err(io)?;
        let _ = std::fs::remove_file(self.key_path(name));
        self.sync_dir()
    }
}

fn info(name: &str, config: &ClientConfig) -> ProfileInfo {
    ProfileInfo {
        name: name.to_string(),
        endpoint: config.profile.endpoint,
        server_public_key: config.profile.server_public_key.clone(),
        kill_switch: kill_switch_name(config.firewall.kill_switch),
        interface: config.tunnel.interface.clone(),
    }
}
