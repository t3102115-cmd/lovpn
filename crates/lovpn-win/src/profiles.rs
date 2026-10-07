//! Profile storage under the protected state directory.
//!
//! `<name>.toml` is the public profile; `<name>.key` is the client private key sealed with
//! DPAPI. A `.key` without a `.toml` is a *pending identity*: a key pair the service made
//! so the administrator can be given its public key before the profile exists. The private
//! key never exists as a plain file.
use crate::store;
use lovpn_client::{
    ClientError,
    model::{ProfileInfo, kill_switch_name, valid_name},
    plan,
};
use lovpn_config::ClientConfig;
use lovpn_keys::{ClientPrivateKey, ClientPublicKey, ServerPublicKey};
use std::{io::Read, path::PathBuf};
use zeroize::Zeroizing;

pub const MAX_PROFILES: usize = 64;

pub struct ProfileStore {
    dir: PathBuf,
}

fn io<T>(_: T) -> ClientError {
    ClientError::Storage
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

impl ProfileStore {
    pub fn open(dir: PathBuf) -> Result<Self, ClientError> {
        store::ensure_private_dir(&dir).map_err(|_| ClientError::Permissions)?;
        Ok(Self { dir })
    }

    fn profile_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.toml"))
    }

    fn key_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.key"))
    }

    fn write_atomic(&self, path: &PathBuf, bytes: &[u8]) -> Result<(), ClientError> {
        let temp = path.with_extension("tmp");
        let _ = std::fs::remove_file(&temp);
        std::fs::write(&temp, bytes).map_err(io)?;
        std::fs::rename(&temp, path).map_err(|e| {
            let _ = std::fs::remove_file(&temp);
            io(e)
        })
    }

    /// Create a key pair held only by the service; returns the public key to give the
    /// server administrator.
    pub fn generate_identity(&self, name: &str) -> Result<ClientPublicKey, ClientError> {
        if !valid_name(name) {
            return Err(ClientError::ProfileName);
        }
        if self.profile_path(name).exists() || self.key_path(name).exists() {
            return Err(ClientError::ProfileExists);
        }
        let key = ClientPrivateKey::generate().map_err(|_| ClientError::KeyInvalid)?;
        self.seal_key(name, &key)?;
        Ok(key.public_key())
    }

    fn seal_key(&self, name: &str, key: &ClientPrivateKey) -> Result<(), ClientError> {
        let raw = key.expose_bytes();
        let sealed = store::seal(&raw[..]).map_err(|_| ClientError::Storage)?;
        self.write_atomic(&self.key_path(name), &sealed)
    }

    fn read_key(&self, name: &str) -> Result<ClientPrivateKey, ClientError> {
        let sealed = std::fs::read(self.key_path(name)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ClientError::ProfileNotFound
            } else {
                ClientError::Storage
            }
        })?;
        let raw = store::unseal(&sealed).map_err(|_| ClientError::KeyInvalid)?;
        let array: Zeroizing<[u8; 32]> =
            Zeroizing::new(<[u8; 32]>::try_from(&raw[..]).map_err(|_| ClientError::KeyInvalid)?);
        ClientPrivateKey::from_bytes(*array).map_err(|_| ClientError::KeyInvalid)
    }

    fn read_profile(&self, name: &str) -> Result<ClientConfig, ClientError> {
        let file = std::fs::File::open(self.profile_path(name)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ClientError::ProfileNotFound
            } else {
                ClientError::Storage
            }
        })?;
        let mut text = String::new();
        file.take(lovpn_config::MAX_CONFIG_BYTES as u64 + 1)
            .read_to_string(&mut text)
            .map_err(io)?;
        let config = lovpn_config::parse(&text).map_err(|_| ClientError::ProfileInvalid)?;
        // Listing/selecting an externally edited profile must enforce the same
        // supported-platform boundary as import and connect. Scoped DNS is additive
        // and supported on Windows; split routing remains explicitly unsupported.
        plan::check_supported(&config)?;
        Ok(config)
    }

    /// Validate and store a profile. `key` is `None` to use the pending identity `name`.
    pub fn import(
        &self,
        name: &str,
        profile_text: &str,
        key: Option<&ClientPrivateKey>,
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
        plan::check_supported(&config)?;
        if self.profile_path(name).exists() {
            return Err(ClientError::ProfileExists);
        }
        match key {
            Some(key) => {
                if self.key_path(name).exists() {
                    return Err(ClientError::ProfileExists);
                }
                if self.list()?.len() >= MAX_PROFILES {
                    return Err(ClientError::TooManyProfiles);
                }
                self.seal_key(name, key)?;
            }
            None => {
                // The pending identity must exist and be readable before the profile does.
                self.read_key(name)?;
            }
        }
        if let Err(error) = self.write_atomic(&self.profile_path(name), profile_text.as_bytes()) {
            if key.is_some() {
                let _ = std::fs::remove_file(self.key_path(name));
            }
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
        Ok((self.read_profile(name)?, self.read_key(name)?))
    }

    pub fn remove(&self, name: &str) -> Result<(), ClientError> {
        if !valid_name(name) {
            return Err(ClientError::ProfileName);
        }
        if !self.profile_path(name).exists() && !self.key_path(name).exists() {
            return Err(ClientError::ProfileNotFound);
        }
        let _ = std::fs::remove_file(self.profile_path(name));
        let _ = std::fs::remove_file(self.key_path(name));
        Ok(())
    }

    pub fn public_key_of(&self, name: &str) -> Result<ClientPublicKey, ClientError> {
        Ok(self.read_key(name)?.public_key())
    }
}
