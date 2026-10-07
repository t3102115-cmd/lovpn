//! Atomic, locked, generation-checked persistence for server state (Unix).
//!
//! Layout inside the state directory (mode 0700, owned by the current user):
//! `state.json` (0600, public state + peer table), `server.key` (0600, the server
//! private key), `state.lock` (0600, advisory `flock` target) and the transient
//! `state.json.tmp`. Updates: lock, load, check generation, mutate in memory,
//! validate, write temp, fsync, rename over `state.json`, fsync directory. A crash
//! at any point leaves either the old or the new complete state; a leftover temp
//! file is ignored and removed by the next writer.
use crate::{ServerError, ServerState};
use lovpn_keys::{ServerPrivateKey, file};
use rustix::fs::{FlockOperation, OFlags, flock};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub const MAX_STATE_BYTES: u64 = 1 << 20;
const STATE_FILE: &str = "state.json";
const TEMP_FILE: &str = "state.json.tmp";
const LOCK_FILE: &str = "state.lock";
const KEY_FILE: &str = "server.key";
const TLS_FILE: &str = "enroll-tls.json";
const TLS_TEMP: &str = "enroll-tls.json.tmp";
const LIMITS_FILE: &str = "enroll-limits.json";
const LIMITS_TEMP: &str = "enroll-limits.json.tmp";

pub struct Store {
    dir: PathBuf,
    owner_uid: u32,
    crash_before_rename: bool,
}

fn nofollow() -> i32 {
    (OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32
}

fn storage<T>(_: T) -> ServerError {
    ServerError::Storage
}

impl Store {
    /// Create a new state directory (parent must exist) with mode 0700, or adopt one that
    /// the installer (systemd-tmpfiles) already created: it must be a real directory,
    /// owned by the current user, mode 0700 and **empty**. Anything else is `Exists`, so
    /// setup can never run over existing state or into a directory it does not own.
    pub fn create_dir(dir: &Path) -> Result<(), ServerError> {
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = std::fs::symlink_metadata(dir).map_err(storage)?;
                let mine = meta.is_dir()
                    && !meta.file_type().is_symlink()
                    && meta.uid() == rustix::process::geteuid().as_raw()
                    && meta.mode() & 0o777 == 0o700;
                let empty = std::fs::read_dir(dir).map_err(storage)?.next().is_none();
                if mine && empty {
                    Ok(())
                } else {
                    Err(ServerError::Exists)
                }
            }
            Err(_) => Err(ServerError::Storage),
        }
    }

    /// Open an existing state directory owned by the current user.
    pub fn open(dir: &Path) -> Result<Self, ServerError> {
        Self::open_as(dir, rustix::process::geteuid().as_raw())
    }

    /// Open a state directory that must be owned by `owner_uid` (mode 0700). Used by
    /// the privileged broker to read state owned by the unprivileged service user.
    /// Readers never take the lock or write; writers must use [`Store::open`].
    pub fn open_as(dir: &Path, owner_uid: u32) -> Result<Self, ServerError> {
        let link = std::fs::symlink_metadata(dir).map_err(storage)?;
        if link.file_type().is_symlink() || !link.is_dir() {
            return Err(ServerError::Permissions);
        }
        if link.uid() != owner_uid || link.mode() & 0o077 != 0 {
            return Err(ServerError::Permissions);
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            owner_uid,
            crash_before_rename: false,
        })
    }

    /// Test hook: abort a commit after the temp file is durable but before the
    /// rename, simulating a crash. Never enabled in production code paths.
    #[doc(hidden)]
    pub fn with_crash_before_rename(mut self) -> Self {
        self.crash_before_rename = true;
        self
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn sync_dir(&self) -> Result<(), ServerError> {
        File::open(&self.dir)
            .and_then(|dir| dir.sync_all())
            .map_err(storage)
    }

    fn lock(&self) -> Result<File, ServerError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nofollow())
            .open(self.path(LOCK_FILE))
            .map_err(storage)?;
        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|_| ServerError::Busy)?;
        Ok(file)
    }

    fn read_file(&self, name: &str) -> Result<Vec<u8>, ServerError> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(nofollow() | OFlags::NONBLOCK.bits() as i32)
            .open(self.path(name))
            .map_err(storage)?;
        let metadata = file.metadata().map_err(storage)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != self.owner_uid
            || metadata.mode() & 0o177 != 0
        {
            return Err(ServerError::Permissions);
        }
        if metadata.len() > MAX_STATE_BYTES {
            return Err(ServerError::State);
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(storage)?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(ServerError::State);
        }
        Ok(bytes)
    }

    fn load_unlocked(&self) -> Result<ServerState, ServerError> {
        let bytes = self.read_file(STATE_FILE)?;
        // Check the version before strict structural parsing so a newer schema is
        // reported as unsupported rather than corrupt. No automatic downgrade.
        let probe: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| ServerError::State)?;
        if probe
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            != Some(u64::from(crate::state::STATE_SCHEMA))
        {
            return Err(ServerError::Version);
        }
        let state: ServerState = serde_json::from_slice(&bytes).map_err(|_| ServerError::State)?;
        state.validate()?;
        Ok(state)
    }

    pub fn load(&self) -> Result<ServerState, ServerError> {
        self.load_unlocked()
    }

    /// Create the server identity key and the first state. Fails if either exists.
    pub fn init(&self, state: &ServerState, key: &ServerPrivateKey) -> Result<(), ServerError> {
        let _lock = self.lock()?;
        state.validate()?;
        if key.public_key().to_string() != state.server.public_key {
            return Err(ServerError::State);
        }
        if self.path(STATE_FILE).exists() || self.path(KEY_FILE).exists() {
            return Err(ServerError::Exists);
        }
        file::write_new(&self.path(KEY_FILE), key).map_err(storage)?;
        if let Err(error) = self.write_state(state) {
            // Do not leave an identity key without state.
            let _ = std::fs::remove_file(self.path(KEY_FILE));
            return Err(error);
        }
        Ok(())
    }

    /// Load the server private key and verify it matches the state's public key.
    pub fn server_key(&self) -> Result<ServerPrivateKey, ServerError> {
        let state = self.load()?;
        let key: ServerPrivateKey =
            file::read_as(&self.path(KEY_FILE), self.owner_uid).map_err(|error| match error {
                file::KeyFileError::Permissions => ServerError::Permissions,
                file::KeyFileError::Invalid(_) => ServerError::State,
                _ => ServerError::Storage,
            })?;
        if key.public_key().to_string() != state.server.public_key {
            return Err(ServerError::State);
        }
        Ok(key)
    }

    fn write_state(&self, state: &ServerState) -> Result<(), ServerError> {
        let mut json = serde_json::to_vec_pretty(state).map_err(|_| ServerError::State)?;
        json.push(b'\n');
        let temp = self.path(TEMP_FILE);
        let _ = std::fs::remove_file(&temp);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nofollow())
            .open(&temp)
            .map_err(storage)?;
        file.write_all(&json)
            .and_then(|()| file.sync_all())
            .map_err(storage)?;
        drop(file);
        if self.crash_before_rename {
            return Err(ServerError::Storage);
        }
        std::fs::rename(&temp, self.path(STATE_FILE)).map_err(storage)?;
        self.sync_dir()
    }

    /// Apply `change` atomically. Returns the committed generation and the closure
    /// result. If `expected_generation` is set and stale, nothing is changed.
    pub fn update<T>(
        &self,
        expected_generation: Option<u64>,
        change: impl FnOnce(&mut ServerState) -> Result<T, ServerError>,
    ) -> Result<(u64, T), ServerError> {
        let _lock = self.lock()?;
        let _ = std::fs::remove_file(self.path(TEMP_FILE));
        let mut state = self.load_unlocked()?;
        if expected_generation.is_some_and(|expected| expected != state.generation) {
            return Err(ServerError::Generation);
        }
        let value = change(&mut state)?;
        state.generation = state.generation.checked_add(1).ok_or(ServerError::State)?;
        state.validate()?;
        self.write_state(&state)?;
        Ok((state.generation, value))
    }

    fn write_private_new(&self, name: &str, bytes: &[u8]) -> Result<(), ServerError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nofollow())
            .open(self.path(name))
            .map_err(storage)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(storage)
    }

    fn tls_document(
        certificate: &[u8],
        private_key: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, ServerError> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let document = serde_json::json!({
            "version": 1,
            "certificate_der": STANDARD.encode(certificate),
            "private_key_pkcs8": STANDARD.encode(private_key),
        });
        serde_json::to_vec(&document)
            .map(zeroize::Zeroizing::new)
            .map_err(|_| ServerError::State)
    }

    /// Persist the enrollment TLS identity (certificate and PKCS#8 key in ONE 0600 file,
    /// so a crash can never leave a mismatched pair). Never overwrites an existing
    /// identity: the pin would silently change. Use [`Store::rotate_tls_identity`].
    pub fn init_tls_identity(
        &self,
        certificate: &[u8],
        private_key: &[u8],
    ) -> Result<(), ServerError> {
        let _lock = self.lock()?;
        if self.path(TLS_FILE).exists() {
            return Err(ServerError::Exists);
        }
        let document = Self::tls_document(certificate, private_key)?;
        let _ = std::fs::remove_file(self.path(TLS_TEMP));
        self.write_private_new(TLS_TEMP, &document)?;
        std::fs::rename(self.path(TLS_TEMP), self.path(TLS_FILE)).map_err(storage)?;
        self.sync_dir()
    }

    /// Replace the enrollment TLS identity atomically (one rename). The old identity is
    /// not kept: the pin changes at once, so rotate between enrollment windows and give
    /// clients the new pin. Pending tokens are unaffected. The identity must exist.
    pub fn rotate_tls_identity(
        &self,
        certificate: &[u8],
        private_key: &[u8],
    ) -> Result<(), ServerError> {
        let _lock = self.lock()?;
        if !self.path(TLS_FILE).exists() {
            return Err(ServerError::NotFound);
        }
        // Refuse to rotate away from something unreadable or unsafe without noticing.
        self.read_file(TLS_FILE)?;
        let document = Self::tls_document(certificate, private_key)?;
        let _ = std::fs::remove_file(self.path(TLS_TEMP));
        self.write_private_new(TLS_TEMP, &document)?;
        std::fs::rename(self.path(TLS_TEMP), self.path(TLS_FILE)).map_err(storage)?;
        self.sync_dir()
    }

    /// Load the enrollment TLS identity; permissions are checked like the state file.
    pub fn tls_identity(&self) -> Result<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>), ServerError> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Document {
            version: u32,
            certificate_der: String,
            private_key_pkcs8: String,
        }
        let bytes = zeroize::Zeroizing::new(self.read_file(TLS_FILE)?);
        let document: Document = serde_json::from_slice(&bytes).map_err(|_| ServerError::State)?;
        if document.version != 1 {
            return Err(ServerError::Version);
        }
        let certificate = STANDARD
            .decode(&document.certificate_der)
            .map_err(|_| ServerError::State)?;
        let key = zeroize::Zeroizing::new(
            STANDARD
                .decode(&document.private_key_pkcs8)
                .map_err(|_| ServerError::State)?,
        );
        Ok((certificate, key))
    }

    /// Identity of the identity file on disk (inode, size, mtime ns): changes when the
    /// identity is rotated, so a running listener can reload it without a restart.
    pub fn tls_identity_stamp(&self) -> Option<(u64, u64, i64)> {
        let m = std::fs::symlink_metadata(self.path(TLS_FILE)).ok()?;
        Some((m.ino(), m.len(), m.mtime() * 1_000_000_000 + m.mtime_nsec()))
    }

    /// Previously persisted failure budgets, if any. Corrupt or unsafe files are
    /// treated as absent (the limiter then starts empty and rewrites it).
    pub fn load_limits(&self) -> Option<Vec<u8>> {
        self.read_file(LIMITS_FILE).ok()
    }

    /// Atomically replace the failure-budget file. Single writer: the listener.
    pub fn save_limits(&self, bytes: &[u8]) -> Result<(), ServerError> {
        let _ = std::fs::remove_file(self.path(LIMITS_TEMP));
        self.write_private_new(LIMITS_TEMP, bytes)?;
        std::fs::rename(self.path(LIMITS_TEMP), self.path(LIMITS_FILE)).map_err(storage)
    }
}
