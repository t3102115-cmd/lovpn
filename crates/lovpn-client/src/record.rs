//! The client broker's durable record of what it is responsible for.
//!
//! It exists so a restarted (or crashed) broker knows which interface, routing rules,
//! DNS settings and kill switch are *its own*, and what the user last asked for. It is
//! written before the matching change is made ("intent first") so a crash in the middle
//! of connecting can still be cleaned up or resumed.
use crate::ClientError;
use rustix::fs::OFlags;
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const RECORD_FILE: &str = "session.json";
const MAX_RECORD_BYTES: u64 = 8192;

fn nofollow() -> i32 {
    (OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32
}

pub use crate::model::Desired;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct SessionRecord {
    pub schema_version: u32,
    /// Incremented every time the desired state or the installed policy changes. The
    /// kill-switch table is stamped with it so its generation can be observed.
    pub generation: u64,
    pub profile: Option<String>,
    pub desired: Desired,
    pub kill_switch_armed: bool,
    /// Kill-switch mode of the profile last connected: `off`, `vpn-only` or `strict`.
    pub mode: Option<String>,
    /// Generation stamped into the installed firewall table, and the profile it was
    /// compiled for; a different profile forces an atomic reinstall.
    pub firewall_generation: u64,
    pub firewall_profile: Option<String>,
    /// Interface this broker created and may modify or delete.
    pub interface_owned: Option<String>,
    /// Routing rules/routes installed by this broker.
    pub routing_installed: bool,
    /// Interface name for which per-link DNS settings were applied.
    pub dns_interface: Option<String>,
    pub updated_unix: u64,
}

pub struct RecordStore {
    dir: PathBuf,
}

impl RecordStore {
    pub fn open(dir: &Path) -> Result<Self, ClientError> {
        let meta = std::fs::symlink_metadata(dir).map_err(|_| ClientError::Record)?;
        if meta.file_type().is_symlink()
            || !meta.is_dir()
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.mode() & 0o077 != 0
        {
            return Err(ClientError::Record);
        }
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub fn load(&self) -> Result<SessionRecord, ClientError> {
        let path = self.dir.join(RECORD_FILE);
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(nofollow() | OFlags::NONBLOCK.bits() as i32)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SessionRecord {
                    schema_version: 1,
                    ..SessionRecord::default()
                });
            }
            Err(_) => return Err(ClientError::Record),
        };
        let metadata = file.metadata().map_err(|_| ClientError::Record)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o177 != 0
            || metadata.len() >= MAX_RECORD_BYTES
        {
            return Err(ClientError::Record);
        }
        let mut bytes = Vec::with_capacity(MAX_RECORD_BYTES as usize);
        file.take(MAX_RECORD_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|_| ClientError::Record)?;
        let record: SessionRecord =
            serde_json::from_slice(&bytes).map_err(|_| ClientError::Record)?;
        if record.schema_version != 1 {
            return Err(ClientError::Record);
        }
        Ok(record)
    }

    pub fn save(&self, record: &SessionRecord) -> Result<(), ClientError> {
        let temp = self.dir.join("session.json.tmp");
        let _ = std::fs::remove_file(&temp);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nofollow())
            .open(&temp)
            .map_err(|_| ClientError::Record)?;
        let json = serde_json::to_vec_pretty(record).map_err(|_| ClientError::Record)?;
        file.write_all(&json)
            .and_then(|()| file.sync_all())
            .map_err(|_| ClientError::Record)?;
        std::fs::rename(&temp, self.dir.join(RECORD_FILE)).map_err(|_| ClientError::Record)?;
        std::fs::File::open(&self.dir)
            .and_then(|d| d.sync_all())
            .map_err(|_| ClientError::Record)
    }
}
