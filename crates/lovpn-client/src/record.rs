//! The client broker's durable record of what it is responsible for.
//!
//! It exists so a restarted (or crashed) broker knows which interface, routing rules,
//! DNS settings and kill switch are *its own*, and what the user last asked for. It is
//! written before the matching change is made ("intent first") so a crash in the middle
//! of connecting can still be cleaned up or resumed.
use crate::ClientError;
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const RECORD_FILE: &str = "session.json";

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Desired {
    Connected,
    #[default]
    Disconnected,
}

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
        match std::fs::read(self.dir.join(RECORD_FILE)) {
            Ok(bytes) if bytes.len() < 8192 => {
                let record: SessionRecord =
                    serde_json::from_slice(&bytes).map_err(|_| ClientError::Record)?;
                if record.schema_version != 1 {
                    return Err(ClientError::Record);
                }
                Ok(record)
            }
            Ok(_) => Err(ClientError::Record),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(SessionRecord {
                schema_version: 1,
                ..SessionRecord::default()
            }),
            Err(_) => Err(ClientError::Record),
        }
    }

    pub fn save(&self, record: &SessionRecord) -> Result<(), ClientError> {
        let temp = self.dir.join("session.json.tmp");
        let _ = std::fs::remove_file(&temp);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
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
