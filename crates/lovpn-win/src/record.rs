//! The service's durable record of what it is responsible for, written *before* each
//! change ("intent first") so a restart after a crash can finish or undo the work.
#[cfg(windows)]
use crate::store;
use lovpn_client::{ClientError, model::Desired};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
#[cfg(windows)]
use std::{
    io::{Read, Write},
    path::PathBuf,
};

#[cfg(windows)]
const FILE: &str = "session.json";
// 32 suffixes of 253 bytes plus 256 IPv4 resolvers fit comfortably, including JSON.
const MAX_BYTES: usize = 32768;

/// The host route that keeps the encrypted transport out of the tunnel.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRoute {
    pub luid: u64,
    pub destination: Ipv4Addr,
    pub next_hop: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Record {
    pub schema_version: u32,
    pub generation: u64,
    pub profile: Option<String>,
    pub desired: Desired,
    pub kill_switch_armed: bool,
    /// `off`, `vpn-only` or `strict` for the profile last connected.
    pub mode: Option<String>,
    /// Generation stamped into the installed firewall filters.
    pub firewall_generation: u64,
    pub endpoint_route: Option<EndpointRoute>,
    /// Durable NRPT intent, including partial apply/restore. Never infer it from profiles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nrpt: Option<crate::dns::Journal>,
    pub updated_unix: u64,
}

impl Record {
    pub fn validate(&self) -> Result<(), ClientError> {
        if !matches!(self.schema_version, 1 | 2)
            || self
                .profile
                .as_ref()
                .is_some_and(|name| !lovpn_client::model::valid_name(name))
            || self
                .mode
                .as_deref()
                .is_some_and(|mode| !matches!(mode, "off" | "vpn-only" | "strict"))
        {
            return Err(ClientError::Record);
        }
        if let Some(journal) = &self.nrpt {
            if self.schema_version != 2 {
                return Err(ClientError::Record);
            }
            journal.validate().map_err(|_| ClientError::Record)?;
        }
        if let Some(route) = &self.endpoint_route {
            let valid = |ip: Ipv4Addr| {
                ip.octets()[0] != 0
                    && ip.octets()[0] < 224
                    && !ip.is_loopback()
                    && !ip.is_link_local()
            };
            if route.luid == 0
                || !valid(route.destination)
                || route.next_hop.is_some_and(|ip| !valid(ip))
            {
                return Err(ClientError::Record);
            }
        }
        Ok(())
    }
}

#[cfg(any(windows, test))]
fn decode(bytes: &[u8]) -> Result<Record, ClientError> {
    if bytes.len() > MAX_BYTES {
        return Err(ClientError::Record);
    }
    let record: Record = serde_json::from_slice(bytes).map_err(|_| ClientError::Record)?;
    record.validate()?;
    Ok(record)
}

#[cfg(any(windows, test))]
fn encode(record: &Record) -> Result<Vec<u8>, ClientError> {
    record.validate()?;
    let bytes = serde_json::to_vec(record).map_err(|_| ClientError::Record)?;
    if bytes.len() > MAX_BYTES {
        return Err(ClientError::Record);
    }
    Ok(bytes)
}

/// Keep recovery intent until restoration AND its durable acknowledgement succeed.
/// Callers must not remove the DNS guard when this returns an error.
#[cfg(any(windows, test))]
pub(crate) fn restore_nrpt(
    record: &mut Record,
    restore: impl FnOnce(&crate::dns::Journal) -> Result<(), ClientError>,
    persist: impl FnOnce(&Record) -> Result<(), ClientError>,
) -> Result<(), ClientError> {
    if let Some(journal) = &record.nrpt {
        restore(journal)?;
        let mut restored = record.clone();
        restored.nrpt = None;
        persist(&restored)?;
        *record = restored;
    }
    Ok(())
}

#[cfg(windows)]
pub struct RecordStore {
    dir: PathBuf,
    // An exclusive Windows file handle serializes the service and offline release,
    // including journal persistence. Crashes release it automatically.
    _session_lock: std::fs::File,
}

#[cfg(windows)]
impl RecordStore {
    pub fn open(dir: PathBuf) -> Result<Self, ClientError> {
        store::ensure_private_dir(&dir).map_err(|_| ClientError::Permissions)?;
        use std::os::windows::fs::OpenOptionsExt;
        let session_lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(dir.join("session.lock"))
            .map_err(|_| ClientError::Record)?;
        Ok(Self {
            dir,
            _session_lock: session_lock,
        })
    }

    pub fn load(&self) -> Result<Record, ClientError> {
        let path = self.dir.join(FILE);
        match std::fs::metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Record {
                    schema_version: 1,
                    ..Record::default()
                });
            }
            Err(_) => return Err(ClientError::Record),
            Ok(m) if !m.is_file() || m.len() > MAX_BYTES as u64 => return Err(ClientError::Record),
            Ok(_) => {}
        }
        let mut bytes = Vec::new();
        std::fs::File::open(&path)
            .map_err(|_| ClientError::Record)?
            .take(MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ClientError::Record)?;
        decode(&bytes)
    }

    pub fn save(&self, record: &Record) -> Result<(), ClientError> {
        let bytes = encode(record)?;
        let path = self.dir.join(FILE);
        let temp = self.dir.join("session.json.tmp");
        let mut file = std::fs::File::create(&temp).map_err(|_| ClientError::Record)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| ClientError::Record)?;
        drop(file);
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        let source: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
        let target: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: both paths are valid NUL-terminated strings; replacement is write-through.
        if unsafe {
            MoveFileExW(
                source.as_ptr(),
                target.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(ClientError::Record);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pending() -> Record {
        Record {
            schema_version: 2,
            nrpt: Some(crate::dns::Journal {
                owner: "0123456789abcdef0123456789abcdef".into(),
                scopes: vec![crate::dns::Scope {
                    namespace: ".corp.example".into(),
                    servers: vec![Ipv4Addr::new(10, 0, 0, 53)],
                }],
            }),
            ..Record::default()
        }
    }
    #[test]
    fn old_record_compatible_but_unknown_and_invalid_intent_rejected() {
        let old = br#"{"schema_version":1,"generation":3,"profile":"office","desired":"disconnected","kill_switch_armed":false,"mode":"strict","firewall_generation":2,"endpoint_route":null,"updated_unix":1}"#;
        let decoded = decode(old);
        assert!(decoded.is_ok(), "{decoded:?}");
        assert!(decode(br#"{"schema_version":1,"future":true}"#).is_err());
        assert!(decode(br#"{"schema_version":99}"#).is_err());
        assert!(decode(br#"{"schema_version":1,"endpoint_route":{"luid":0,"destination":"192.0.2.1","next_hop":null}}"#).is_err());
        let mut r = pending();
        r.schema_version = 1;
        assert!(encode(&r).is_err());
        r.schema_version = 2;
        if let Some(j) = &mut r.nrpt {
            j.owner.clear();
        }
        assert!(encode(&r).is_err());
    }
    #[test]
    fn restoration_and_save_failures_retain_intent() {
        let mut r = pending();
        assert!(
            restore_nrpt(
                &mut r,
                |_| Err(ClientError::CommandFailed("nrpt")),
                |_| panic!("must not save failed restore")
            )
            .is_err()
        );
        assert!(r.nrpt.is_some());
        assert!(restore_nrpt(&mut r, |_| Ok(()), |_| Err(ClientError::Record)).is_err());
        assert!(r.nrpt.is_some());
        assert!(
            restore_nrpt(
                &mut r,
                |_| Ok(()),
                |saved| {
                    assert!(saved.nrpt.is_none());
                    Ok(())
                }
            )
            .is_ok()
        );
        assert!(r.nrpt.is_none());
    }
    #[test]
    fn largest_supported_journal_roundtrips_and_bound_is_enforced() {
        let mut r = pending();
        if let Some(j) = &mut r.nrpt {
            j.scopes = (0..32)
                .map(|i| crate::dns::Scope {
                    namespace: format!(
                        ".{}.{}.{}.s{i:02}{}",
                        "a".repeat(63),
                        "b".repeat(63),
                        "c".repeat(63),
                        "d".repeat(57)
                    ),
                    servers: (1..=8).map(|last| Ipv4Addr::new(10, 0, 0, last)).collect(),
                })
                .collect();
        }
        let bytes = encode(&r);
        assert!(bytes.is_ok(), "{bytes:?}");
        if let Ok(bytes) = bytes {
            assert!(decode(&bytes).is_ok());
            assert!(bytes.len() > 8192);
        }
        assert!(decode(&vec![b' '; MAX_BYTES + 1]).is_err());
    }

    mod fuzz {
        use super::super::decode;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn arbitrary_record_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
                let _ = decode(&bytes);
            }
        }
    }
}
