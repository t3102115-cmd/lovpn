//! Protected private-key files (Unix).
//!
//! Layout: one canonical base64 line, `0600`, regular file owned by the effective
//! user, in a directory that group/other users cannot write. This is the same text
//! form as `wg genkey`, so no LoVPN-specific format needs migration.
//!
//! Writes use `O_CREAT|O_EXCL|O_NOFOLLOW`: an existing key or symlink is never
//! overwritten or followed. A failed write removes its partial file. Reads refuse
//! symlinks, hard-linked, over-permissive, foreign-owned, non-regular or oversized
//! files. Rotation/replacement is deliberately not implemented here.
use crate::{KeyError, PrivateKey, Role};
use rustix::fs::OFlags;
use std::{
    error::Error,
    fmt,
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

/// Sanitized: never contains a path, key text or OS error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyFileError {
    /// Missing, unreadable, not a regular file, a symlink or hard-linked.
    Unavailable,
    /// File exists already; refusing to overwrite a key.
    Exists,
    /// Wrong owner, group/other access, or an unsafe parent directory.
    Permissions,
    /// Oversized or invalid contents.
    Invalid(KeyError),
    Io,
}

impl KeyFileError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "key-file.unavailable",
            Self::Exists => "key-file.exists",
            Self::Permissions => "key-file.permissions",
            Self::Invalid(_) => "key-file.invalid",
            Self::Io => "key-file.io",
        }
    }
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "Key file is missing or is not a plain, single-link regular file (symlinks are refused). No path is included in this error.",
            Self::Exists => "A key file already exists; LoVPN never overwrites key material.",
            Self::Permissions => "Key file must be mode 0600, owned by the current user, in a directory not writable by group or other users.",
            Self::Invalid(_) => "Key file contents are not one canonical, valid base64 key.",
            Self::Io => "Key file input/output failed; no partial key was kept.",
        })
    }
}

impl Error for KeyFileError {}

const MAX_KEY_FILE_BYTES: u64 = 128;

fn check_parent(path: &Path, owner_uid: u32) -> Result<(), KeyFileError> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let metadata = std::fs::metadata(parent).map_err(|_| KeyFileError::Unavailable)?;
    if !metadata.is_dir()
        || metadata.mode() & 0o022 != 0
        || (metadata.uid() != owner_uid && metadata.uid() != 0)
    {
        return Err(KeyFileError::Permissions);
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), KeyFileError> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    std::fs::File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| KeyFileError::Io)
}

/// Create a new `0600` key file. Fails if anything exists at `path`.
pub fn write_new<R: Role>(path: &Path, key: &PrivateKey<R>) -> Result<(), KeyFileError> {
    check_parent(path, rustix::process::geteuid().as_raw())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                KeyFileError::Exists
            } else {
                KeyFileError::Io
            }
        })?;
    let mut line = key.expose_base64();
    line.push('\n');
    let result = file
        .write_all(line.as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    if result.is_err() {
        let _ = std::fs::remove_file(path);
        return Err(KeyFileError::Io);
    }
    if sync_parent(path).is_err() {
        return Err(KeyFileError::Io);
    }
    Ok(())
}

/// Load and strictly validate a key file owned by the effective user.
pub fn read<R: Role>(path: &Path) -> Result<PrivateKey<R>, KeyFileError> {
    read_as(path, rustix::process::geteuid().as_raw())
}

/// Like [`read`], but the file must be owned by `owner_uid` instead. For a
/// privileged reader (the broker) of a key owned by an unprivileged service user.
pub fn read_as<R: Role>(path: &Path, owner_uid: u32) -> Result<PrivateKey<R>, KeyFileError> {
    check_parent(path, owner_uid)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|_| KeyFileError::Unavailable)?;
    let metadata = file.metadata().map_err(|_| KeyFileError::Io)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(KeyFileError::Unavailable);
    }
    if metadata.uid() != owner_uid || metadata.mode() & 0o177 != 0 {
        return Err(KeyFileError::Permissions);
    }
    if metadata.len() > MAX_KEY_FILE_BYTES {
        return Err(KeyFileError::Invalid(KeyError::Encoding));
    }
    let mut buffer = zeroize::Zeroizing::new(Vec::with_capacity(MAX_KEY_FILE_BYTES as usize + 1));
    (&mut file)
        .take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut buffer)
        .map_err(|_| KeyFileError::Io)?;
    let text = std::str::from_utf8(&buffer)
        .map_err(|_| KeyFileError::Invalid(KeyError::Encoding))?
        .strip_suffix('\n')
        .unwrap_or_default();
    PrivateKey::from_base64(text).map_err(KeyFileError::Invalid)
}
