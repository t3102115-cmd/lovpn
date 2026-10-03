//! Authenticated Unix-socket service skeleton shared by the LoVPN brokers.
//!
//! The socket is `0600` and owned by the service user; callers are additionally
//! identified with kernel peer credentials (`SO_PEERCRED`) so the broker can authorize
//! each *operation*. One request per connection: a single JSON line of bounded size.
use serde::{Serialize, de::DeserializeOwned};
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const IO_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindError {
    AlreadyRunning,
    Socket,
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AlreadyRunning => "Another broker is already listening on that socket.",
            Self::Socket => "The broker socket could not be created safely (check the directory and permissions).",
        })
    }
}

impl std::error::Error for BindError {}

/// Bind `path` safely: refuse non-socket files and live brokers, replace stale sockets,
/// then restrict to `0600` and hand to `owner_uid` (a failed chown is fatal for root).
pub fn bind(path: &Path, owner_uid: u32) -> Result<UnixListener, BindError> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() {
            return Err(BindError::Socket);
        }
        if UnixStream::connect(path).is_ok() {
            return Err(BindError::AlreadyRunning);
        }
        std::fs::remove_file(path).map_err(|_| BindError::Socket)?;
    }
    let listener = UnixListener::bind(path).map_err(|_| BindError::Socket)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| BindError::Socket)?;
    let chowned = rustix::fs::chown(path, Some(rustix::process::Uid::from_raw(owner_uid)), None);
    if chowned.is_err() && rustix::process::geteuid().is_root() {
        return Err(BindError::Socket);
    }
    Ok(listener)
}

/// The caller's uid as reported by the kernel.
pub fn peer_uid(stream: &UnixStream) -> Option<u32> {
    rustix::net::sockopt::socket_peercred(stream)
        .ok()
        .map(|cred| cred.uid.as_raw())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadError {
    TooLarge,
    Io,
}

impl ReadError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooLarge => "request.too-large",
            Self::Io => "request.io",
        }
    }
}

/// Read one `\n`-terminated line of at most `max` bytes (the newline included).
pub fn read_line(stream: &UnixStream, max: u64) -> Result<Vec<u8>, ReadError> {
    let mut line = Vec::new();
    BufReader::new(stream.take(max + 1))
        .read_until(b'\n', &mut line)
        .map_err(|_| ReadError::Io)?;
    if line.len() as u64 > max {
        return Err(ReadError::TooLarge);
    }
    Ok(line)
}

pub fn write_json<T: Serialize>(stream: &UnixStream, value: &T) {
    if let Ok(mut line) = serde_json::to_vec(value) {
        line.push(b'\n');
        let _ = (&*stream).write_all(&line);
    }
}

/// Client side: send one request, read one reply of at most `max_response` bytes.
pub fn call<Q: Serialize, R: DeserializeOwned>(
    socket: &Path,
    request: &Q,
    timeout: Duration,
    max_response: u64,
) -> Result<R, CallError> {
    let stream = UnixStream::connect(socket).map_err(|_| CallError::Unreachable)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| CallError::Io)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| CallError::Io)?;
    let mut line = serde_json::to_vec(request).map_err(|_| CallError::Io)?;
    line.push(b'\n');
    (&stream).write_all(&line).map_err(|_| CallError::Io)?;
    let reply = read_line(&stream, max_response).map_err(|_| CallError::Io)?;
    serde_json::from_slice(&reply).map_err(|_| CallError::Io)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallError {
    /// Nothing is listening, or the caller may not connect.
    Unreachable,
    Io,
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Structured, sanitized log line (JSON to stderr, captured by journald).
pub fn log(fields: serde_json::Value) {
    let _ = writeln!(std::io::stderr().lock(), "{fields}");
}

/// Resolve a user name from `/etc/passwd` (no NSS, no network lookups).
pub fn resolve_user(name: &str) -> Option<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next() == Some(name)).then(|| fields.nth(1).and_then(|uid| uid.parse().ok()))?
    })
}
