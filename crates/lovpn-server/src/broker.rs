//! The privileged broker: a Unix-socket service that is the only component allowed to
//! change host networking on behalf of `lovpn-server`.
//!
//! Security properties (each covered by a test):
//! - the socket is `0600` and owned by the service user; callers are *also* checked
//!   with kernel peer credentials (`SO_PEERCRED`), per operation;
//! - one request per connection, one line of JSON, at most 4 KiB, strict schema, with
//!   read/write timeouts; requests are served one at a time (serialized);
//! - requests carry **no paths, interface names, addresses or commands**: the broker
//!   reads state from its own configured directory and runs the pure compilers;
//! - `apply` can demand an expected state generation and refuses states older than
//!   anything already applied (rollback protection kept in the broker's own directory);
//! - log lines contain the operation, caller uid and result code only.
use crate::{
    ServerError, Store,
    applier::{Applier, ApplyError, DEFAULT_IP_FORWARD, Runner},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const MAX_REQUEST_BYTES: u64 = 4096;
pub const MAX_RESPONSE_BYTES: u64 = 256 * 1024;
pub const DEFAULT_SOCKET: &str = "/run/lovpn-server/broker.sock";
const IO_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Op {
    Ping,
    Status,
    Apply,
    RepairFirewall,
    Teardown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub op: Op,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_generation: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Response {
    pub ok: bool,
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub data: Value,
}

impl Response {
    fn success(data: Value) -> Self {
        Self {
            ok: true,
            code: "ok".into(),
            message: "ok".into(),
            data,
        }
    }
    fn failure(code: &str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            code: code.into(),
            message: message.into(),
            data: Value::Null,
        }
    }
}

/// Operation-level authorization. Reaching the socket is not enough.
pub fn authorize(op: Op, caller_uid: u32, owner_uid: u32) -> bool {
    match op {
        // Removing protection and network configuration is root-only.
        Op::Teardown => caller_uid == 0,
        Op::Ping | Op::Status | Op::Apply | Op::RepairFirewall => {
            caller_uid == 0 || caller_uid == owner_uid
        }
    }
}

#[derive(Clone)]
pub struct BrokerConfig {
    pub state_dir: PathBuf,
    /// Unprivileged service user that owns `state_dir`.
    pub owner_uid: u32,
    /// Broker-private directory (not writable by `owner_uid`): the applied record.
    pub broker_dir: PathBuf,
    pub socket: PathBuf,
    pub ip_forward_path: PathBuf,
}

impl BrokerConfig {
    pub fn new(state_dir: PathBuf, owner_uid: u32, broker_dir: PathBuf, socket: PathBuf) -> Self {
        Self {
            state_dir,
            owner_uid,
            broker_dir,
            socket,
            ip_forward_path: PathBuf::from(DEFAULT_IP_FORWARD),
        }
    }
}

pub struct Broker {
    config: BrokerConfig,
    runner: Arc<dyn Runner>,
    listener: UnixListener,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerError {
    AlreadyRunning,
    Socket,
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AlreadyRunning => "Another broker is already listening on that socket.",
            Self::Socket => "The broker socket could not be created safely (check the directory and permissions).",
        })
    }
}

impl std::error::Error for BrokerError {}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Structured, sanitized log line: no payloads, keys, paths or peer data.
fn log(event: &str, op: Option<Op>, uid: Option<u32>, code: &str) {
    let line = json!({"ts": now(), "event": event, "op": op, "uid": uid, "code": code});
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

impl Broker {
    pub fn bind(config: BrokerConfig, runner: Arc<dyn Runner>) -> Result<Self, BrokerError> {
        let path = &config.socket;
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if !meta.file_type().is_socket() {
                return Err(BrokerError::Socket);
            }
            if UnixStream::connect(path).is_ok() {
                return Err(BrokerError::AlreadyRunning);
            }
            std::fs::remove_file(path).map_err(|_| BrokerError::Socket)?;
        }
        let listener = UnixListener::bind(path).map_err(|_| BrokerError::Socket)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| BrokerError::Socket)?;
        let privileged = rustix::process::geteuid().is_root();
        let chowned = rustix::fs::chown(
            path,
            Some(rustix::process::Uid::from_raw(config.owner_uid)),
            None,
        );
        if chowned.is_err() && privileged {
            return Err(BrokerError::Socket);
        }
        Ok(Self {
            config,
            runner,
            listener,
        })
    }

    /// Serve forever, one connection at a time.
    pub fn serve(&self) -> ! {
        loop {
            self.serve_one();
        }
    }

    /// Accept and fully handle exactly one connection (used by tests).
    pub fn serve_one(&self) {
        let Ok((stream, _)) = self.listener.accept() else {
            return;
        };
        self.handle(stream);
    }

    fn handle(&self, stream: UnixStream) {
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        let Ok(cred) = rustix::net::sockopt::socket_peercred(&stream) else {
            log(
                "peer-credentials-unavailable",
                None,
                None,
                "auth.no-credentials",
            );
            return;
        };
        let uid = cred.uid.as_raw();
        let response = match read_request(&stream) {
            Err(code) => {
                log("request-rejected", None, Some(uid), code);
                Response::failure(code, "The request was rejected as malformed or oversized.")
            }
            Ok(request) if !authorize(request.op, uid, self.config.owner_uid) => {
                log("request-denied", Some(request.op), Some(uid), "auth.denied");
                Response::failure(
                    "auth.denied",
                    "This caller is not authorized for that operation.",
                )
            }
            Ok(request) => {
                let response = self.dispatch(&request);
                log("request", Some(request.op), Some(uid), &response.code);
                response
            }
        };
        if let Ok(mut line) = serde_json::to_vec(&response) {
            line.push(b'\n');
            let _ = (&stream).write_all(&line);
        }
    }

    fn dispatch(&self, request: &Request) -> Response {
        if request.op == Op::Ping {
            return Response::success(json!({"pong": true}));
        }
        let applier = Applier {
            runner: self.runner.as_ref(),
            broker_dir: self.config.broker_dir.clone(),
            ip_forward_path: self.config.ip_forward_path.clone(),
        };
        let result: Result<Value, ApplyError> = (|| {
            if request.op == Op::Teardown {
                let report = applier.teardown()?;
                return Ok(json!(report));
            }
            let store = Store::open_as(&self.config.state_dir, self.config.owner_uid)?;
            let state = store.load()?;
            if request
                .expected_generation
                .is_some_and(|g| g != state.generation)
            {
                return Err(ApplyError::State(ServerError::Generation));
            }
            match request.op {
                Op::Status => Ok(json!(applier.observe(&state)?)),
                Op::Apply => {
                    let key = store.server_key()?;
                    Ok(json!(applier.apply(&state, &key)?))
                }
                Op::RepairFirewall => {
                    applier.repair_firewall(&state)?;
                    Ok(json!({"generation": state.generation}))
                }
                Op::Ping | Op::Teardown => Ok(Value::Null),
            }
        })();
        match result {
            Ok(data) => Response::success(data),
            Err(error) => Response::failure(error.code(), error.to_string()),
        }
    }
}

fn read_request(stream: &UnixStream) -> Result<Request, &'static str> {
    let mut line = Vec::new();
    BufReader::new(stream.take(MAX_REQUEST_BYTES + 1))
        .read_until(b'\n', &mut line)
        .map_err(|_| "request.io")?;
    if line.len() as u64 > MAX_REQUEST_BYTES {
        return Err("request.too-large");
    }
    serde_json::from_slice(&line).map_err(|_| "request.malformed")
}

/// Send one request to a broker and read its reply. Used by `lovpn-server`.
pub fn call(socket: &Path, request: &Request, timeout: Duration) -> Result<Response, ServerError> {
    let stream = UnixStream::connect(socket).map_err(|_| ServerError::Unsupported)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| ServerError::Storage)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| ServerError::Storage)?;
    let mut line = serde_json::to_vec(request).map_err(|_| ServerError::Storage)?;
    line.push(b'\n');
    (&stream)
        .write_all(&line)
        .map_err(|_| ServerError::Storage)?;
    let mut reply = Vec::new();
    BufReader::new((&stream).take(MAX_RESPONSE_BYTES + 1))
        .read_until(b'\n', &mut reply)
        .map_err(|_| ServerError::Storage)?;
    if reply.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(ServerError::Storage);
    }
    serde_json::from_slice(&reply).map_err(|_| ServerError::Storage)
}

/// Resolve a user name from `/etc/passwd` (no NSS, no network lookups).
pub fn resolve_user(name: &str) -> Option<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next() == Some(name)).then(|| fields.nth(1).and_then(|uid| uid.parse().ok()))?
    })
}
