//! The client broker: the only process allowed to change this machine's networking for
//! LoVPN. It owns profiles (including the client private key), the session record, the
//! kill switch, routing, the tunnel interface and per-link DNS.
//!
//! Security properties (covered by tests):
//! - `0600` socket owned by the controlling user, plus kernel peer credentials checked
//!   per operation (that user or root);
//! - one JSON line per connection, at most 96 KiB, strict schema, I/O timeouts, handled
//!   one at a time under a lock shared with the monitor;
//! - requests name a *profile*, never a path, interface, address or command;
//! - the private key travels only in `import-profile`, is held in zeroizing memory and is
//!   never logged, echoed or returned;
//! - log lines carry the operation, caller uid and result code only.
use crate::{ClientError, Engine, engine::TickAction};
use lovpn_sys::ipc;
use serde::Serialize;
use serde_json::json;
use std::{
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime},
};
use zeroize::Zeroizing;

pub const MAX_REQUEST_BYTES: u64 = 96 * 1024;
pub const MAX_RESPONSE_BYTES: u64 = 256 * 1024;
pub const DEFAULT_SOCKET: &str = "/run/lovpn-client/broker.sock";

pub use crate::protocol::{Request, Response, Secret};

/// Operation-level authorization. Every operation, including the recovery ones
/// (`disconnect`, `reset`), is available to the controlling user and root: a user must
/// always be able to get their network back. This also means a compromised user account
/// can lift the kill switch; the kill switch defends against network leaks, not against
/// a hostile local user (see docs/client.md).
pub fn authorize(_op: &str, caller_uid: u32, owner_uid: u32) -> bool {
    caller_uid == 0 || caller_uid == owner_uid
}

#[derive(Clone)]
pub struct BrokerConfig {
    pub socket: PathBuf,
    pub owner_uid: u32,
}

pub struct Broker {
    config: BrokerConfig,
    engine: Arc<Mutex<Engine>>,
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
            Self::AlreadyRunning => "Another client broker is already listening on that socket.",
            Self::Socket => "The broker socket could not be created safely.",
        })
    }
}

impl std::error::Error for BrokerError {}

fn log(event: &str, op: Option<&str>, uid: Option<u32>, code: &str) {
    ipc::log(json!({"ts": ipc::unix_now(), "event": event, "op": op, "uid": uid, "code": code}));
}

fn failure(error: ClientError) -> Response {
    Response::failure(error.code(), error.to_string())
}

impl Broker {
    pub fn bind(config: BrokerConfig, engine: Arc<Mutex<Engine>>) -> Result<Self, BrokerError> {
        let listener = ipc::bind(&config.socket, config.owner_uid).map_err(|e| match e {
            ipc::BindError::AlreadyRunning => BrokerError::AlreadyRunning,
            ipc::BindError::Socket => BrokerError::Socket,
        })?;
        Ok(Self {
            config,
            engine,
            listener,
        })
    }

    pub fn serve(&self) -> ! {
        loop {
            self.serve_one();
        }
    }

    pub fn serve_one(&self) {
        let Ok((stream, _)) = self.listener.accept() else {
            return;
        };
        self.handle(stream);
    }

    fn handle(&self, stream: UnixStream) {
        let _ = stream.set_read_timeout(Some(ipc::IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(ipc::IO_TIMEOUT));
        let Some(uid) = ipc::peer_uid(&stream) else {
            log(
                "peer-credentials-unavailable",
                None,
                None,
                "auth.no-credentials",
            );
            return;
        };
        let response = match ipc::read_line(&stream, MAX_REQUEST_BYTES) {
            Err(error) => {
                log("request-rejected", None, Some(uid), error.code());
                Response::failure(
                    error.code(),
                    "The request was rejected as malformed or oversized.",
                )
            }
            Ok(line) => {
                // The line may contain a private key: zeroize it when done.
                let line = Zeroizing::new(line);
                match serde_json::from_slice::<Request>(&line) {
                    Err(_) => {
                        log("request-rejected", None, Some(uid), "request.malformed");
                        Response::failure(
                            "request.malformed",
                            "The request was rejected as malformed or oversized.",
                        )
                    }
                    Ok(request) if !authorize(request.op(), uid, self.config.owner_uid) => {
                        log(
                            "request-denied",
                            Some(request.op()),
                            Some(uid),
                            "auth.denied",
                        );
                        Response::failure(
                            "auth.denied",
                            "This caller is not authorized for that operation.",
                        )
                    }
                    Ok(request) => {
                        let op = request.op();
                        let response = self.dispatch(request);
                        log("request", Some(op), Some(uid), &response.code);
                        response
                    }
                }
            }
        };
        ipc::write_json(&stream, &response);
    }

    fn dispatch(&self, request: Request) -> Response {
        let Ok(mut engine) = self.engine.lock() else {
            return failure(ClientError::Record);
        };
        crate::protocol::dispatch(&mut *engine, request)
    }
}

/// Wall clock moved ahead of the monotonic clock by more than `slack`: the machine was
/// suspended (or the clock was stepped). Either way, nudge the handshake.
pub fn detect_resume(wall_delta: Duration, mono_delta: Duration, slack: Duration) -> bool {
    wall_delta > mono_delta + slack
}

/// Reconcile in the background every `interval`. Never removes protection.
pub fn spawn_monitor(engine: Arc<Mutex<Engine>>, interval: Duration) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let (mut last_wall, mut last_mono) = (SystemTime::now(), Instant::now());
        loop {
            std::thread::sleep(interval);
            let (wall, mono) = (SystemTime::now(), Instant::now());
            let resumed = detect_resume(
                wall.duration_since(last_wall).unwrap_or_default(),
                mono.duration_since(last_mono),
                Duration::from_secs(10),
            );
            (last_wall, last_mono) = (wall, mono);
            let report = match engine.lock() {
                Ok(mut engine) => engine.tick(resumed),
                Err(_) => continue,
            };
            if !matches!(report.action, TickAction::Healthy | TickAction::Idle) {
                log(
                    "monitor",
                    None,
                    None,
                    &format!("{:?}:{}", report.action, report.reasons.join(",")).to_lowercase(),
                );
            }
        }
    })
}

/// Client side: send one request value, read one reply.
pub fn call<Q: Serialize>(
    socket: &Path,
    request: &Q,
    timeout: Duration,
) -> Result<Response, ipc::CallError> {
    ipc::call(socket, request, timeout, MAX_RESPONSE_BYTES)
}
