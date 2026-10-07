//! Online-enrollment listener (runs as the unprivileged service user, never root).
//!
//! One connection is handled at a time: failure budget check (before TLS and before
//! reading anything) → pinned-identity TLS 1.3 handshake → one bounded request line →
//! atomic redemption under the state lock → profile → best-effort apply through the
//! broker. Every step has a deadline. Responses to failed redemptions are uniform.
//! Logs record the event class and token *id* only: no token text, request body,
//! client address or key.
use crate::{
    ExportOptions, ServerError, Store,
    enroll::Redemption,
    limits::{self, Limits},
};
use lovpn_enroll::{
    EnrollError, proto,
    tls::{self, Pin},
    token::Token,
};
use lovpn_keys::ClientPublicKey;
use rustls::ServerConfig;
use serde_json::json;
use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Overall per-connection deadline (handshake + request + response).
pub const CONNECTION_DEADLINE: Duration = Duration::from_secs(10);
const BUSY_RETRIES: u32 = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Redeemed,
    Replayed,
    Denied,
    Malformed,
    Unavailable,
    RateLimited,
    HandshakeFailed,
}

impl Outcome {
    const fn label(self) -> &'static str {
        match self {
            Self::Redeemed => "redeemed",
            Self::Replayed => "replayed",
            Self::Denied => "denied",
            Self::Malformed => "malformed",
            Self::Unavailable => "unavailable",
            Self::RateLimited => "rate-limited",
            Self::HandshakeFailed => "handshake-failed",
        }
    }
    const fn is_failure(self) -> bool {
        matches!(self, Self::Denied | Self::Malformed | Self::HandshakeFailed)
    }
}

pub type ApplyFn = Box<dyn FnMut(u64) -> bool>;

struct Context {
    store: Store,
    options: ExportOptions,
    apply: ApplyFn,
    clock: Box<dyn Fn() -> u64>,
}

pub struct Enroller {
    ctx: Context,
    config: Arc<ServerConfig>,
    pin: Pin,
    identity_stamp: Option<(u64, u64, i64)>,
    limits: Limits,
    deadline: Duration,
}

fn wall_clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Enroller {
    /// Load the persisted TLS identity and failure budgets. The identity must have
    /// been created with `enroll tls-init`; it is never created implicitly, so the pin
    /// an administrator distributes cannot change underneath them.
    pub fn new(store: Store, options: ExportOptions, apply: ApplyFn) -> Result<Self, ServerError> {
        // Stamp BEFORE reading: a rotation landing in between leaves a stale stamp, so the
        // next connection reloads, never the other way round (new stamp, old identity).
        let identity_stamp = store.tls_identity_stamp();
        let (certificate, key) = store.tls_identity()?;
        let config = tls::server_config(&certificate, &key).map_err(|_| ServerError::State)?;
        let pin = Pin::of_certificate(&certificate);
        let limits = store
            .load_limits()
            .and_then(|bytes| Limits::from_json(&bytes))
            .unwrap_or_default();
        Ok(Self {
            ctx: Context {
                store,
                options,
                apply,
                clock: Box::new(wall_clock),
            },
            config,
            pin,
            identity_stamp,
            limits,
            deadline: CONNECTION_DEADLINE,
        })
    }

    pub fn pin(&self) -> Pin {
        self.pin
    }

    /// Test hook: a fixed clock, so expiry can be exercised deterministically.
    #[doc(hidden)]
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> u64>) -> Self {
        self.ctx.clock = clock;
        self
    }

    #[doc(hidden)]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    fn persist_limits(&self) {
        // A failed write only weakens persistence across restarts; it is not fatal.
        let _ = self.ctx.store.save_limits(&self.limits.to_json());
    }

    /// Pick up a rotated TLS identity (see `enroll tls-rotate`) without a restart. A
    /// changed but unusable identity file keeps the previous identity serving and is
    /// logged; it never downgrades to anything weaker.
    fn reload_identity_if_rotated(&mut self) {
        let stamp = self.ctx.store.tls_identity_stamp();
        if stamp == self.identity_stamp {
            return;
        }
        self.identity_stamp = stamp;
        let loaded = self
            .ctx
            .store
            .tls_identity()
            .ok()
            .and_then(|(certificate, key)| {
                let config = tls::server_config(&certificate, &key).ok()?;
                Some((config, Pin::of_certificate(&certificate)))
            });
        match loaded {
            Some((config, pin)) => {
                self.config = config;
                self.pin = pin;
                lovpn_sys::ipc::log(
                    json!({"event": "enroll-identity-reloaded", "pin": pin.to_string()}),
                );
            }
            None => lovpn_sys::ipc::log(json!({"event": "enroll-identity-reload-failed"})),
        }
    }

    /// Handle one accepted connection and return what happened.
    pub fn handle(&mut self, socket: TcpStream, remote: SocketAddr) -> Outcome {
        self.reload_identity_if_rotated();
        let now = (self.ctx.clock)();
        let source = limits::source_key(remote.ip());
        if self.limits.check(&source, now).is_err() {
            // Dropped before any TLS or parsing work.
            drop(socket);
            log(Outcome::RateLimited, None, None);
            return Outcome::RateLimited;
        }
        let mut outcome = None;
        let mut token_id = None;
        let mut peer_id = None;
        let ctx = &mut self.ctx;
        let result =
            tls::serve_connection(Arc::clone(&self.config), socket, self.deadline, |request| {
                let (answer, result) = process(ctx, request);
                token_id = result.token_id;
                peer_id = result.peer_id;
                outcome = Some(result.outcome);
                answer
            });
        let outcome = match (outcome, result) {
            (Some(outcome), Ok(())) => outcome,
            (Some(outcome), Err(_)) if !outcome.is_failure() => outcome,
            (Some(outcome), Err(_)) => outcome,
            (None, _) => Outcome::HandshakeFailed,
        };
        let now = (self.ctx.clock)();
        if outcome.is_failure() {
            self.limits.failure(&source, now);
            self.persist_limits();
        } else if matches!(outcome, Outcome::Redeemed | Outcome::Replayed) {
            self.limits.success(&source, now);
            self.persist_limits();
        }
        log(outcome, token_id.as_deref(), peer_id);
        outcome
    }

    /// Accept loop; polls `stop` so a signal handler or test can end it.
    pub fn serve(&mut self, listener: &TcpListener, stop: &AtomicBool) -> std::io::Result<()> {
        listener.set_nonblocking(true)?;
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((socket, remote)) => {
                    let _ = socket.set_nonblocking(false);
                    self.handle(socket, remote);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(40));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

struct Processed {
    outcome: Outcome,
    token_id: Option<String>,
    peer_id: Option<u32>,
}

fn refuse(outcome: Outcome, error: EnrollError, token_id: Option<String>) -> (Vec<u8>, Processed) {
    let answer = proto::encode(&proto::Response::failure(error)).unwrap_or_default();
    (
        answer,
        Processed {
            outcome,
            token_id,
            peer_id: None,
        },
    )
}

fn process(ctx: &mut Context, request: Result<Vec<u8>, EnrollError>) -> (Vec<u8>, Processed) {
    let Ok(line) = request else {
        return refuse(Outcome::Malformed, EnrollError::Malformed, None);
    };
    let Ok(request) = proto::parse_request(&line) else {
        return refuse(Outcome::Malformed, EnrollError::Malformed, None);
    };
    let Ok(token) = Token::parse(&request.token) else {
        // A malformed token is answered like any other wrong token.
        return refuse(Outcome::Denied, EnrollError::Denied, None);
    };
    let token_id = Some(token.id_hex());
    let Ok(key) = request.client_public_key.parse::<ClientPublicKey>() else {
        return refuse(Outcome::Malformed, EnrollError::Malformed, token_id);
    };
    let now = (ctx.clock)();
    let Ok(state) = ctx.store.load() else {
        return refuse(Outcome::Unavailable, EnrollError::Unavailable, token_id);
    };
    let (redemption, generation) = if let Some(peer) = state.replayed_peer(&token, &key, now) {
        (
            Redemption {
                peer_id: peer.id,
                replayed: true,
            },
            state.generation,
        )
    } else {
        let mut attempt = 0;
        loop {
            match ctx.store.update(None, |s| s.redeem_token(&token, key, now)) {
                Ok((generation, redemption)) => break (redemption, generation),
                Err(ServerError::Busy) if attempt < BUSY_RETRIES => {
                    attempt += 1;
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(ServerError::Busy | ServerError::Storage | ServerError::Clock) => {
                    return refuse(Outcome::Unavailable, EnrollError::Unavailable, token_id);
                }
                // Unknown, wrong secret, expired, used, revoked, duplicate key, pool
                // exhausted…: one answer for the caller, details only in the class log.
                Err(_) => return refuse(Outcome::Denied, EnrollError::Denied, token_id),
            }
        }
    };
    let Ok(state) = ctx.store.load() else {
        return refuse(Outcome::Unavailable, EnrollError::Unavailable, token_id);
    };
    let profile = state.export_profile(&redemption.peer_id.to_string(), &ctx.options);
    let Ok(profile) = profile else {
        return refuse(Outcome::Unavailable, EnrollError::Unavailable, token_id);
    };
    let applied = (ctx.apply)(state.generation.max(generation));
    let answer = proto::encode(&proto::Response::success(
        profile,
        state.server.public_key.clone(),
        applied,
    ))
    .unwrap_or_default();
    (
        answer,
        Processed {
            outcome: if redemption.replayed {
                Outcome::Replayed
            } else {
                Outcome::Redeemed
            },
            token_id,
            peer_id: Some(redemption.peer_id),
        },
    )
}

fn log(outcome: Outcome, token_id: Option<&str>, peer_id: Option<u32>) {
    lovpn_sys::ipc::log(json!({
        "event": "enroll",
        "outcome": outcome.label(),
        "token_id": token_id,
        "peer_id": peer_id,
    }));
}
