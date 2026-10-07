//! `lovpn-ui`: the LoVPN window.
//!
//! It runs as the normal user, serves a single local page on 127.0.0.1 and asks the LoVPN
//! service for everything, exactly like the `lovpn` command. It holds no secrets and makes
//! no network connection other than that loopback listener. It exits when the window closes.
#![cfg_attr(windows, windows_subsystem = "windows")]
mod api;
mod http;

use api::{Backend, Context};
use lovpn_cli::{AppError, Report, client};
use serde_json::Value;
use std::{
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    path::PathBuf,
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_CONNECTIONS: usize = 16;
/// The page pings every few seconds; without a ping for this long the window is gone.
const IDLE_EXIT_SECS: u64 = 45;
/// Never opened at all (the user ignored the link).
const NEVER_OPENED_EXIT_SECS: u64 = 300;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct Live {
    socket: PathBuf,
}

fn data(report: Result<Report, AppError>) -> Result<Value, AppError> {
    report.map(|r| r.data)
}

impl Live {
    /// Linux/Unix: the key lives in a private file only until the service has its own copy.
    #[cfg(unix)]
    fn key_path(name: &str) -> Result<PathBuf, AppError> {
        use std::os::unix::fs::DirBuilderExt;
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .ok_or_else(|| {
                AppError::new(
                    "identity.location",
                    "Could not find your configuration folder.",
                )
            })?;
        let dir = base.join("lovpn");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|_| {
                AppError::new(
                    "identity.location",
                    "Could not create a private folder for your key.",
                )
            })?;
        Ok(dir.join(format!("{name}.key")))
    }
}

impl Backend for Live {
    fn status(&self) -> Result<Value, AppError> {
        data(client::status(&self.socket))
    }
    fn profiles(&self) -> Result<Value, AppError> {
        data(client::profile_list(&self.socket))
    }
    fn connect(&self, profile: Option<&str>) -> Result<Value, AppError> {
        data(client::connect(&self.socket, profile))
    }
    fn disconnect(&self, release: bool) -> Result<Value, AppError> {
        data(client::disconnect(&self.socket, release))
    }
    fn reconnect(&self) -> Result<Value, AppError> {
        data(client::reconnect(&self.socket))
    }
    fn repair(&self) -> Result<Value, AppError> {
        data(client::repair(&self.socket))
    }
    fn reset(&self) -> Result<Value, AppError> {
        data(client::reset(&self.socket))
    }
    fn use_profile(&self, name: &str) -> Result<Value, AppError> {
        data(client::profile_use(&self.socket, name))
    }
    fn remove(&self, name: &str) -> Result<Value, AppError> {
        data(client::profile_remove(&self.socket, name))
    }
    fn test(&self, name: &str) -> Result<Value, AppError> {
        data(client::server_test(&self.socket, name))
    }
    fn create_identity(&self, name: &str) -> Result<Value, AppError> {
        #[cfg(unix)]
        let report = {
            let path = Self::key_path(name)?;
            client::identity_generate(&self.socket, Some(&path), None)
        };
        #[cfg(windows)]
        let report = client::identity_generate(&self.socket, None, Some(name));
        data(report)
    }
    fn device_key(&self, name: &str) -> Result<Value, AppError> {
        data(client::identity_public(&self.socket, None, Some(name)))
    }
    fn import(&self, name: &str, profile_text: &str, expected: &str) -> Result<Value, AppError> {
        #[cfg(unix)]
        let key = Some(Self::key_path(name)?);
        #[cfg(windows)]
        let key: Option<PathBuf> = None;
        data(client::profile_import_text(
            &self.socket,
            profile_text,
            name,
            key.as_deref(),
            expected,
            true,
        ))
    }
    fn logs(&self, lines: u32) -> Result<Value, AppError> {
        data(client::logs(&self.socket, lines))
    }
}

fn open_window(url: &str) {
    #[cfg(windows)]
    {
        // An app-style Edge window (always present on Windows 11); else the default browser.
        let edge = std::process::Command::new("cmd")
            .args(["/c", "start", "", "msedge", &format!("--app={url}")])
            .status();
        if !edge.is_ok_and(|s| s.success()) {
            let _ = std::process::Command::new("cmd")
                .args(["/c", "start", "", url])
                .status();
        }
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: lovpn-ui [--socket PATH] [--port N] [--no-open] [--url-file PATH]");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut socket = PathBuf::from(if cfg!(windows) {
        r"\\.\pipe\lovpn-client"
    } else {
        "/run/lovpn-client/broker.sock"
    });
    let mut port = 0u16;
    let mut open = true;
    let mut url_file: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => match args.next() {
                Some(v) => socket = PathBuf::from(v),
                None => return usage(),
            },
            "--port" => match args.next().and_then(|v| v.parse().ok()) {
                Some(v) => port = v,
                None => return usage(),
            },
            "--no-open" => open = false,
            "--url-file" => match args.next() {
                Some(v) => url_file = Some(PathBuf::from(v)),
                None => return usage(),
            },
            _ => return usage(),
        }
    }
    let mut secret = [0u8; 32];
    if getrandom::fill(&mut secret).is_err() {
        eprintln!("lovpn-ui: no secure random source is available.");
        return ExitCode::FAILURE;
    }
    let token: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    let listener = match TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("lovpn-ui: cannot listen on the loopback interface: {e}");
            return ExitCode::FAILURE;
        }
    };
    let Ok(local) = listener.local_addr() else {
        return ExitCode::FAILURE;
    };
    let ctx = Arc::new(Context {
        port: local.port(),
        token,
        last_ping: AtomicU64::new(0),
    });
    let backend: Arc<dyn Backend> = Arc::new(Live { socket });
    let url = format!("http://127.0.0.1:{}/?t={}", ctx.port, ctx.token);
    println!("LoVPN is running. If no window opened, open this link in your browser:\n{url}");
    if let Some(path) = &url_file {
        // Private file: the URL carries the session secret.
        let _ = std::fs::write(path, &url);
    }
    if open {
        open_window(&url);
    }

    let started = unix_now();
    {
        let ctx = Arc::clone(&ctx);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(5));
                let (now, ping) = (unix_now(), ctx.last_ping.load(Ordering::SeqCst));
                let gone = if ping == 0 {
                    now.saturating_sub(started) > NEVER_OPENED_EXIT_SECS
                } else {
                    now.saturating_sub(ping) > IDLE_EXIT_SECS
                };
                if gone {
                    std::process::exit(0);
                }
            }
        });
    }
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let (ctx, backend, active) = (Arc::clone(&ctx), Arc::clone(&backend), Arc::clone(&active));
        std::thread::spawn(move || {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            // Some operations (connect) legitimately take a while; only the write is bounded.
            let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
            let response = match http::read_request(&mut stream) {
                Ok(request) => api::route(&ctx, backend.as_ref(), &request, unix_now()),
                Err(http::ParseError::TooLarge) => http::Response::text(413, "Request too large."),
                Err(http::ParseError::Timeout) => http::Response::text(408, "Request timed out."),
                Err(http::ParseError::Malformed) => http::Response::text(400, "Bad request."),
            };
            let _ = http::write_response(&mut stream, &response);
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    ExitCode::SUCCESS
}
