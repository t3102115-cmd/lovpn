//! The service body: control pipe, request dispatch, monitor thread, log file.
//!
//! Security properties (mirroring the Linux broker): requests name a *profile*, never a
//! path, interface, address or command; at most 96 KiB per request, one JSON line; the
//! private key only travels in `import-profile` and is zeroized; log lines carry the
//! operation, caller SID and result code only.
use crate::{engine::Engine, pipe, store};
use lovpn_client::{
    ClientError,
    model::TickAction,
    protocol::{Request, Response, dispatch},
};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const MAX_REQUEST_BYTES: usize = 96 * 1024;
const LOG_ROTATE_BYTES: u64 = 1024 * 1024;
#[path = "lifecycle.rs"]
mod lifecycle;
use lifecycle::{MONITOR_INTERVAL, monitor_gap};

/// Installed by `lovpn-service install`; only administrators can write it.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub owner_sid: String,
}

pub struct Paths {
    pub state_dir: PathBuf,
    pub driver_dll: PathBuf,
    pub service_exe: PathBuf,
}

impl Paths {
    pub fn discover() -> std::io::Result<Self> {
        let exe = std::env::current_exe()?;
        let dir = exe.parent().map(Path::to_path_buf).unwrap_or_default();
        Ok(Self {
            state_dir: store::default_state_dir(),
            driver_dll: dir.join("wireguard.dll"),
            service_exe: exe,
        })
    }
}

pub fn read_config(state_dir: &Path) -> Option<ServiceConfig> {
    let text = std::fs::read_to_string(state_dir.join("service.json")).ok()?;
    let config: ServiceConfig = serde_json::from_str(&text).ok()?;
    (config.owner_sid.starts_with("S-1-")
        && config
            .owner_sid
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S'))
    .then_some(config)
}

pub fn write_config(state_dir: &Path, config: &ServiceConfig) -> std::io::Result<()> {
    store::ensure_private_dir(state_dir).map_err(|e| std::io::Error::other(e.to_string()))?;
    let text = serde_json::to_string(config).map_err(std::io::Error::other)?;
    std::fs::write(state_dir.join("service.json"), text)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct Logger {
    path: PathBuf,
}

impl Logger {
    fn log(&self, event: &str, op: Option<&str>, caller: Option<&str>, code: &str) {
        let line = serde_json::json!({"ts": unix_now(), "event": event, "op": op, "caller": caller, "code": code});
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if std::fs::metadata(&self.path).is_ok_and(|m| m.len() > LOG_ROTATE_BYTES) {
            let _ = std::fs::rename(&self.path, self.path.with_extension("log.1"));
        }
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(file, "{line}");
        }
    }
}

/// Shared with the service control handler.
#[derive(Default)]
pub struct Signals {
    pub stop: AtomicBool,
    /// Set on power resume so the monitor rebuilds the tunnel.
    pub resumed: AtomicBool,
    /// Set by IP interface/route notifications to request immediate observation.
    pub network_changed: AtomicBool,
}

/// Register notifications for both physical interface changes and default-route changes.
/// Callbacks only set an atomic flag: they never enter the engine mutex or call WFP.
struct NetworkNotifications {
    interface: windows_sys::Win32::Foundation::HANDLE,
    route: windows_sys::Win32::Foundation::HANDLE,
    _signals: Arc<Signals>,
}

impl NetworkNotifications {
    fn register(signals: &Arc<Signals>) -> Result<Self, crate::WinError> {
        use windows_sys::Win32::{NetworkManagement::IpHelper::*, Networking::WinSock::AF_UNSPEC};
        let mut registration = Self {
            interface: std::ptr::null_mut(),
            route: std::ptr::null_mut(),
            _signals: Arc::clone(signals),
        };
        let context = Arc::as_ptr(&registration._signals).cast_mut().cast();
        // SAFETY: the Arc keeps context alive until both callbacks are cancelled in Drop.
        let code = unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(interface_changed),
                context,
                false,
                &mut registration.interface,
            )
        };
        if code != 0 {
            return Err(crate::WinError::new("network-interface-notify", code));
        }
        // SAFETY: same lifetime contract; no initial callback is requested.
        let code = unsafe {
            NotifyRouteChange2(
                AF_UNSPEC,
                Some(route_changed),
                context,
                false,
                &mut registration.route,
            )
        };
        if code != 0 {
            return Err(crate::WinError::new("network-route-notify", code));
        }
        Ok(registration)
    }
}

// SAFETY: Windows supplies the registered context and keeps the referenced Arc alive
// until CancelMibChangeNotify2 completes; this callback never unregisters itself.
unsafe extern "system" fn interface_changed(
    context: *const std::ffi::c_void,
    _: *const windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPINTERFACE_ROW,
    _: windows_sys::Win32::NetworkManagement::IpHelper::MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: context is the Signals pointer registered above.
    unsafe { &*context.cast::<Signals>() }
        .network_changed
        .store(true, Ordering::SeqCst);
}

// SAFETY: identical registration lifetime contract to interface_changed.
unsafe extern "system" fn route_changed(
    context: *const std::ffi::c_void,
    _: *const windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2,
    _: windows_sys::Win32::NetworkManagement::IpHelper::MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: context is the Signals pointer registered above.
    unsafe { &*context.cast::<Signals>() }
        .network_changed
        .store(true, Ordering::SeqCst);
}

impl Drop for NetworkNotifications {
    fn drop(&mut self) {
        for handle in [self.interface, self.route] {
            if !handle.is_null() {
                // SAFETY: registered notification handle; cancellation waits for callbacks.
                let code = unsafe {
                    windows_sys::Win32::NetworkManagement::IpHelper::CancelMibChangeNotify2(handle)
                };
                if code != 0 {
                    // Cancellation failure means a callback might still reference Signals.
                    // Retain one strong reference rather than risking a use-after-free.
                    std::mem::forget(Arc::clone(&self._signals));
                }
            }
        }
    }
}

fn authorized(owner_sid: &str, caller: &pipe::Caller) -> bool {
    caller.is_admin || caller.sid == owner_sid || caller.sid == "S-1-5-18"
}

/// Emergency recovery that does not need the service: remove every LoVPN firewall filter
/// and record that nothing is armed, so a service that later starts does not put the block
/// back. Needs Administrator. This is the explicit user decision to leave `strict`.
pub fn release_offline(paths: &Paths) -> Result<(), String> {
    store::ensure_private_dir(&paths.state_dir).map_err(|e| e.to_string())?;
    let records =
        crate::record::RecordStore::open(paths.state_dir.clone()).map_err(|e| e.to_string())?;
    // Invalid/unknown intent must never be discarded to release the firewall.
    let mut record = records.load().map_err(|e| e.to_string())?;
    crate::record::restore_nrpt(
        &mut record,
        |journal| {
            crate::dns::restore(journal)
                .map(|_| ())
                .map_err(|_| lovpn_client::ClientError::CommandFailed("nrpt-restore"))
        },
        |restored| records.save(restored),
    )
    .map_err(|e| e.to_string())?;
    record.desired = lovpn_client::model::Desired::Disconnected;
    record.kill_switch_armed = false;
    record.mode = None;
    record.profile = None;
    record.endpoint_route = None;
    record.updated_unix = unix_now();
    // Persist the explicit release before removing filters: a crash between steps leaves
    // protection in place, rather than allowing startup to re-arm a supposedly released policy.
    records.save(&record).map_err(|e| e.to_string())?;
    crate::wfp::Engine::open()
        .and_then(|e| e.remove_all())
        .map_err(|e| e.to_string())
}

/// Run until `signals.stop`. Returns an error string only for startup failures.
pub fn run(paths: &Paths, signals: Arc<Signals>) -> Result<(), String> {
    store::ensure_private_dir(&paths.state_dir).map_err(|e| e.to_string())?;
    let config = read_config(&paths.state_dir)
        .ok_or("the service is not installed (missing or invalid service.json)")?;
    let logger = Arc::new(Logger {
        path: paths.state_dir.join("logs").join("service.log"),
    });
    let engine = Engine::new(
        paths.state_dir.clone(),
        &paths.driver_dll,
        paths.service_exe.display().to_string(),
    )
    .map_err(|e| e.to_string())?;
    let engine = Arc::new(Mutex::new(engine));

    // Resume the recorded state; boot packet filters cover the pre-BFE interval only
    // after an armed policy has successfully been committed at least once.
    if let Ok(mut e) = engine.lock() {
        let report = e.recover_on_start();
        logger.log(
            "startup",
            None,
            None,
            &format!("{:?}:{}", report.action, report.reasons.join(",")).to_lowercase(),
        );
    }

    let _notifications = NetworkNotifications::register(&signals).map_err(|e| {
        if let Ok(mut e) = engine.lock() {
            e.shutdown_tunnel();
        }
        e.to_string()
    })?;
    let monitor = spawn_monitor(&engine, &signals, &logger);

    let mut listener = pipe::Listener::new(pipe::DEFAULT_PIPE, &config.owner_sid);
    while !signals.stop.load(Ordering::SeqCst) {
        let mut connection = match listener.accept() {
            Ok(c) => c,
            Err(error) => {
                logger.log("accept-failed", None, None, error.step);
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        if signals.stop.load(Ordering::SeqCst) {
            break;
        }
        // Windows only allows impersonating a pipe client after the server has read from
        // it, so the request is read first; the pipe's DACL already limits who can connect.
        let line = connection.read_line(MAX_REQUEST_BYTES);
        let Ok(caller) = connection.caller() else {
            logger.log(
                "peer-credentials-unavailable",
                None,
                None,
                "auth.no-credentials",
            );
            continue;
        };
        let response = match line {
            None => {
                logger.log(
                    "request-rejected",
                    None,
                    Some(&caller.sid),
                    "request.malformed",
                );
                Response {
                    ok: false,
                    code: "request.malformed".into(),
                    message: "The request was rejected as malformed or oversized.".into(),
                    data: serde_json::Value::Null,
                }
            }
            Some(line) => {
                let line = Zeroizing::new(line);
                match serde_json::from_slice::<Request>(&line) {
                    Err(_) => {
                        logger.log(
                            "request-rejected",
                            None,
                            Some(&caller.sid),
                            "request.malformed",
                        );
                        Response {
                            ok: false,
                            code: "request.malformed".into(),
                            message: "The request was rejected as malformed or oversized.".into(),
                            data: serde_json::Value::Null,
                        }
                    }
                    Ok(request) if !authorized(&config.owner_sid, &caller) => {
                        logger.log(
                            "request-denied",
                            Some(request.op()),
                            Some(&caller.sid),
                            "auth.denied",
                        );
                        Response {
                            ok: false,
                            code: "auth.denied".into(),
                            message: "This caller is not authorized for that operation.".into(),
                            data: serde_json::Value::Null,
                        }
                    }
                    Ok(request) => {
                        let op = request.op();
                        let response = match engine.lock() {
                            Ok(mut e) => {
                                let response = dispatch(&mut *e, request);
                                if !response.ok
                                    && let Some(failure) = crate::engine::take_last_failure()
                                {
                                    logger.log(
                                        "step-failed",
                                        Some(op),
                                        None,
                                        &format!("{}:{}", failure.step, failure.win32),
                                    );
                                }
                                response
                            }
                            Err(_) => {
                                let error = ClientError::Record;
                                Response {
                                    ok: false,
                                    code: error.code().into(),
                                    message: error.to_string(),
                                    data: serde_json::Value::Null,
                                }
                            }
                        };
                        logger.log("request", Some(op), Some(&caller.sid), &response.code);
                        response
                    }
                }
            }
        };
        if let Ok(bytes) = serde_json::to_vec(&response) {
            connection.write_line(&bytes);
        }
    }
    // Join first: a monitor waking after shutdown must never recreate the adapter.
    let _ = monitor.join();
    // Graceful stop: drop the adapter and the host route; the firewall policy stays.
    if let Ok(mut e) = engine.lock() {
        e.shutdown_tunnel();
    }
    logger.log("stopped", None, None, "ok");
    Ok(())
}

fn spawn_monitor(
    engine: &Arc<Mutex<Engine>>,
    signals: &Arc<Signals>,
    logger: &Arc<Logger>,
) -> std::thread::JoinHandle<()> {
    let (engine, signals, logger) = (Arc::clone(engine), Arc::clone(signals), Arc::clone(logger));
    std::thread::spawn(move || {
        let mut last = SystemTime::now();
        let mut next_poll = Instant::now() + MONITOR_INTERVAL;
        while !signals.stop.load(Ordering::SeqCst) {
            // Short interruptible wait bounds stop/resume/network-event latency.
            std::thread::sleep(Duration::from_millis(100));
            if signals.stop.load(Ordering::SeqCst) {
                break;
            }
            let network_changed = signals.network_changed.swap(false, Ordering::SeqCst);
            let power_resumed = signals.resumed.swap(false, Ordering::SeqCst);
            if !network_changed && !power_resumed && Instant::now() < next_poll {
                continue;
            }
            let now = SystemTime::now();
            // `Instant` does not advance during suspend on Windows, so compare with wall time.
            let stalled = monitor_gap(last, now);
            last = now;
            next_poll = Instant::now() + MONITOR_INTERVAL;
            // Network changes request observation/route repair, not unconditional reconnect:
            // rebuilding the tunnel emits its own route/interface notifications.
            let resumed = power_resumed || stalled;
            let report = match engine.lock() {
                Ok(mut e) => e.tick(resumed),
                Err(_) => continue,
            };
            if !matches!(report.action, TickAction::Healthy | TickAction::Idle) {
                logger.log(
                    "monitor",
                    None,
                    None,
                    &format!("{:?}:{}", report.action, report.reasons.join(",")).to_lowercase(),
                );
            }
        }
    })
}
