//! The Linux tray: a StatusNotifierItem and freedesktop notifications.
//!
//! It runs as the normal user, polls the LoVPN service over the same local channel as the
//! `lovpn` command, and shows one StatusNotifierItem (the KDE/freedesktop tray protocol)
//! plus freedesktop notifications. It makes no network connection, holds no secrets, and
//! runs nothing but `lovpn-ui` (found next to itself or on PATH) when asked to open the window.
use crate::model::{Key, Tracker};
use ksni::{MenuItem, Tray, blocking::TrayMethods, menu::StandardItem};
use lovpn_cli::client;
use serde_json::Value;
use std::{
    collections::HashMap,
    path::PathBuf,
    process::{Command, ExitCode},
    time::Duration,
};

const POLL: Duration = Duration::from_secs(3);

struct LovpnTray {
    key: Key,
    socket: PathBuf,
}

impl LovpnTray {
    /// Run a service action off the tray's thread; the next poll shows the result.
    fn background(&self, action: fn(&std::path::Path)) {
        let socket = self.socket.clone();
        std::thread::spawn(move || action(&socket));
    }
}

fn open_window() {
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("lovpn-ui")))
        .filter(|path| path.is_file());
    let _ = Command::new(sibling.unwrap_or_else(|| PathBuf::from("lovpn-ui"))).spawn();
}

impl Tray for LovpnTray {
    fn id(&self) -> String {
        "lovpn".into()
    }
    fn title(&self) -> String {
        format!("LoVPN: {}", self.key.title())
    }
    fn icon_name(&self) -> String {
        self.key.icon().into()
    }
    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            StandardItem {
                label: self.key.title().into(),
                enabled: false,
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Open LoVPN".into(),
                activate: Box::new(|_| open_window()),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Connect".into(),
                enabled: self.key.can_connect(),
                activate: Box::new(|this: &mut Self| {
                    this.background(|socket| {
                        let _ = client::connect(socket, None);
                    });
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Disconnect".into(),
                enabled: self.key.can_disconnect(),
                activate: Box::new(|this: &mut Self| {
                    this.background(|socket| {
                        let _ = client::disconnect(socket, false);
                    });
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit tray".into(),
                activate: Box::new(|_| std::process::exit(0)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

/// One freedesktop notification. A desktop without a notification service is fine: skipped.
fn notify(body: &str) {
    let Ok(session) = zbus::blocking::Connection::session() else {
        return;
    };
    let hints: HashMap<&str, zbus::zvariant::Value<'_>> = HashMap::new();
    let _ = session.call_method(
        Some("org.freedesktop.Notifications"),
        "/org/freedesktop/Notifications",
        Some("org.freedesktop.Notifications"),
        "Notify",
        &(
            "LoVPN",
            0u32,
            "network-vpn",
            "LoVPN",
            body,
            Vec::<&str>::new(),
            hints,
            8000i32,
        ),
    );
}

pub fn run() -> ExitCode {
    let mut socket = PathBuf::from("/run/lovpn-client/broker.sock");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match (arg.as_str(), args.next()) {
            ("--socket", Some(path)) => socket = PathBuf::from(path),
            _ => {
                eprintln!("usage: lovpn-tray [--socket PATH]");
                return ExitCode::from(2);
            }
        }
    }
    let tray = LovpnTray {
        key: Key::Service,
        socket: socket.clone(),
    };
    let handle = match tray.spawn() {
        Ok(handle) => handle,
        Err(error) => {
            eprintln!(
                "lovpn-tray: no tray is available on this desktop ({error}). \
                 The window and the `lovpn` command still work."
            );
            return ExitCode::FAILURE;
        }
    };
    let mut tracker = Tracker::default();
    while !handle.is_closed() {
        let status: Option<Value> = client::status(&socket).ok().map(|report| report.data);
        let now = Key::from_status(status.as_ref());
        if let Some(message) = tracker.observe(now) {
            notify(message);
        }
        // The icon follows the settled state, so a one-poll blip does not flicker it.
        if let Some(settled) = tracker.settled() {
            handle.update(|tray| tray.key = settled);
        }
        std::thread::sleep(POLL);
    }
    ExitCode::SUCCESS
}
