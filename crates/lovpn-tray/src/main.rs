//! `lovpn-tray`: the LoVPN tray icon and notifications.
//!
//! It runs as the normal user, polls the LoVPN service over the same local channel as the
//! `lovpn` command, and shows one tray icon plus notifications. It makes no network
//! connection, holds no secrets, and runs nothing but `lovpn-ui` (found next to itself or on
//! PATH) when asked to open the window.
#![cfg_attr(windows, windows_subsystem = "windows")]
#[cfg(any(test, windows))]
mod icon;
#[cfg(target_os = "linux")]
mod linux;
mod model;
#[cfg(windows)]
mod windows;

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    return linux::run();
    #[cfg(windows)]
    return windows::run();
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        eprintln!("lovpn-tray: this platform has no tray support.");
        std::process::ExitCode::FAILURE
    }
}
