//! `lovpn-service`: the privileged Windows client service.
//!
//! `lovpn-service service`    run under the Service Control Manager (what the service runs)
//! `lovpn-service run`        run in the foreground (laboratory use; Ctrl+C leaves the
//!                            persistent firewall policy in place, by design)
//! `lovpn-service install [--owner-sid SID]` / `uninstall`
#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("lovpn-service supports Windows only.");
    std::process::ExitCode::from(2)
}

#[cfg(windows)]
mod host;

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    host::main()
}
