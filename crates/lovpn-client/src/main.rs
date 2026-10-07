//! `lovpn-clientd`: the privileged client broker (run as root, normally by systemd).
#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("lovpn-clientd supports Linux only.");
    std::process::ExitCode::from(2)
}

#[cfg(target_os = "linux")]
mod daemon;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    daemon::main()
}
