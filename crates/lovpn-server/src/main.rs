//! `lovpn-server`: offline state and peer management. Executes no system commands,
//! opens no sockets and applies no firewall or WireGuard configuration.
#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("lovpn-server supports Linux only.");
    std::process::ExitCode::from(2)
}

#[cfg(target_os = "linux")]
mod cli;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    cli::main()
}
