//! Lab: install the kill switch, prove it blocks and permits as compiled, then remove it.
//! Reverts everything before exiting, including on failure paths. Needs Administrator.
#[cfg(windows)]
fn main() {
    use lovpn_win::{policy, wfp};
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
        time::Duration,
    };
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let input = policy::PolicyInput {
        generation: 1,
        tunnel_interface: None,
        endpoint: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 51820),
        service_path: exe,
        kill_switch: true,
        dns_guard: true,
        block_ipv6: true,
    };
    let engine = match wfp::Engine::open() {
        Ok(e) => e,
        Err(e) => return println!("open: {e}"),
    };
    let specs = policy::compile(&input);
    let internet = SocketAddr::from(([1, 1, 1, 1], 443));
    let before = TcpStream::connect_timeout(&internet, Duration::from_secs(4)).is_ok();
    println!("before: internet reachable = {before}");
    let listener = TcpListener::bind("127.0.0.1:0").ok();
    let local = listener.as_ref().and_then(|l| l.local_addr().ok());
    let r = engine.replace(&specs);
    println!("install: {r:?}");
    if r.is_ok() {
        let mut names: Vec<_> = specs.iter().map(|s| s.name.clone()).collect();
        names.sort();
        println!(
            "installed == compiled: {}",
            engine.installed().ok().as_ref() == Some(&names)
        );
        println!(
            "blocked: internet connect ok = {}",
            TcpStream::connect_timeout(&internet, Duration::from_secs(4)).is_ok()
        );
        if let Some(a) = local {
            println!(
                "loopback connect ok = {}",
                TcpStream::connect_timeout(&a, Duration::from_secs(2)).is_ok()
            );
        }
    }
    println!("remove: {:?}", engine.remove_all());
    println!(
        "installed after remove: {:?}",
        engine.installed().map(|v| v.len())
    );
    println!(
        "after: internet reachable = {}",
        TcpStream::connect_timeout(&internet, Duration::from_secs(4)).is_ok()
    );
}
#[cfg(not(windows))]
fn main() {}
