//! Lab probe: create the adapter, push a config, observe, remove. Needs Administrator.
#[cfg(windows)]
fn main() {
    use lovpn_keys::{ClientPrivateKey, ServerPublicKey};
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        path::PathBuf,
    };
    let dll = PathBuf::from(std::env::args().nth(1).unwrap_or_default());
    let driver = match lovpn_win::driver::Driver::load(&dll) {
        Ok(d) => d,
        Err(e) => return println!("load failed: {e}"),
    };
    let key = ClientPrivateKey::generate().unwrap_or_else(|_| std::process::exit(2));
    let server: ServerPublicKey = ClientPrivateKey::generate()
        .map(|k| k.public_key().to_string())
        .unwrap_or_default()
        .parse()
        .unwrap_or_else(|_| std::process::exit(2));
    let adapter = match driver.create_adapter("LoVPN-probe") {
        Ok(a) => a,
        Err(e) => return println!("create failed: {e}"),
    };
    println!("created, luid={}", adapter.luid());
    let r = adapter.configure(
        &key,
        &server,
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9),
        &[(Ipv4Addr::UNSPECIFIED, 0)],
    );
    println!("configure: {r:?}");
    println!("up: {:?}", adapter.set_up(true));
    if let Ok(o) = adapter.observe() {
        println!(
            "rx={} tx={} handshake={:?}",
            o.rx_bytes, o.tx_bytes, o.handshake_age_secs
        );
    }
}
#[cfg(not(windows))]
fn main() {}
