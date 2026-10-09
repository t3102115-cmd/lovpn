//! A client that connects and stays silent must not hold the single-threaded accept loop.
#![cfg(windows)]
#![allow(clippy::unwrap_used)]

use lovpn_win::pipe::Listener;
use std::{
    fs::OpenOptions,
    io::Write,
    sync::mpsc,
    time::{Duration, Instant},
};

#[test]
fn a_silent_client_is_dropped_and_the_next_client_is_served() {
    let name = format!(r"\\.\pipe\lovpn-test-{}", std::process::id());
    let (tx, rx) = mpsc::channel();
    let server_name = name.clone();
    std::thread::spawn(move || {
        // S-1-5-32-544 (Administrators) is also granted by the pipe's own DACL.
        let mut listener = Listener::new(&server_name, "S-1-5-32-544");
        for _ in 0..2 {
            let mut connection = listener.accept().unwrap();
            let started = Instant::now();
            let line = connection.read_line(4096);
            tx.send((line, started.elapsed())).unwrap();
        }
    });

    // Connect and send nothing.
    let silent = loop {
        match OpenOptions::new().read(true).write(true).open(&name) {
            Ok(file) => break file,
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    let (line, waited) = rx.recv_timeout(Duration::from_secs(20)).unwrap();
    assert!(line.is_none(), "a silent client yields no request");
    assert!(
        waited >= Duration::from_secs(4) && waited < Duration::from_secs(10),
        "the read gave up after the deadline, not forever: {waited:?}"
    );
    drop(silent);

    // The loop is free again: a normal client is served promptly.
    let mut client = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&name)
        .unwrap();
    client.write_all(b"{\"op\":\"ping\"}\n").unwrap();
    let (line, waited) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(line.unwrap(), b"{\"op\":\"ping\"}");
    assert!(waited < Duration::from_secs(2));
}
