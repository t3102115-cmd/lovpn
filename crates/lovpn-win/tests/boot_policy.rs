use lovpn_win::policy::{self, Action, BOOT_LAYERS, PolicyInput};
use std::net::{Ipv4Addr, SocketAddrV4};

#[test]
fn boot_generation_tracks_armed_runtime_policy_and_explicit_release() {
    let mut input = PolicyInput {
        generation: 99,
        tunnel_interface: Some(123),
        endpoint: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 51820),
        service_path: r"C:\Program Files\LoVPN\lovpn-clientd.exe".into(),
        kill_switch: true,
        dns_guard: true,
        block_ipv6: true,
    };
    let boot = policy::compile_boot(&policy::compile(&input));
    assert_eq!(boot.len(), BOOT_LAYERS.len());
    assert!(
        boot.iter()
            .all(|f| f.action == Action::Block && f.conditions.is_empty())
    );
    assert!(
        boot.iter()
            .all(|f| f.name.starts_with("LoVPN g99 boot-block-all "))
    );
    input.generation += 1;
    input.tunnel_interface = None;
    let next = policy::compile_boot(&policy::compile(&input));
    assert!(
        next.iter()
            .all(|f| f.name.starts_with("LoVPN g100 boot-block-all "))
    );
    assert!(
        next.iter()
            .all(|f| !boot.iter().any(|old| old.name == f.name))
    );
    input.kill_switch = false;
    assert!(policy::compile_boot(&policy::compile(&input)).is_empty());
}
