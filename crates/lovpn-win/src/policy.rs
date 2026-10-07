//! Pure compilation of the Windows firewall policy: which WFP filters must exist for a
//! given connection state. No I/O, so the invariants are unit-tested on every platform;
//! `wfp` merely installs and verifies exactly what this module returns.
//!
//! Evaluation model: all filters live in one LoVPN sublayer. Within it, higher weight is
//! evaluated first and the first terminating action wins. Permits are weighted above the
//! targeted blocks, which are weighted above the catch-all block, so "block everything
//! except X" fails closed: anything not listed is blocked.
use std::net::{Ipv4Addr, SocketAddrV4};

pub const WEIGHT_PERMIT: u8 = 15;
pub const WEIGHT_TARGETED_BLOCK: u8 = 12;
pub const WEIGHT_BLOCK_ALL: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Layer {
    ConnectV4,
    ConnectV6,
    RecvV4,
    RecvV6,
    BootInboundV4,
    BootInboundV6,
    BootOutboundV4,
    BootOutboundV6,
}

pub const LAYERS: [Layer; 4] = [
    Layer::ConnectV4,
    Layer::ConnectV6,
    Layer::RecvV4,
    Layer::RecvV6,
];

pub const BOOT_LAYERS: [Layer; 4] = [
    Layer::BootInboundV4,
    Layer::BootInboundV6,
    Layer::BootOutboundV4,
    Layer::BootOutboundV6,
];

impl Layer {
    pub const fn is_v6(self) -> bool {
        matches!(
            self,
            Self::ConnectV6 | Self::RecvV6 | Self::BootInboundV6 | Self::BootOutboundV6
        )
    }
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ConnectV4 => "c4",
            Self::ConnectV6 => "c6",
            Self::RecvV4 => "r4",
            Self::RecvV6 => "r6",
            Self::BootInboundV4 => "bi4",
            Self::BootInboundV6 => "bi6",
            Self::BootOutboundV4 => "bo4",
            Self::BootOutboundV6 => "bo6",
        }
    }
}

/// Boot-time IP packet layers cannot express ALE application/tunnel exceptions safely.
/// When the runtime policy arms a catch-all, deny every IP packet before BFE starts.
/// BFE then replaces these boot-time filters with the persistent ALE policy. Boot filters
/// use BOOTTIME alone (Windows forbids combining it with PERSISTENT).
pub fn compile_boot(runtime: &[FilterSpec]) -> Vec<FilterSpec> {
    let Some(block) = runtime.iter().find(|f| {
        f.layer == Layer::ConnectV4
            && f.action == Action::Block
            && f.conditions.is_empty()
            && f.name.contains(" block-all ")
    }) else {
        return Vec::new();
    };
    let prefix = block.name.split(" block-all ").next().unwrap_or("LoVPN");
    BOOT_LAYERS
        .into_iter()
        .map(|layer| FilterSpec {
            name: format!("{prefix} boot-block-all {}", layer.tag()),
            layer,
            action: Action::Block,
            weight: WEIGHT_BLOCK_ALL,
            conditions: Vec::new(),
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Permit,
    Block,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Condition {
    Loopback,
    /// Traffic leaving or arriving on the tunnel adapter.
    Interface(u64),
    RemoteAddress(Ipv4Addr),
    RemotePort(u16),
    LocalPort(u16),
    /// IP protocol number (6 TCP, 17 UDP).
    Protocol(u8),
    /// Only the LoVPN service executable (WireGuardNT's sockets belong to it).
    Application(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilterSpec {
    /// Unique, stable and generation-stamped; installed filters are matched by this name.
    pub name: String,
    pub layer: Layer,
    pub action: Action,
    pub weight: u8,
    pub conditions: Vec<Condition>,
}

#[derive(Clone, Debug)]
pub struct PolicyInput {
    pub generation: u64,
    /// `None` until the adapter exists. The kill switch is installed *before* it.
    pub tunnel_interface: Option<u64>,
    pub endpoint: SocketAddrV4,
    /// Absolute path of `lovpn-clientd.exe`.
    pub service_path: String,
    /// Catch-all block: nothing leaves except what is explicitly permitted.
    pub kill_switch: bool,
    /// Keep DNS from reaching any resolver except through the tunnel.
    pub dns_guard: bool,
    /// Block all IPv6 (the M3 tunnel carries IPv4 only).
    pub block_ipv6: bool,
}

fn spec(
    input: &PolicyInput,
    role: &str,
    layer: Layer,
    action: Action,
    weight: u8,
    conditions: Vec<Condition>,
) -> FilterSpec {
    FilterSpec {
        name: format!("LoVPN g{} {role} {}", input.generation, layer.tag()),
        layer,
        action,
        weight,
        conditions,
    }
}

pub fn compile(input: &PolicyInput) -> Vec<FilterSpec> {
    let mut out = Vec::new();
    for layer in LAYERS {
        let v6 = layer.is_v6();
        let connect = matches!(layer, Layer::ConnectV4 | Layer::ConnectV6);
        // Loopback is always allowed: local services and the resolver stub keep working.
        out.push(spec(
            input,
            "permit-loopback",
            layer,
            Action::Permit,
            WEIGHT_PERMIT,
            vec![Condition::Loopback],
        ));
        if !v6 {
            if let Some(tunnel) = input.tunnel_interface {
                out.push(spec(
                    input,
                    "permit-tunnel",
                    layer,
                    Action::Permit,
                    WEIGHT_PERMIT,
                    vec![Condition::Interface(tunnel)],
                ));
            }
            // The encrypted WireGuard transport to the server, from the service only.
            let mut conditions = vec![
                Condition::Protocol(17),
                Condition::RemoteAddress(*input.endpoint.ip()),
                Condition::RemotePort(input.endpoint.port()),
            ];
            if connect {
                conditions.push(Condition::Application(input.service_path.clone()));
            }
            out.push(spec(
                input,
                "permit-endpoint",
                layer,
                Action::Permit,
                WEIGHT_PERMIT,
                conditions,
            ));
            // DHCP keeps the physical link's lease alive (client port 68, server port 67).
            out.push(spec(
                input,
                "permit-dhcp",
                layer,
                Action::Permit,
                WEIGHT_PERMIT,
                vec![
                    Condition::Protocol(17),
                    Condition::LocalPort(68),
                    Condition::RemotePort(67),
                ],
            ));
        }
        if input.dns_guard && !v6 {
            for protocol in [17u8, 6] {
                out.push(spec(
                    input,
                    if protocol == 17 {
                        "block-dns-udp"
                    } else {
                        "block-dns-tcp"
                    },
                    layer,
                    Action::Block,
                    WEIGHT_TARGETED_BLOCK,
                    vec![Condition::Protocol(protocol), Condition::RemotePort(53)],
                ));
            }
        }
        if input.block_ipv6 && v6 {
            out.push(spec(
                input,
                "block-ipv6",
                layer,
                Action::Block,
                WEIGHT_TARGETED_BLOCK,
                vec![],
            ));
        }
        if input.kill_switch {
            out.push(spec(
                input,
                "block-all",
                layer,
                Action::Block,
                WEIGHT_BLOCK_ALL,
                vec![],
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> PolicyInput {
        PolicyInput {
            generation: 7,
            tunnel_interface: Some(42),
            endpoint: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 51820),
            service_path: r"C:\Program Files\LoVPN\lovpn-clientd.exe".into(),
            kill_switch: true,
            dns_guard: true,
            block_ipv6: true,
        }
    }

    fn find<'a>(set: &'a [FilterSpec], role: &str, layer: Layer) -> Vec<&'a FilterSpec> {
        set.iter()
            .filter(|f| f.layer == layer && f.name.contains(role))
            .collect()
    }

    #[test]
    fn kill_switch_blocks_every_layer_at_the_lowest_weight() {
        let set = compile(&input());
        for layer in LAYERS {
            let block = find(&set, "block-all", layer);
            assert_eq!(block.len(), 1, "{layer:?}");
            assert_eq!(block[0].action, Action::Block);
            assert!(block[0].conditions.is_empty());
            assert!(
                set.iter()
                    .filter(|f| f.layer == layer && f.action == Action::Permit)
                    .all(|f| f.weight > block[0].weight)
            );
        }
    }

    #[test]
    fn without_a_kill_switch_there_is_no_catch_all() {
        let mut i = input();
        i.kill_switch = false;
        assert!(compile(&i).iter().all(|f| !f.name.contains("block-all")));
        // The leak guards are independent of the kill switch.
        assert!(compile(&i).iter().any(|f| f.name.contains("block-dns")));
        assert!(compile(&i).iter().any(|f| f.name.contains("block-ipv6")));
    }

    #[test]
    fn ipv6_is_only_ever_permitted_on_loopback() {
        let set = compile(&input());
        for f in set.iter().filter(|f| f.layer.is_v6()) {
            if f.action == Action::Permit {
                assert_eq!(f.conditions, vec![Condition::Loopback], "{}", f.name);
            }
        }
        for layer in [Layer::ConnectV6, Layer::RecvV6] {
            assert_eq!(find(&set, "block-ipv6", layer).len(), 1);
        }
    }

    #[test]
    fn dns_is_blocked_below_the_tunnel_permit_and_above_the_catch_all() {
        let set = compile(&input());
        let dns = find(&set, "block-dns-udp", Layer::ConnectV4)[0];
        let tunnel = find(&set, "permit-tunnel", Layer::ConnectV4)[0];
        let all = find(&set, "block-all", Layer::ConnectV4)[0];
        assert!(tunnel.weight > dns.weight && dns.weight > all.weight);
        assert_eq!(tunnel.conditions, vec![Condition::Interface(42)]);
    }

    #[test]
    fn before_the_adapter_exists_the_policy_still_fails_closed() {
        let mut i = input();
        i.tunnel_interface = None;
        let set = compile(&i);
        assert!(set.iter().all(|f| !f.name.contains("permit-tunnel")));
        assert_eq!(find(&set, "block-all", Layer::ConnectV4).len(), 1);
        // Only the server transport is permitted to reach the network.
        let endpoint = find(&set, "permit-endpoint", Layer::ConnectV4)[0];
        assert!(
            endpoint
                .conditions
                .contains(&Condition::RemoteAddress(Ipv4Addr::new(203, 0, 113, 9)))
        );
        assert!(endpoint.conditions.contains(&Condition::Protocol(17)));
    }

    #[test]
    fn names_are_unique_and_carry_the_generation() {
        let set = compile(&input());
        let mut names: Vec<_> = set.iter().map(|f| f.name.clone()).collect();
        assert!(names.iter().all(|n| n.starts_with("LoVPN g7 ")));
        names.sort();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len());
    }

    #[test]
    fn endpoint_transport_is_bound_to_the_service_application() {
        let set = compile(&input());
        let c = find(&set, "permit-endpoint", Layer::ConnectV4)[0];
        assert!(
            c.conditions.iter().any(
                |x| matches!(x, Condition::Application(p) if p.ends_with("lovpn-clientd.exe"))
            )
        );
    }

    #[test]
    fn boot_protection_has_no_stale_tunnel_or_application_exceptions() {
        let boot = compile_boot(&compile(&input()));
        assert_eq!(boot.len(), BOOT_LAYERS.len());
        for layer in BOOT_LAYERS {
            let Some(f) = boot.iter().find(|f| f.layer == layer) else {
                panic!("missing boot layer {layer:?}");
            };
            assert_eq!(f.action, Action::Block);
            assert!(f.conditions.is_empty());
            assert!(f.name.starts_with("LoVPN g7 boot-block-all "));
        }
        let mut unarmed = input();
        unarmed.kill_switch = false;
        assert!(compile_boot(&compile(&unarmed)).is_empty());
    }
}
