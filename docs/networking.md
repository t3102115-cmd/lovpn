# Networking and fail-closed policy

All live integration in this document is a design requirement unless explicitly
listed as tested. The first compiler is a laboratory-only policy generator.

## Topology

Windows/Linux client → WireGuard UDP → user-operated Linux server → private LAN
and/or Internet. The encrypted outer endpoint must remain reachable independently
of the tunnel default route. There is no required LoVPN-operated network service.

WireGuard's usual UDP port is 51820, configurable. Offline enrollment opens no
additional port. Future online enrollment binds only when explicitly enabled;
its TCP port and TLS identity must appear in setup's reviewed plan. No UPnP/NAT-PMP
port opening or LAN discovery occurs silently.

## Routing

Full tunnel requires IPv4 default routing and either an IPv6 tunnel default or
explicit IPv6 block. Assign tunnel addresses independently of route networks;
never reinterpret an interface address as a network. Route-mode split tunneling
must explicitly identify protected destinations and their DNS coverage. It does
not mean all traffic is private. LAN bypass is an enumerated exception, off by
default, with overlap/conflict checks against VPN and endpoint routes.

Planned Linux routing uses an owned policy-routing table, WireGuard socket fwmark
and route rules to prevent endpoint recursion. Do not permit all UDP to any
destination or all existing conntrack flows. Endpoint mobility needs an atomic
old/new allowlist transaction coordinated with WireGuard roaming; a new endpoint
is not adopted from arbitrary DNS responses without policy validation.

Literal endpoint addresses are required initially. This avoids bootstrap DNS
queries outside protection. Future hostname support requires a disclosed resolver,
pinned identity, TTL/change policy and separate, tightly scoped bootstrap rules.

## Linux firewall compiler contract

Own only `table inet lovpn_client`. Generate a complete atomic nft transaction:
`add table` followed by `flush table` and fully rebuilt chains in that table. Never
use `flush ruleset`; never remove another application's table. A failed nft batch
must leave the previous table unchanged. An apply backend must first verify table
ownership and serialize generations; the offline compiler cannot establish this.

Full-tunnel VPN-only/Strict policy uses a drop-policy output chain and a drop-policy
forward chain. Permit loopback; permit only the exact endpoint's UDP port with a
reserved WireGuard fwmark; permit permitted IP families through the tunnel device.
When IPv6 is blocked, the family drop precedes tunnel-device acceptance. Never use
unconditional `ct state established,related accept`: that would allow pre-existing
connections to escape. Default-drop forwarding prevents unhandled container traffic
from becoming an accidental bypass, but container compatibility is not implemented.

The reserved mark is not a cryptographic boundary: privileged processes can set
marks. The compiler must reject resolver endpoints that collide with the WireGuard
endpoint/port, and no globally allowed DNS UDP exception may exist. Local processes
with administrative capabilities are outside this enforcement boundary.

Initial rules intentionally have **no DHCP, IPv6 NDP, RA or LAN allowances**. Static
IPv4 lab tests are possible; production roaming and IPv6 outer endpoints are not
ready. Reject an IPv6 outer endpoint in the initial compiler rather than pretending
IPv6 underlay works. IPv6 payload through an IPv4 WireGuard endpoint is a separate
case. Later underlay exceptions must be constrained by interface, hop limit,
ICMPv6 type and scope and tested against hostile routers.

Kill-switch modes refer to lifecycle behavior, not just rule text:

- **Off:** no protection claimed; future explicit restoration removes owned rules.
- **VPN-only:** protect connecting/reconnecting/connected states; release only after
  an intentional, authenticated disconnect. A crash is not a disconnect.
- **Strict:** protection remains on deliberate disconnect, shutdown and service
  failure until the user explicitly disables it. Boot-time coverage is required.

The compiler can represent Off/IPv6 policy in configuration but refuses to produce
an enforceable protection plan for Off or split routing. It cannot implement either
mode's lifecycle persistence. CLI output must say generated, not applied/protected.

## DNS and IPv6

Require explicit unicast resolver IPs. DNS is routed through the tunnel; full IPv4
default and, when used, full IPv6 default cover resolvers. Split routes must cover
every configured resolver. Reject IPv6 DNS with IPv6 blocked, ambiguous local
loopback stubs, scoped link-local DNS without an interface model, and empty lists.

Planned Linux adapters configure systemd-resolved per-link DNS and the `~.` routing
domain or coordinate with NetworkManager. Neither alone proves absence of fallback:
firewall enforcement and actual multi-adapter queries are required. Windows needs
NRPT/interface policy plus WFP, with multi-homed resolver behavior tested. Preserve
and restore prior resolver state transactionally. Unsupported resolver configurations
fail closed rather than editing `/etc/resolv.conf` blindly.

Applications can use DoH/DoT or their own DNS stack. Full-tunnel routing confines
that traffic to the VPN, but cannot promise it uses the selected resolver. Split
DNS needs explicit per-domain policy and an OS support matrix. No captive-portal
exception is automatic; a temporary bypass must be visible, time-bounded and opt-in.

## Server gateway design

Allocate non-overlapping per-peer /32 IPv4 and /128 IPv6 AllowedIPs; reject address
spoofing and unauthorized client-to-client forwarding. LAN gateway mode routes only
approved destinations. Routed mode requires return routes on the LAN/router. Internet
gateway mode enables forwarding deliberately, adds scoped nft forwarding and IPv4
masquerade on the selected egress, and explains the public exit IP. Prefer routed
IPv6 prefixes; do not silently add NAT66. A server without IPv6 egress must not
advertise IPv6 full-tunnel capability. Record/restore owned sysctl changes safely.

## Recovery

Future `firewall status/show/validate` inspect actual owned state; `repair` reconciles
while blocked. `reset` requires an explicit warning that traffic may leave outside
the VPN, and removes only verified LoVPN-owned resources. A local-console recovery
path and firewall ownership journal must exist before privileged installation is
shipped. This milestone never installs host rules; isolated test namespaces vanish
on exit. Do not manually apply generated lab policies to a remote machine.
