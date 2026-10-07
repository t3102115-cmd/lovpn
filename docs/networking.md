# Networking and fail-closed policy

The M3 Linux client now applies and observes an owned full-tunnel policy through
`lovpn-clientd`; server and client live behavior is still only evidenced in
disposable namespaces and, for service behavior, on two Fedora 44 virtual machines
(`tests/linux-vm`: real systemd, resolved, NetworkManager, reboot, suspend). That is
evidence for those paths, not a support claim for other distributions or hardware.

## Topology

Windows/Linux client → WireGuard UDP → user-operated Linux server → private LAN
and/or Internet. The encrypted outer endpoint must remain reachable independently
of the tunnel default route. There is no required LoVPN-operated network service.

WireGuard's usual UDP port is 51820, configurable. Offline enrollment opens no
additional port. Online enrollment binds only when the administrator runs
`lovpn-server enroll serve --listen ADDR` (or configures the unit); LoVPN never opens the
firewall for it, so the administrator opens that TCP port deliberately. Its TLS identity is
created only by the explicit `enroll tls-init`. No UPnP/NAT-PMP
port opening or LAN discovery occurs silently.

## Routing

Full tunnel requires IPv4 default routing and either an IPv6 tunnel default or
explicit IPv6 block. Assign tunnel addresses independently of route networks;
never reinterpret an interface address as a network. Route-mode split tunneling
must explicitly identify protected destinations and their DNS coverage. It does
not mean all traffic is private. LAN bypass is an enumerated exception, off by
default, with overlap/conflict checks against VPN and endpoint routes.

The M3 Linux client uses an owned policy-routing table, WireGuard socket fwmark
and route rules to prevent endpoint recursion. Do not permit all UDP to any
destination or all existing conntrack flows. Endpoint mobility needs an atomic
old/new allowlist transaction coordinated with WireGuard roaming; a new endpoint
is not adopted from arbitrary DNS responses without policy validation.

The policy table has a fixed LoVPN convention, not a kernel ownership primitive.
Cleanup inspects its routes first and removes only the recorded LoVPN default route
on the broker-created interface. If any other route is present, cleanup refuses to
flush the table and keeps the session in a repairable desired state.

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

M3 rules intentionally allow only the IPv4 DHCP client renewal flow (UDP source
port 68 to destination port 67) in addition to loopback, the marked IPv4 endpoint
and the tunnel. This is an nft exception, not a DHCP client or lease manager. There
are **no IPv6 NDP/RA, IPv6 DHCP or LAN allowances**. Static IPv4 lab tests are
possible; IPv6 outer endpoints, IPv6 tunnel payload, production roaming and LAN
bypass are not ready. Reject an IPv6 outer endpoint rather than pretending IPv6
underlay works. Later underlay exceptions must be constrained by interface, hop
limit, ICMPv6 type and scope and tested against hostile routers.

Kill-switch modes refer to lifecycle behavior, not just rule text:

- **Off:** no protection claimed; future explicit restoration removes owned rules.
- **VPN-only:** protect connecting/reconnecting/connected states; release only after
  an intentional, authenticated disconnect. A crash is not a disconnect.
- **Strict:** protection remains on deliberate disconnect, shutdown and service
  failure until the user explicitly disables it. Boot-time coverage is required.

The offline compiler still only previews policy. The Linux client broker can install
owned full-tunnel VPN-only/Strict policy and persist its desired state, but refuses
Off-as-protection, split routing, IPv6 tunnel mode and IPv6 endpoints. CLI preview
output is not proof of host protection; client `status` is based on observations.

## DNS and IPv6

Require explicit unicast resolver IPs. DNS is routed through the tunnel; full IPv4
default and, when used, full IPv6 default cover resolvers. Split routes must cover
every configured resolver. Reject IPv6 DNS with IPv6 blocked, ambiguous local
loopback stubs, scoped link-local DNS without an interface model, and empty lists.

The M3 Linux adapter configures systemd-resolved per-link DNS and the `~.` routing
domain when `/etc/resolv.conf` is resolved-managed. It never rewrites
`/etc/resolv.conf`. This does not prove absence of fallback: firewall enforcement
and actual multi-adapter queries are required, and real resolved behavior is not
yet exercised. `--dns-backend unmanaged` deliberately leaves DNS unchanged and
reports it as unprotected/degraded. NetworkManager coordination is not implemented.
Windows needs
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

Client `status`/`diagnostics` inspect actual owned interface, rules, routes, firewall,
handshake and resolver observations; `repair` reconciles while blocked. `reset`
removes only verified LoVPN-owned resources and explicitly restores normal networking.
The durable client record re-arms strict protection after broker restart, and the
monitor attempts repair after interface loss or a detected resume. The owner or root
can explicitly release the kill switch. Real suspend/resume, reboot ordering and a
systemd-run service have not been exercised. The offline compiler still never
installs host rules; do not apply its preview to a remote machine.
