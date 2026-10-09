# Current repository state

Audit date: 2026-10-07. This is an evidence-based snapshot of the checked-out
working tree. The working tree already contained substantial uncommitted M3 work
before this audit; it was preserved rather than reset or rewritten.

## Repository shape

The repository is a Cargo workspace with nine crates:

| Crate | Current responsibility | Privilege / platform |
| --- | --- | --- |
| `lovpn-config` | bounded schema-v1 public TOML parsing and semantic validation | pure, cross-platform |
| `lovpn-keys` | typed WireGuard-compatible keys, zeroizing secret handling, Unix key files | pure key logic; protected file module on Unix |
| `lovpn-sys` | fixed-tool execution, Linux observations and Unix IPC helpers | Unix implementation |
| `lovpn-firewall` | deterministic client and server nftables policy compilers | pure compiler |
| `lovpn-server` | server identity/state, peer leases, offline enrollment, Linux broker/applier and CLI | Linux broker is privileged |
| `lovpn-client` | Linux client engine, broker, profiles, routing, kill switch and DNS adapter | Linux broker is privileged |
| `lovpn-cli` | client commands as a library plus the `lovpn` binary; offline validation and service client | unprivileged; Linux socket and Windows named pipe |
| `lovpn-win` | Windows platform layer: WireGuardNT loader, IP Helper, WFP policy compiler/applier, DPAPI/ACL storage, named pipe, engine, `lovpn-service` | the only crate allowed `unsafe`; service runs as LocalSystem |
| `lovpn-ui` | the window: loopback web app over the CLI library | unprivileged, no secrets |

The repository also contains Linux packaging, staged installer smoke tests,
disposable namespace tests, CI for Linux and Windows Rust checks, and design and
security documentation. There is a Windows client service and a window
([windows.md](windows.md), [ui.md](ui.md)). Online enrollment (pinned TLS, one-time tokens) is implemented for the Linux server and
the CLI ([enrollment.md](enrollment.md)). There is a tray (`lovpn-tray`, Linux and Windows), no updater, and no cloud
dependency.

## Implemented and working in this tree

### Configuration and keys

- Public profile schema v1 is bounded at 64 KiB, rejects unknown fields and
  versions, and validates endpoint, interface, address, route, DNS, MTU and IPv6
  consistency.
- Split routing, IPv6 tunnel mode and IPv6 endpoints are represented in the
  schema but rejected by the M3 Linux client before mutation.
- WireGuard key generation uses OS randomness and `x25519-dalek`; LoVPN does not
  define a replacement cryptographic protocol.
- Private keys use role-typed, redacting types and best-effort zeroization.
  Unix key files are exclusive, no-follow, owner-checked and mode 0600.

### Linux server

- `lovpn-server setup` performs dry-run planning or writes a validated server
  identity/state directory without changing networking.
- Peer create/list/export/revoke/rotate, IPv4 address allocation, generation
  checks, atomic locked persistence, key/address quarantine and offline
  public-key enrollment exist.
- The root server broker authenticates Unix-socket callers with kernel peer
  credentials, authorizes operations, reads validated state, applies fixed
  `ip`/`wg`/`nft` operations, enables/restores IPv4 forwarding, and records an
  anti-rollback generation.
- Server policy is scoped to LoVPN-named nftables tables and refuses foreign
  interfaces/tables. Real WireGuard, forwarding/NAT, revocation and peer
  isolation are exercised in disposable namespaces.

### Linux client

- `lovpn-clientd` is a root broker; `lovpn` remains unprivileged and uses a
  caller-authenticated Unix socket.
- Profile import keeps the client private key in the broker-owned root state
  directory and verifies the expected server public key.
- The implemented connection slice is literal IPv4 endpoint, full IPv4 tunnel,
  IPv6 blocking, policy routing with a WireGuard fwmark, owned nftables kill
  switch, optional systemd-resolved per-link DNS, handshake/status observation,
  reconnect, monitor repair and restart recovery.
- Disconnect behavior differs deliberately: VPN-only releases on explicit
  disconnect; strict remains blocked until explicit release. Missing or
  contradictory observations never become `Protected`.
- The client route cleanup now inspects the reserved policy table and removes
  only the exact LoVPN default route on the recorded owned interface. It refuses
  to mutate a table containing another route instead of flushing the table.
- Session records are read with no-follow and regular-file/owner/link/mode/size
  checks. Disconnect cleanup restores a connected desired state if cleanup fails,
  allowing the monitor to repair rather than silently treating a partial cleanup
  as intentional.

## Partially implemented

- Linux client service units and installers pass static/staging checks and were operated
  as real services on Fedora 44 VMs; other distributions and physical hosts are untested.
- systemd-resolved integration is implemented behind an explicit backend and was exercised
  against real systemd-resolved, a NetworkManager restart and DHCP renewal on Fedora 44; real
  fallback behavior, multi-adapter behavior, NetworkManager *managing* the tunnel link and
  transactional restoration are not evidenced.
- M3 has only full-tunnel IPv4 with IPv6 blocked. LAN bypass, split routing,
  non-NAT/LAN gateway mode, IPv6 tunnel/underlay support and NDP/RA handling are
  intentionally unavailable.
- The server supports an Internet-gateway/NAT slice only. Host firewall UDP
  allowance, DNS service operation and LAN return routes remain operator work.
- Recovery is tested in disposable namespaces and through fake-host tests; real
  boot ordering, reboot persistence, suspend/resume, Wi-Fi/Ethernet changes and
  existing firewall/VPN coexistence remain open.
- The Windows client (WireGuardNT, WFP, service, named-pipe authorization, DPAPI) is
  implemented and verified in one Windows 11 VM only; sleep/resume, real network
  changes and reboot persistence are not evidenced ([windows.md](windows.md)).

## Missing

- NVDA/JAWS/VoiceOver audit of the window (axe and a partial Orca run are done); proof of the Windows tray menu.
- Online enrollment: QR/URI encoding and a rotation overlap period (the rest is implemented
  and was run on real systemd units and in the Windows VM).
- Server key rotation and optional PSK lifecycle.
- Windows MSI/installer packaging beyond the PowerShell script.
- Signed update verification, rollback-safe updater and release provenance.
- Real-host platform leak matrix, fuzzing/property expansion, performance data,
  SBOM and an independent security review.

## Security concerns and technical debt

1. **No production security claim is justified.** Namespace evidence is not real
   host, boot, suspend, resolver or coexistence evidence.
2. The Linux brokers are powerful networking authorities even with bounded systemd
   capabilities. A compromised broker, root account or kernel is outside the
   protection boundary.
3. The client kill switch is intentionally scoped to the owned namespace and
   tested policy. Earlier host firewall verdicts, alternate namespaces, custom
   application DNS, containers and unsupported adapters need separate treatment.
4. The fixed policy-routing table and nft ownership markers are local resource
   conventions, not a kernel cryptographic ownership mechanism. Conflicts are
   refused; they must not be silently repaired.
5. Private-key zeroization is best effort; moved values and process/core dumps
   remain residual risks.
6. The server state owner is trusted to administer peers and can create a newer
   valid state. The root broker's anti-rollback record only protects applied
   generations while its own directory survives.
7. Existing documentation had one stale protocol statement saying the local
   daemon was only planned; it must remain aligned with the implemented M3
   client/server brokers.

## Checks observed for this audit

Passed in this session:

- `cargo fmt --check` before the focused changes;
- `cargo test --locked --workspace` before the focused changes;
- `cargo clippy --locked --workspace --all-targets -- -D warnings` before the
  focused changes;
- `python3 scripts/check-docs.py`;
- `./scripts/test-install.sh`;
- full post-change workspace fmt, clippy and test checks using a clean target
  directory on `/tmp` because the repository filesystem caused a known Rust 1.97
  incremental compiler ICE;
- the staged installer smoke test and the complete disposable Linux networking
  suites after the route/record changes.

Exact commands and the harness corrections are recorded in
[development.md](development.md). The real-host Linux evidence (Fedora 44 VMs: real systemd,
resolved, NetworkManager, reboot, suspend, leaks captured outside the guest) is the
"Real-host gate" section there; it is one distribution on virtual NICs.

## Source-of-truth documents

- [architecture.md](architecture.md): accepted component and privilege design.
- [networking.md](networking.md): routing, firewall, DNS and recovery boundaries.
- [threat-model.md](threat-model.md): assets, adversaries, goals and residual risk.
- [security-model.md](security-model.md): key, storage, IPC and update controls.
- [feature-matrix.md](feature-matrix.md): implementation versus backlog matrix.
- [roadmap.md](roadmap.md): milestone gates based on this state.
