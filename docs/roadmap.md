# Roadmap and release gates

No dates or production support are promised. An unchecked gate is unavailable,
not a hidden toggle. IDs below are the local issue backlog until a tracker exists.

## M0 — architecture

- Record environment and missing dependencies; distinguish observed from planned.
- Define data/control planes, trust boundaries, storage, networking and recovery.
- Compare GUI stacks before adoption; define license and supply-chain policy.
- Deliver architecture, threat model, security model, networking, development and
  this roadmap. Revisit them at each security checkpoint.

## M1 — offline security foundation (done)

- `CFG-01`: strict schema-v1 public profile parsing; unknown fields/versions,
  dangerous routes, invalid DNS/IPv6 policy and resource exhaustion rejected.
- `FW-01`: deterministic Linux full-tunnel nft policy compiler; exact, marked UDP
  endpoint exception; no generic established-connection bypass; scoped reset plan.
- `CLI-01`: usable offline config validation, firewall inspection, diagnostics and
  privacy output, including JSON and meaningful failure codes.
- `QA-01`: parser/policy regression tests; isolated real-kernel nft validation and
  IPv4/IPv6 packet enforcement tests, including an established pre-policy socket.
- Gate: actual evidence recorded; no claim of an installed kill switch or VPN.

M1 implementation evidence is recorded in [development.md](development.md). The
offline foundation satisfies the parser/compiler/CLI portions; the privileged
service, live VPN lifecycle and platform DNS integration remain later gates.

## M2 — identities, server and enrollment (M2a, M2b done; M2c open)

Split into slices. **M2a (done, see [server.md](server.md))**: `KEY-01` key types and
protected key files (Unix); `SRV-01` state/peers/pool/atomic generations/export and a
pure server nft compiler with namespace verification; `ENR-01` offline enrollment only.
**M2b (done, see [server.md](server.md))**: privileged broker and applier (WireGuard
interface, nft tables, forwarding), sanitized structured logging, systemd unit,
install/uninstall script, anti-rollback record, apply-time revocation enforcement, and
the two-peer traffic / revoked-peer-loses-access gate test with real WireGuard. Still
open from the M2 scope: running the unit as a real service on a host, server key
rotation, health metrics, LAN-gateway/non-NAT/split modes, IPv6 tunneling.
**M2c (not started)**:
online enrollment per [enrollment.md](enrollment.md). Windows key storage (DPAPI/ACL)
remains open. The bullets below are the full milestone scope.

- `KEY-01`: mature WireGuard key generation, Linux protected files/credential
  loading, Windows DPAPI/ACL integration, zeroizing secret types and key rotation.
- `SRV-01`: Linux server broker, peers/address pools, atomic generation changes,
  revoke/rotate/list/export, health, restricted systemd units and dry-run setup.
- `ENR-01`: offline public-key exchange first; pinned TLS one-time enrollment with
  OS-random tokens, hashed token storage, expiry, revocation, rate limits, atomic
  single-use consumption and crash-safe replay tests. Never export a client key.
- Gate: two isolated peers exchange traffic; revoked peer loses access; enrollment
  replay/expiry/race tests; secret persistence and privilege review complete.

## M3 — usable Linux client and server

- `LIN-01`: generic netlink WireGuard, rtnetlink routes/rules, endpoint fwmark,
  systemd service and caller-authenticated IPC. No arbitrary command execution.
- `LIN-02`: persistent full-tunnel/strict kill switch, DHCP/NDP bootstrapping,
  NetworkManager coordination, network-change and suspend/resume handling.
- `DNS-01`: systemd-resolved/NetworkManager adapters with transactional restoration,
  exclusive tunnel DNS and IPv6 blocking/tunneling. Unsupported resolver fails closed.
- `RT-01`: server forwarding, NAT/non-NAT and LAN routing without host-wide flushes;
  per-peer anti-spoofing and forward rules; no uncontrolled client-to-client access.
- `REC-01`: inspect/repair/reset/uninstall only owned resources; explicit consent
  before removing protection; stale journal and interrupted-upgrade recovery.
- Gate: leak suite during crash, reconnect, interface switch, DNS fallback, route
  conflict, reboot and recovery. Test Debian/Ubuntu and Fedora separately.

## M4 — Windows client (v1 blocker)

- `WIN-01`: documented WireGuardNT integration, signed driver distribution review,
  Windows service, authenticated named-pipe IPC and protected key storage.
- `WIN-02`: persistent/boot-time WFP rules, DNS/NRPT, route and power notifications,
  IPv6/link-local/multi-interface enforcement. App splitting is later work.
- `WIN-03`: installer/service lifecycle, upgrade/rollback/uninstall and recovery.
- Gate: run tests in the Windows VM on explicitly recorded Windows builds. A Rust
  cross-target check is not a Windows runtime, WFP or driver test.

## M5 — usability

- `UX-01`: accessible onboarding, connect/disconnect, profiles/favorites/tags,
  server health and opt-in probes, tray, notifications, privacy, diagnostics.
- `UX-02`: localization resources, dark/high contrast modes, keyboard/screen reader.
- `RT-02`: network split routing, explicit LAN bypass and split DNS per backend;
  strict full-tunnel defaults stay understandable. No fake security switches.
- Later: app-based splitting, auto-selection, trusted networks (SSID is not an
  authentication factor), decentralized directories and Lo Security integration.

## M6 — release hardening and packaging

- `REL-01`: independently reviewed update verification using TUF-style metadata,
  offline trust roots, threshold signing, expiry and anti-rollback state.
- `REL-02`: locked dependencies, audit/deny, SBOM, source/driver licenses, provenance,
  signing-key custody, reproducibility and signed manual/offline installations.
- `QA-02`: parser fuzzing, state-machine property tests, privilege review, adversarial
  enrollment/configuration tests, actual DNS/IPv6/routing leak and failure matrix.
- `PERF-01`: measure throughput, handshake/connect/reconnect times, CPU/RAM, battery
  and loss behavior in a documented setup; make no unmeasured performance claims.

## v1 definition of done

Both Linux-server → Linux-client and Linux-server → Windows-client flows must pass
enrollment, full-tunnel routing, DNS, IPv6, persistent kill switch, crash/reboot,
reconnect and clean recovery tests. Security review, beginner/admin/developer
documentation and reproducible installation are required. Compilation is not v1.
