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

## M2 — identities, server and enrollment (M2a, M2b, M2c done)

Split into slices. **M2a (done, see [server.md](server.md))**: `KEY-01` key types and
protected key files (Unix); `SRV-01` state/peers/pool/atomic generations/export and a
pure server nft compiler with namespace verification; `ENR-01` offline enrollment only.
**M2b (done, see [server.md](server.md))**: privileged broker and applier (WireGuard
interface, nft tables, forwarding), sanitized structured logging, systemd unit,
install/uninstall script, anti-rollback record, apply-time revocation enforcement, and
the two-peer traffic / revoked-peer-loses-access gate test with real WireGuard. Still
open from the M2 scope: running the unit as a real service on a host, server key
rotation, health metrics, LAN-gateway/non-NAT/split modes, IPv6 tunneling.
**M2c (done, see [enrollment.md](enrollment.md))**: online enrollment: pinned TLS 1.3,
hashed one-time tokens, atomic single-use redemption with idempotent lost-response retry,
clock-regression refusal, persistent pre-TLS rate limits, unprivileged listener and unit,
`lovpn enroll`, and a namespace gate with a real WireGuard handshake. Still open: running
the enrollment unit under real systemd, TLS identity rotation, QR/URI encodings, Windows
execution of `lovpn enroll --identity`. Windows key storage (DPAPI/ACL) remains open. The bullets below are the full milestone scope.

- `KEY-01`: mature WireGuard key generation, Linux protected files/credential
  loading, Windows DPAPI/ACL integration, zeroizing secret types and key rotation.
- `SRV-01`: Linux server broker, peers/address pools, atomic generation changes,
  revoke/rotate/list/export, health, restricted systemd units and dry-run setup.
- `ENR-01`: offline public-key exchange first; pinned TLS one-time enrollment with
  OS-random tokens, hashed token storage, expiry, revocation, rate limits, atomic
  single-use consumption and crash-safe replay tests. Never export a client key.
- Gate: two isolated peers exchange traffic; revoked peer loses access; enrollment
  replay/expiry/race tests; secret persistence and privilege review complete.

## M3 — usable Linux client and server (implementation slice)

- `LIN-01` **implemented for the Linux slice**: the root `lovpn-clientd` uses fixed
  `ip`/`wg`/`nft`/`resolvectl` operations, policy routes/rules, endpoint fwmark,
  caller-authenticated IPC and a hardened unit. It refuses foreign resources and
  arbitrary command execution. Verified as a real systemd service (installed by the real
  installer, capability set checked, SIGKILL recovery) on a Fedora 44 VM with enforcing
  SELinux; other distributions are untested.
- `LIN-02` **partially implemented**: persistent full IPv4/strict or VPN-only policy,
  interface-loss/restart recovery and a resume-detection nudge exist. DHCP is only
  an IPv4 firewall allowance. In the Fedora VM gate a real reboot, a real ACPI S3
  suspend/resume, a NetworkManager restart with DHCP re-acquisition, a server outage and a
  daemon SIGKILL all kept the machine Protected or Blocked with no IPv4 frame leaving the
  physical NIC (captured outside the guest). NDP/RA, NetworkManager *managing* the tunnel
  link, several uplinks and real hardware remain open.
- `DNS-01` **partially implemented**: systemd-resolved per-link `~.` settings,
  observation, revert and an explicit unmanaged/degraded mode exist. Real systemd-resolved
  (Fedora 44) holds the `~.` link settings, answers only from the tunnel resolver and kept
  them across a resolved restart. Multi-adapter, transactional host restoration, a lost
  setting being repaired on a real host and IPv6 DNS are not evidenced; IPv6 tunnel mode is
  unsupported.
- `RT-01`: server forwarding, NAT/non-NAT and LAN routing without host-wide flushes;
  per-peer anti-spoofing and forward rules; no uncontrolled client-to-client access.
- `REC-01` **partially implemented**: Linux client status/repair/reset and the
  staging-tested uninstall operate on verified owned resources, with explicit
  kill-switch release and restart recovery; real installers, uninstall (state and keys kept)
  and `teardown` were run on the VMs, and a rebooted server restores itself from persisted
  state (`--apply-on-start`). Stale journals and interrupted upgrades remain open. Route cleanup refuses to flush a
  policy table containing an unrecognized route.
- Gate: leak suite during crash, reconnect, interface switch, DNS fallback, route
  conflict, reboot and recovery. Test Debian/Ubuntu and Fedora separately. **Fedora 44 is
  done** in `tests/linux-vm` (real systemd, SELinux enforcing, resolved, NetworkManager,
  reboot, suspend, crash, outage; 102 checks). The gate stays open for Debian/Ubuntu, real
  NIC hardware (Wi-Fi/Ethernet switching, several uplinks), rogue DHCP/RA, IPv6 and route
  conflicts with other VPNs.

## M4 — Windows client (v1 blocker) — implementation extended, gates open

Done and verified in one Windows 11 VM ([windows.md](windows.md)): `WIN-01` (pinned,
signature-checked WireGuardNT, service, ACL'd named pipe with token checks, DPAPI keys) and
the persistent-WFP, DNS-guard and IPv6-block parts of `WIN-02`; PowerShell installer for
`WIN-03`. Boot-time filters, additive NRPT split DNS and MSI sources now exist, and native
NRPT/isolated WFP tests passed. The latest VM end-to-end run failed 14 checks with no
WireGuard handshake; this is not a release pass. **Still open:** reboot/pre-BFE enforcement, power and network
change notifications proven on hardware, multi-interface and link-local enforcement,
upgrade/rollback, an MSI, and testing on more Windows builds. Original scope:

- `WIN-01`: documented WireGuardNT integration, signed driver distribution review,
  Windows service, authenticated named-pipe IPC and protected key storage.
- `WIN-02`: persistent/boot-time WFP rules, DNS/NRPT, route and power notifications,
  IPv6/link-local/multi-interface enforcement. App splitting is later work.
- `WIN-03`: installer/service lifecycle, upgrade/rollback/uninstall and recovery.
- Gate: run tests in the Windows VM on explicitly recorded Windows builds. A Rust
  cross-target check is not a Windows runtime, WFP or driver test.

## M5 — usability — first slice implemented

Done ([ui.md](ui.md)): a window with Home (the protection ring), Servers, Devices, Privacy,
Diagnostics, Settings, Logs and Advanced, an onboarding wizard, sanitized diagnostics and
light/dark themes, on both platforms. Added since: English/German localization, an axe
accessibility audit (0 violations), forced-colors support, 93 automated browser checks,
opt-in window notifications and a tray (`lovpn-tray`, Linux and Windows). **Still open:** an
NVDA/VoiceOver audit (Orca was run partly), server health probes (opt-in), favorites/tags, more
languages and a native-speaker review. Original scope:

- `UX-01`: accessible onboarding, connect/disconnect, profiles/favorites/tags,
  server health and opt-in probes, tray, notifications, privacy, diagnostics.
- `UX-02`: localization resources, dark/high contrast modes, keyboard/screen reader.
- `RT-02`: network split routing, explicit LAN bypass and split DNS per backend;
  strict full-tunnel defaults stay understandable. No fake security switches.
- Later: app-based splitting, auto-selection, trusted networks (SSID is not an
  authentication factor), decentralized directories and Lo Security integration.

## M6 — release hardening and packaging — implemented as far as code and this lab allow

Done: property tests (parsers, protocol, keys, state rules), packet-capture leak matrix,
privilege-review gate, reproducible builds on Linux and Windows, SBOM, signing/verification
scripts, provenance attestation workflow, performance measurements (see [release.md](release.md),
[performance.md](performance.md), [privilege-review.md](privilege-review.md)). **Open, needs people
or hardware:** REL-01 updater ([update-design.md](update-design.md), no implementation, needs
independent review), key custody, human privilege review, coverage-guided fuzzing (nightly),
performance on Windows/many peers/battery/real network. Original scope:

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
