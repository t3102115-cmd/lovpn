# Changelog

All notable changes to this pre-release project are recorded here. There is no
production release yet.

## Unreleased: online enrollment (M2c)

- Added `lovpn-enroll`: one-time token format (256-bit secret, SHA-256 digest at rest,
  constant-time compare), the 4 KiB strict request/response protocol and a TLS 1.3-only
  (`rustls` + ring, `rcgen`) transport that trusts exactly one pinned certificate.
- `lovpn-server enroll tls-init|pin|token create|list|revoke|serve`: tokens live in the
  state so redemption (peer creation + consumption) is one atomic commit; idempotent
  lost-response retry for the same key; uniform denial; clock-regression refusal;
  persistent pre-TLS per-source and global rate limits; the unprivileged listener refuses
  to run as root and asks the broker to apply (reporting `applied` honestly).
- `lovpn enroll`: token from a file or stdin (never argv), pin required, public key only,
  profile validated locally and imported; `lovpn privacy` now discloses it.
- `packaging/linux/lovpn-server-enroll.service` (no capabilities, disabled and
  unconfigured by default) and installer/uninstall support.
- Evidence: 22 + 3 server tests, CLI tests, and an `enrollment_gate` in
  `tests/networking/server_e2e.py` with real TLS and a real WireGuard handshake. Pin covers
  the whole certificate, not only the SPKI; no proof of possession by design; no QR/URI.
- `lovpn-server enroll tls-rotate --yes`: atomic single-file identity replacement; a running
  listener reloads it by itself (no overlap period, pending tokens unaffected).
- Real-host gate `tests/linux-vm/run.sh`: two Fedora 44 VMs with real systemd, enforcing
  SELinux, systemd-resolved, NetworkManager, reboot and ACPI suspend; leaks measured from
  outside the guest (102 checks). Found and fixed: `setup` now adopts the installer-created
  empty 0700 state directory; the server broker unit applies persisted state at start
  (`--apply-on-start`) so a rebooted server comes back; a rotation race in the listener.
- `lovpn enroll --identity` is a flag (the service-held key is named like `--name`); run
  in the Windows 11 VM.

## Earlier unreleased: Windows client and window

- Added the **Windows client** (`lovpn-win` crate and `lovpn-service`): WireGuardNT (pinned
  SHA-256 and signature), IP Helper routes/addresses/MTU/DNS, a persistent WFP kill
  switch with DNS guard and IPv6 block, DPAPI-sealed service-held keys in an ACL-protected
  directory, an ACL'd named pipe with token checks, service lifecycle with crash recovery
  and a monitor, and `scripts/install-client.ps1`. Verified in a Windows 11 VM
  (`tests/windows/vm-e2e.ps1`, 34 checks; `vm-recovery.ps1`, 13 checks), including the offline
  `lovpn-service release` recovery. See `docs/windows.md` for limits.
- Added the **window** (`lovpn-ui`) for Windows and Linux: loopback-only local web app with
  Home (protection ring), Servers, Devices, Privacy, Diagnostics, Settings, Logs, Advanced,
  onboarding and sanitized diagnostics. See `docs/ui.md`.
- CLI: `server add|list|remove|test`, `profile use`, `logs`, default-server marker; client
  commands now compile and work on Windows; `lovpn-cli` is also a library.
- Shared model/protocol/dispatch (`lovpn-client`) so Linux and Windows cannot disagree on
  states or requests; new `ClientEngine` trait; new `generate-identity`,
  `import-identity-profile` and `logs` operations (Windows-only; Linux answers
  `unsupported.platform`).
- Fixed: `lovpn-client` and the key tests did not build/test on Windows; `--socket` had an
  empty default on Windows that broke every command.
- Linux: `lovpn-ui` and a desktop entry are installed by `install-client.sh`.

## Unreleased — M3: Linux client implementation slice

- Added the Linux `lovpn-clientd` root broker and unprivileged `lovpn` lifecycle:
  full IPv4 routing, endpoint exception, owned nftables kill switch, reconnect,
  strict/vpn-only recovery and optional systemd-resolved per-link DNS.
- Added a hardened `lovpn-clientd.service` and dry-run/staging-tested
  `scripts/install-client.sh`; uninstall retains all client profiles, keys and
  session state and never performs network cleanup.
- Added client and troubleshooting documentation with explicit privilege, DNS,
  DHCP, IPv6, split/LAN, lifecycle and evidence limits.
- Not claimed: a real systemd service, real resolved behavior, DHCP or
  NetworkManager integration, reboot/suspend host testing, IPv6 endpoints/tunnel,
  split routing, LAN bypass, Windows or production leak protection.

## Unreleased — M2b: privileged broker and server apply

- Added the Linux server broker (`lovpn-server broker`): 0600 Unix socket, kernel peer
  credentials, per-operation authorization, bounded strict requests, structured logs.
- Added the applier: WireGuard interface and peers (atomic `wg syncconf`), forwarding,
  LoVPN-owned nftables tables stamped with the state generation, ownership checks,
  rollback of partial applies, drift observation, firewall repair and scoped teardown.
- Added anti-rollback protection for applied state, `apply`, `status --live`,
  `teardown`, and `--apply` on peer create/revoke/rotate (revocation now takes effect
  on the live interface).
- Added a hardened systemd unit, sysusers/tmpfiles files and `scripts/install-server.sh`
  (dry-run by default, staging-tested).
- Added a real-WireGuard server gate test and an installer smoke test.
- Not included in M2b: running the unit as a real service, Windows, GUI, online
  enrollment and server key rotation. The Linux client lifecycle is described in M3.

## M2a: keys, server state, offline enrollment

- Added `lovpn-keys`: role-typed WireGuard keys (x25519-dalek, getrandom, zeroize),
  strict parsing, redaction and protected Unix key files.
- Added `lovpn-server` (Linux): setup dry-run/state write, peers, IPv4 pool, atomic
  generation-checked state, offline profile export, `firewall show/validate`.
- Added server nftables policy compiler and kernel namespace tests.
- Added `lovpn identity generate|public`.
- Added docs: server administration, enrollment and broker design.
- Not included: privileged applier/broker, daemon, systemd units, online enrollment,
  Linux client lifecycle, Windows, GUI. Revocation is not enforced on live interfaces.

## Earlier — offline foundation

- Added architecture, threat model, security model, networking design, development
  evidence, roadmap and feature matrix.
- Added strict bounded schema-v1 public profile validation with sanitized errors,
  explicit IPv4/IPv6/DNS/routing policy, and no executable import hooks.
- Added a deterministic, non-executing nftables full-tunnel policy compiler with
  scoped reset preview and explicit unsupported-mode failures.
- Added an unprivileged CLI for `config validate`, firewall preview/validation,
  privacy, diagnostics/status and version reporting.
- Added parser, CLI, policy, and disposable Linux WireGuard/nftables enforcement tests.
- Added native Windows test/clippy/release-build CI path and dependency/doc checks.

Not included: client/server daemons, enrollment, private-key storage, DNS resolver
integration, GUI, Windows WFP/driver integration, automatic updates or production
support claims.
