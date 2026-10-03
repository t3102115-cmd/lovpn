# Changelog

All notable changes to this pre-release project are recorded here. There is no
production release yet.

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
- Not included: running the unit as a real service, the client lifecycle, Windows, GUI,
  online enrollment, server key rotation.

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
