# Development and evidence

## Initial assessment — 2026-10-03

- Workspace was empty, with no source, instructions or Git repository.
- Linux: Fedora 44 KDE, x86_64, kernel 7.2.8-200.fc44.x86_64.
- Rust/cargo 1.97.1; rustfmt and clippy installed. Windows MSVC Rust target installed
  locally; this alone does not provide an MSVC linker/SDK or Windows runtime tests.
- nftables 1.1.6, iproute2 6.17.0, systemd 259; NetworkManager/resolved tools present.
- WireGuard kernel module loaded, `/dev/net/tun` and `/dev/kvm` present. `wg` absent.
- Ordinary user, no effective CAP_NET_ADMIN. Private user+network namespace creation
  and querying its empty nft ruleset succeeded without touching host networking.
- QEMU/libvirt tooling installed; no VMs registered in the user's libvirt session.
- Windows test VM reached using SSH with existing host-key validation and a system
  password prompt; **no credential copied to this repository or command arguments**.
  Windows 11 Pro, version 10.0.26200, 64-bit; rustc 1.99.0, cargo 1.99.0 observed.
  Exact VM address, username and credentials intentionally omitted here.
- Missing locally: cargo-audit, cargo-deny, cargo-fuzz, cargo-llvm-cov, shellcheck,
  GTK3 and WebKitGTK development packages. No system packages installed by inspection.

The foundation check also built `cargo-audit 0.22.2` into the approved temporary
directory `/tmp/opencode/lovpn-tools` (not globally installed) and scanned the locked
68-dependency graph against the RustSec advisory database on 2026-10-03. The command
completed without a reported advisory. This is a snapshot dependency check, not a
security audit of LoVPN and not a claim that future dependencies are safe. `cargo-deny`
and fuzzing tools remain unavailable locally; CI configuration requires them.

## Build policy

Use Rust 1.97.1 as the initially tested baseline/MSRV; older versions are not claimed.
Direct dependencies are exact-version requirements; commit Cargo.lock for binaries.
No nightly features or project-authored unsafe code. New dependencies must justify
their role, license, maintenance, transitive cost and build-time network behavior.
The build may contact crates.io/Rust infrastructure and CI may fetch advisory
databases; the resulting foundation CLI has no online features. For air-gapped
builds prepare a verified vendor directory/cache on a connected machine first.

Planned checks: `./scripts/build-linux.sh`, `./scripts/build-windows.sh`,
`./scripts/test.sh`, `./scripts/lint.sh`, `./scripts/test-networking.sh`.
The Windows script must not pretend Linux cross-checking is a native Windows build.
Use the VM's installed Rust for native checks; do not install new compilers silently.

## Test matrix / release blockers

| Environment / behavior | Current evidence | Required before support claim |
| --- | --- | --- |
| Fedora 44 host tools | Inspected; isolated nft namespace available | Actual CLI/compiler tests below |
| Ubuntu/Debian client/server | Not tested | Install, resolver/firewall coexistence, reboot |
| Windows 11 Pro 10.0.26200 | SSH and compiler versions inspected | Native tests; future service/WFP/driver/leak suite |
| Windows other builds | Not tested | Explicit supported-build matrix |
| Full WireGuard client/server | Not implemented | Enrollment, handshake, traffic, revocation |
| DNS/IPv6/full-tunnel protection | No product protection claim | Packet captures from independent observer |
| Sleep/wake, Wi-Fi/Ethernet change | Not implemented | Failure injection throughout transitions |
| Existing firewall/VPN/NAT/routing | Not integrated | Ownership, coexistence and clean recovery |
| Release/update verification | Not implemented | Signature/rollback/provenance tests |

## Evidence discipline

Record exact commands, exit status and coverage. Unit tests are not OS enforcement
tests. nft syntax acceptance is not a leak test. A namespace packet test covers
only its declared flows, not a whole VPN. Cross-target compilation is not Windows
execution. A missing tool or advisory DB is blocked, not passed. Performance has
not been measured. Never run destructive firewall experiments in the host namespace.

Security review checkpoints and final command results will be appended after the
foundation implementation is integrated.

## Current M1 evidence — 2026-10-03

- `cargo +stable test --workspace`: passed, 31 Rust tests plus doc-test targets.
- `cargo +stable clippy --locked --workspace --all-targets -- -D warnings`: passed.
- `cargo +1.97.1 test --locked --workspace` and `cargo +1.97.1 clippy --locked
  --workspace --all-targets -- -D warnings`: passed; this is the pinned initial MSRV
  check. The filesystem emitted only a hard-link/incremental-cache performance
  warning because the workspace is on a filesystem without hard-link support.
- `cargo +stable fmt --all -- --check`: passed.
- `python3 scripts/check-docs.py`: passed, 12 Markdown files and no outbound link
  checks.
- `RUSTUP_TOOLCHAIN=stable CARGO_INCREMENTAL=0 ./scripts/test-networking.sh`: passed
  29 disposable-namespace checks. The suite created ephemeral WireGuard links and
  nftables state only inside user/network namespaces and removed the owned table;
  it did not modify host firewall state.
- Native Windows 11 Pro 10.0.26200 VM: Rust 1.99.0 native `cargo test --locked
  --workspace` passed (30 cross-platform integration tests; the Linux-only
  symlink/FIFO test is cfg-disabled), and native `cargo clippy --locked --workspace
  --all-targets -- -D warnings` passed. The native release build then stalled during
  compilation without CPU progress for over two hours and was terminated; the release
  build and CLI smoke commands were not completed.
- `cargo-audit 0.22.2 audit --deny warnings`: completed against the locked graph;
  no advisory was reported. Fuzzing and coverage remain pending.
- `cargo-deny 0.20.2 --locked check`: passed all advisory, ban, license and source
  checks after pinning internal path dependency versions and allowing the transitive
  Unicode-3.0 license expression. The executable was built in `/tmp/opencode` and
  is not part of the repository.
- `./scripts/build-linux.sh`: passed, producing optimized Linux workspace binaries.

These results validate the offline foundation only. They do not validate enrollment,
privileged services, DNS resolver behavior, boot persistence, Windows WFP/driver
integration, sleep/wake transitions, or production leak protection.

## M2a evidence — 2026-10-03

- Baseline before changes: `cargo +1.97.1 test/clippy/fmt` and `scripts/check-docs.py`
  passed (31 tests).
- The repository's own `target/` directory on the exFAT-style DATA drive produced a
  rustc internal compiler error during incremental builds; M2a builds and tests used a
  fresh `CARGO_TARGET_DIR` on a normal filesystem. This is an environment problem, not
  a code claim.
- New tests: `lovpn-keys` (8: RFC 7748 vector, weak/non-canonical rejection, clamping,
  redaction, key-file permission/symlink/hard-link/oversize cases), server compiler
  (3), `lovpn-server` library (10: lifecycle, key/lease reuse, pool exhaustion, setup
  validation, atomic persistence, concurrent writers, crash recovery, corrupt/oversized/
  downgraded state, permissions, secret absence) and CLI (4), client identity CLI (1).
- `scripts/test-networking.sh`: 36 checks passed (29 client + 7 server policy) inside a
  disposable user+network namespace: kernel nft check/apply, idempotent re-apply,
  no host drop policy, reset removes only LoVPN tables and keeps an unrelated table.
- Final M2a run on Rust 1.97.1: `cargo fmt --check`, `cargo clippy --locked --workspace
  --all-targets -- -D warnings`, `cargo test --locked --workspace` (57 tests, 0 failed)
  and `scripts/check-docs.py` passed. `cargo-audit` (80 locked crates) reported no
  advisory and `cargo-deny` passed advisories/bans/licenses/sources after allowing
  BSD-3-Clause (x25519-dalek/curve25519-dalek). Snapshot checks, not a security audit.
- Finding during testing: a clamped private key passed as `--public-key` was accepted;
  fixed with a confirmation guard (`server.key-looks-private`) and documented as a
  residual risk.
- Not tested: packet forwarding/NAT through the server, WireGuard handshake against
  server output, systemd, broker (not built), Windows (not executed; the `lovpn-keys`
  file module and `lovpn-server` are Unix/Linux only and Windows was not touched this
  slice).

## M2b evidence — 2026-10-03

- Final run on Rust 1.97.1 (scratchpad `CARGO_TARGET_DIR`, see the M2a note about the
  corrupt repo `target/`): `cargo fmt --check`, `cargo clippy --locked --workspace
  --all-targets -- -D warnings`, `cargo test --locked --workspace` (73 tests, 0 failed,
  +16 broker/applier tests) and `scripts/check-docs.py` passed. `cargo-audit` (80 locked
  crates) found no advisory; `cargo-deny` passed all four checks. Snapshot checks.
- Unprivileged applier/broker tests use a fake in-memory host plus a real Unix socket:
  key never in argv and only on stdin, idempotent apply, stale-address reconcile,
  revocation by re-apply, foreign interface/table refusal with zero mutating commands,
  rollback of a failed apply, rollback-to-old-state refusal, teardown scope, read-only
  observation and drift reasons, private broker directory, peer-credential denial for
  other users and root-only teardown, oversized/malformed/unknown/extra-field requests,
  slow-client timeout, unsafe socket paths and double start, fail-closed on corrupt state.
- `scripts/test-networking.sh` now runs three suites, all in disposable namespaces,
  74 PASS lines total: the 29 existing client checks, 7 server-policy checks, and a
  38-check server gate (`tests/networking/server_e2e.py`) with **real WireGuard, the real
  broker process, two client namespaces and an upstream namespace**: enrollment from
  `lovpn identity generate`, drift before apply, apply and observed in-sync state, two
  peers reaching the upstream through the tunnel with source NAT, real handshakes, peer
  isolation (dropping rule's counter > 0), live revocation (revoked peer loses access,
  other peer keeps working), rollback refusal and restoration, key rotation, loss of
  interface and tables followed by drift report and recovery (client re-handshake took
  about 16 s: WireGuard's rekey timeout), `firewall repair`, foreign-table refusal, and
  teardown with forwarding restored.
- `scripts/test-install.sh` (4 PASS): plan mode changes nothing; staged install; uninstall
  keeps the server key; `systemd-analyze verify` accepts the unit.
  `systemd-analyze security --offline` scored the unit 2.8 ("OK"). These are static
  checks: the unit was **not** started as a real service.
- Findings during M2b: (1) a first gate run showed recovery needs WireGuard's rekey
  timeout, so the test polls instead of asserting instant recovery and the docs state the
  delay; (2) `nft add table` does not update an existing comment, so the compiler
  emits add/delete/add in one atomic batch to stamp the current generation.
- Not tested: running the broker as a systemd service or on a host with an existing
  firewall/VPN/NAT, reboot persistence, IPv6, throughput/latency, a real client, Windows
  (nothing Windows-related ran this slice; `lovpn-server` and the key-file module are
  Unix/Linux only).
