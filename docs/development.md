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
| Full WireGuard client/server | Disposable namespace client/server gates; no real-host support claim | Enrollment, handshake, traffic, revocation on supported host matrix |
| DNS/IPv6/full-tunnel protection | IPv4 policy and optional resolved adapter implemented; unmanaged DNS/IPv6 limits documented | Independent resolver/packet leak evidence |
| Sleep/wake, Wi-Fi/Ethernet change | Resume detection/nudge implemented; real power/network transitions not tested | Failure injection throughout transitions |
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

## M3 packaging/documentation evidence — 2026-10-03

- `python3 scripts/check-docs.py`: passed (16 Markdown files, no network requests).
- `bash -n scripts/install-client.sh scripts/test-install.sh scripts/install-server.sh`:
  passed.
- `./scripts/test-install.sh`: passed 8 checks covering server and client dry-run
  plans, staged files/modes, profile-preserving uninstall, and the client owner UID
  configuration. No root, users, systemd manager or network changes were used.
- On the available systemd 259 tools, `systemd-analyze verify` accepted both broker
  units and `systemd-analyze security --offline=yes` accepted both units. These are
  static analyses only; neither broker was started as a service.
- Not run for this packaging lane: the networking end-to-end suites, real
  systemd/resolved behavior, DHCP, reboot ordering, suspend/resume, NetworkManager
  coexistence, IPv6 or real-host leak tests.

## M3 client evidence — 2026-10-03

- On Rust 1.97.1 with `CARGO_TARGET_DIR` on a normal filesystem:
  `cargo +1.97.1 fmt --all -- --check` passed; workspace
  `cargo +1.97.1 clippy --locked --workspace --all-targets -- -D warnings` passed;
  and `cargo +1.97.1 test --locked --workspace` passed (the workspace suite completed
  with 102 tests and 0 failures, plus zero-test unit/doc-test targets). A first full
  run exposed and fixed one unused import and a pre-existing nondeterministic test
  key choice; those fixes are included in this working tree.
- Client-focused coverage includes 20 engine tests and 6 real-socket client-broker
  tests. The firewall compiler suite has 12 tests, including owned generations and
  the IPv4 DHCP exception.
- With `RUSTUP_TOOLCHAIN=1.97.1 CARGO_INCREMENTAL=0`,
  `./scripts/test-networking.sh` passed with 135 `PASS:` lines across the client
  policy suite, server policy suite, real server WireGuard gate and new real client
  WireGuard/broker gate. All namespaces were created under
  `unshare --user --map-root-user --net --pid --fork --mount-proc`; no host firewall,
  resolver or persistent namespace was used.
- The new client gate observed offline enrollment, expected-server-key rejection,
  real WireGuard traffic NATed through the server, exact `dns-unmanaged` degraded
  status, fail-closed routing and cleartext-uplink blocking after interface loss,
  monitor repair, broker crash/restart recovery, strict release and VPN-only
  disconnect, reset and preservation of an unrelated nftables table.
- These results do not test a real systemd service, real systemd-resolved, DHCP
  lease renewal, Wi-Fi/Ethernet changes, suspend/resume, NetworkManager coexistence,
  IPv6 tunnel/endpoint behavior, LAN bypass or a host-wide production leak claim.

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

## 2026-10-07 audit and focused security fix evidence

- The repository was audited in its existing working-tree state. No reset or broad
  rewrite was performed. The workspace already contained the M3 Linux client,
  server broker, packaging and disposable client gate.
- Focused fix: client route cleanup no longer flushes policy table `19567`. It
  inspects the table and removes only the recorded default route on the broker-owned
  interface; an extra route returns `connect.foreign-route`. A failed disconnect
  restores a connected desired record so monitor repair remains active.
- Route inspection is strict for mutation decisions: malformed or incomplete JSON
  is treated as unknown and aborts cleanup rather than being interpreted as an
  empty table.
- Defense-in-depth fix: client session records are bounded no-follow reads with
  regular-file, single-link, owner and permission checks. Regression tests cover a
  session symlink and group-readable record.
- `CARGO_TARGET_DIR=/tmp/omnirush/lovpn-target CARGO_INCREMENTAL=0 cargo fmt --all
  -- --check`: passed.
- `CARGO_TARGET_DIR=/tmp/omnirush/lovpn-target CARGO_INCREMENTAL=0 cargo clippy
  --locked --workspace --all-targets -- -D warnings`: passed.
- `CARGO_TARGET_DIR=/tmp/omnirush/lovpn-target CARGO_INCREMENTAL=0 cargo test
  --locked --workspace`: passed; all workspace tests and doc-test targets passed.
- `python3 scripts/check-docs.py`: passed.
- `./scripts/test-install.sh`: passed; staged server/client installation and
  uninstall preservation checks passed.
- `CARGO_TARGET_DIR=/tmp/omnirush/lovpn-target CARGO_INCREMENTAL=0
  ./scripts/test-networking.sh`: passed. The disposable suites covered real
  WireGuard/nftables policy, server NAT/peer isolation/revocation/recovery, and
  client enrollment, endpoint recursion, pre-existing flow blocking, interface
  loss, monitor repair, broker restart, strict/vpn-only release and reset.
- The first networking attempts exposed test-harness defects rather than product
  failures: a Python probe accidentally put its timeout in an exception suite,
  blocked sends were treated as process failures, and the roam test did not restore
  its original cleartext path. The harness now handles those expected blocked
  outcomes explicitly.
- The repository filesystem still causes a Rust 1.97 incremental compiler ICE in
  the default `target/` directory. The successful post-change checks used a clean
  target directory on `/tmp`; this is an environment limitation, not a code result.
- Not run or claimed: real systemd service operation, real systemd-resolved and
  NetworkManager coexistence, reboot/suspend host matrix, Windows runtime/WFP/
  WireGuardNT behavior, fuzzing, performance, or a production leak guarantee.

## Windows client and window — 2026-10-07

Environment: Windows 11 Pro 10.0.26200 VM (administrator, SSH key authentication, Rust
installed); host Fedora 44. The lab server is `tests/windows/lab-server.sh`: the real
`lovpn-server` and broker in a disposable user+network namespace created by `pasta`, with a
DNS responder on the tunnel address and an HTTP decoy on an unroutable TEST-NET address.
Nothing on the host network changed; no root was used. `tests/windows/lab-exec.sh` runs a
command inside that namespace.

- Driver: `wireguard-nt-1.1.zip` from download.wireguard.com; `amd64/wireguard.dll`
  SHA-256 `b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3`;
  `Get-AuthenticodeSignature`: Valid, `CN=WireGuard LLC`. (The vendor publishes no hash,
  so the pin is trust on first download plus the signature.)
- Linux: `cargo fmt --check`, `clippy --locked --workspace --all-targets -D warnings`,
  `cargo test --locked --workspace` (124 tests), `scripts/test-install.sh` (8 checks),
  `scripts/test-networking.sh` (all suites, 150 checks, re-run on the final tree),
  `python3 scripts/check-docs.py`, and `cargo deny check` (advisories, bans, licenses,
  sources: ok; `cargo-deny 0.20.2` built into a temporary directory, not installed).
- Windows (native): `cargo fmt --check`, `clippy --locked --workspace --all-targets -D
  warnings`, `cargo test --locked --workspace --no-fail-fast` (63 tests, includes the
  Windows-only storage tests for DPAPI, directory ACL and profile rules).
- Windows runtime: `tests/windows/vm-e2e.ps1` 34/34 and `tests/windows/vm-recovery.ps1`
  13/13 on the final build (run as a SYSTEM scheduled task because a strict kill switch
  cuts any SSH session; a SYSTEM watchdog task runs `lovpn-service release`).
- Window: 12 unit tests (HTTP parser, session secret, Host/Origin, sanitizer, language
  catalog parity); 93 browser checks plus an axe-core audit (0 violations) in headless
  Chromium against a test double (`tests/ui/`, never shipped; `scripts/test-ui.sh`); the real
  Windows service by hand. Tray: 8 unit tests, one live run on KDE Plasma and one on the Windows VM desktop.
- Not run: reboot persistence, sleep/resume, real network-change events, other Windows
  builds or hardware, screen-reader testing, browsers other than Chromium, fuzzing, real
  systemd service operation on Linux.

Failures found by this testing and fixed are listed in [windows.md](windows.md#evidence);
the unit tests also caught a request-smuggling vector (duplicate `Content-Length`) and a
header-size-limit bypass in the window's HTTP layer before release.

## M2c online enrollment evidence — 2026-10-07

- New crate `lovpn-enroll` (token, bounded protocol, TLS 1.3-only pinned transport on
  `rustls` 0.23.45 + ring, `rcgen` 0.14.10, `sha2`, `subtle`). `deny.toml` now allows the
  permissive ISC license (ring, rustls-webpki, untrusted); the exact ring license terms
  (including its OpenSSL/BoringSSL-derived files) still need the REL-02 license review.
- Linux: `cargo fmt --check`, `clippy --locked --workspace --all-targets -D warnings`,
  `cargo test --locked --workspace` (164 tests), `scripts/test-install.sh` (8 checks, now
  including the enrollment unit under `systemd-analyze verify`/`security --offline`),
  `scripts/test-networking.sh` (169 checks; `server_e2e.py` gained `enrollment_gate`),
  `python3 scripts/check-docs.py`, `cargo deny check` and `cargo audit` (no findings).
- Server tests (`tests/enroll.rs`, 20): redemption, digest-only storage on disk, exact
  expiry boundary, idempotent retry vs replay vs other key, revoked peer, uniform denial for
  revoked/unknown/wrong-secret, naming/TTL/capacity rules, clock regression, duplicate-key
  not burning the token, old-state compatibility, 8-thread concurrent redemption creating
  one peer, crash before commit leaving the token pending, wrong pin sending nothing,
  expired/revoked over the wire, malformed/oversized/unknown-field requests, pre-TLS rate
  limiting that survives a listener restart, a stalled socket bounded by the deadline, and
  TLS identity permissions. `tests/enroll_cli.rs` (3) runs the real binary and scans its
  output, logs and state files for tokens, secrets, client keys and addresses.
- Gate (`enrollment_gate`, real TLS to a listener running as a nested uid 1000, real broker
  apply, real WireGuard): wrong pin refused with nothing logged server-side, enrollment,
  `applied` confirmed, peer live in the kernel, traffic through the tunnel with a handshake,
  identical retry returns the same profile, another key refused, one active peer, log/state
  free of the token, revoke removes the peer.
- Superseded by the next section: the enrollment unit, identity rotation and the Windows
  run are now done. Still not run: fuzzing of the request parser, and load or slow-loris
  measurements beyond the unit deadline test.

## Real-host gate — 2026-10-07

`tests/linux-vm/run.sh --fresh` (see `tests/linux-vm/README.md`): two KVM guests, Fedora
Cloud Base 44 (kernel 6.19.10, **SELinux enforcing throughout**, systemd-resolved and
NetworkManager active), image checksum-verified; built from scratch, then 17 phases and
**102 checks, 0 failures** in one uninterrupted run. Control is the QEMU guest agent over
virtio-serial so it survives a strict kill switch; leak claims are parsed from QEMU's own
frame capture of each NIC, with a positive control (after release the same capture does see
direct IPv4 on the physical NIC).

- Install and services: the real `install-server.sh`/`install-client.sh` as root (service
  user, 0700 state and broker directories, units verified by `systemd-analyze verify`),
  `systemctl enable --now`, journal logging. Measured capabilities: server broker
  CAP_NET_ADMIN+CAP_DAC_READ_SEARCH+CAP_CHOWN only; client broker CAP_NET_ADMIN+CAP_CHOWN only;
  enrollment listener runs as `lovpn-server` with **no capabilities** and NoNewPrivs
  (`systemd-analyze security`: exposure 1.7). An unconfigured enrollment unit does not listen.
- Enrollment on real units: TLS identity rotated under the running service; the old pin is
  refused, the listener logs `enroll-identity-reloaded`, the new pin enrolls; the server's
  unit asked the real broker to apply and the key was live in the kernel; neither journal
  contains the token.
- Connected: every one of the seven checks observed OK, real `resolvectl` link settings
  (`~.`), a name that exists only on the tunnel resolver resolves, tunnel-only HTTP works,
  traffic to the host works through tunnel + server NAT, traffic forced onto the physical
  NIC is blocked, and the capture shows only WireGuard on the LAN NIC and nothing but DHCP on
  the physical NIC.
- Failures: `SIGKILL` of the client daemon (kill switch table survives; systemd restarts it;
  back to Protected without reconnecting), NetworkManager restart and DHCP re-acquisition
  through the kill switch, `systemd-resolved` restart (link settings intact), frozen server
  VM (no fallback path), strict disconnect (Blocked) and explicit release.
- Reboot and suspend: a real client reboot with a strict connected profile came back
  Protected on its own about 21 s after the command; across the whole boot the client sent
  exactly one DHCP frame, ARP, and WireGuard on the LAN NIC, **no other IPv4 and no IPv6** on
  the physical NIC. A real ACPI S3 suspend/resume: Protected about 2 s after wake, traffic
  works, no leak frame. A real server reboot: the broker's `--apply-on-start` restored
  interface, peers and firewall by itself and the client returned to Protected.
- Uninstall/teardown: client uninstall removes program and unit and keeps profiles/keys;
  server `teardown` then uninstall keeps state and key.
- Bugs this gate found and fixed: `setup --write-state` refused the empty 0700 directory the
  installer's tmpfiles rule creates; a rebooted server stayed down until an administrator ran
  `apply` (now `--apply-on-start`); the enrollment listener could miss a rotation that landed
  between reading and stamping the identity; three of my own test checks used a token
  fragment that can legitimately appear anywhere (secrets may contain `-`).
- Windows `lovpn enroll --identity`: built natively in the Windows 11 VM (ring compiles with
  MSVC) and run against a Linux listener on the VMware network: wrong pin refused, valid token
  enrolled and imported with the service-held key, identical retry returned the same profile.
  The identity name must equal the profile name, so `--identity` is a flag.
- Not covered: Debian/Ubuntu or any other distribution, physical NICs and Wi-Fi switching,
  several uplinks, IPv6 underlay, rogue DHCP/RA, a NetworkManager profile that *manages* the
  tunnel link, other VPNs or firewalls on the host, interrupted writes (power loss), and
  anything about performance. The guest agent's own SELinux domain is permissive (lab control
  channel only). Reboot and suspend are virtual: no real firmware or driver resume path.
