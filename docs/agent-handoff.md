# LoVPN agent handoff

Handoff date: 2026-10-07 (second session)

## CURRENT STATE

LoVPN is an early implementation, not a production VPN release. The workspace has nine
Rust crates. The Linux server and client brokers, the CLI, the **Windows client service**
and the **window** all exist and were exercised end to end:

- Linux server and client: unchanged in behavior; shared model, protocol and dispatch were
  moved to platform-neutral modules (`lovpn-client::{model,protocol}`, `ClientEngine`).
- Windows client (`lovpn-win`, `lovpn-service.exe`, `scripts/install-client.ps1`):
  WireGuardNT (pinned hash + signature), IP Helper, persistent WFP kill switch with DNS
  guard and IPv6 block, DPAPI keys, ACL'd named pipe with token checks, SCM service with
  crash recovery and a monitor, offline `lovpn-service release`. See [windows.md](windows.md).
- The window (`lovpn-ui`, [ui.md](ui.md)): Home with the protection ring, Servers, Devices,
  Privacy, Diagnostics, Settings, Logs, Advanced, onboarding wizard, sanitized diagnostics,
  light/dark. Works on Windows and Linux.

The Windows client was verified in **one** Windows 11 VM against a real LoVPN server in a
disposable namespace. Sleep/resume, real network changes and reboot persistence are not
evidenced. Still absent: IPv6 tunnel/underlay, split tunnel, LAN access, online
enrollment, tray, updater, MSI. See [current-state.md](current-state.md) and
[feature-matrix.md](feature-matrix.md).

## COMPLETED (this session and the previous one)

First session (CLI and Linux hardening):
- Audited the repo; wrote [current-state.md](current-state.md).
- Fixed client cleanup flushing the whole policy-routing table (now exact-route removal,
  foreign routes refused); fixed disconnect failure recovery; hardened session-record reads.
- Added CLI `server add|list|remove|test`, `profile use`, `logs`, default-server marker.
  `server test` verifies the stored profile only and reports reachability `not-tested`.

Second session (Windows + window):
- Windows build/test were broken natively (Unix-only items in `lovpn-client` and the key
  tests; an empty clap default for `--socket`). Fixed; gates now pass on both platforms.
- New crate `lovpn-win` (the only crate allowed `unsafe`; `undocumented_unsafe_blocks` is
  denied): `driver`, `ip`, `wfp`, `policy` (pure, tested everywhere), `store` (DPAPI, ACL),
  `pipe`, `profiles`, `record`, `engine`, `daemon`, `host`/`main` (service), tests.
- New crate `lovpn-ui` with a strict hand-written loopback HTTP layer (unit tests found a
  smuggling vector and a limit bypass, both fixed) and the page (`ui/`).
- `lovpn-cli` is now a library plus a binary; client commands work on Windows; Windows has
  no key file: `identity generate --name`, `profile import` without `--key-file`.
- Protocol: `generate-identity`, `import-identity-profile`, `logs` (Windows-only; Linux
  answers `unsupported.platform`).
- Linux packaging installs `lovpn-ui` and a desktop entry; install smoke test extended.
- Docs: new [windows.md](windows.md) and [ui.md](ui.md); README, current-state, feature
  matrix, roadmap, architecture (GUI decision), security model, enrollment, SECURITY,
  troubleshooting, client, development and CHANGELOG updated to match.

Bugs found by the Windows runtime tests and fixed (do not reintroduce): tunnel address left
in DAD *Tentative* (unroutable); `ImpersonateNamedPipeClient` before a read; reply lost by
`DisconnectNamedPipe` without a flush; endless 3-second "repair" for an on-link server;
stale host route from a stopped/released service failing the next connect.

## TESTS RUN AND RESULTS

Linux: `cargo fmt --check`, `clippy --locked --workspace --all-targets -D warnings`,
`cargo test --locked --workspace` (124 tests), `scripts/test-install.sh` (8 checks),
`scripts/test-networking.sh` (150 checks), `scripts/check-docs.py`,
`cargo deny check` (all four sections ok): passed.

Windows (native, VM): fmt, clippy `-D warnings`, `cargo test --workspace` (63 tests): passed.
`tests/windows/vm-e2e.ps1` 34/34 and `tests/windows/vm-recovery.ps1` 13/13 on the final
build. Window: 12 unit tests, 93 browser checks, axe audit; manual review of all states in a browser, plus connect,
logs and disconnect through the window on the real Windows service.

`scripts/test-networking.sh` passed again on the final tree (150 checks, all suites: firewall,
server firewall, server end to end, client end to end).

## REMAINING

- Real hosts: the Linux matrix is done on Fedora 44 VMs only (`tests/linux-vm`); Debian/Ubuntu,
  hardware NICs and Wi-Fi switching remain;
  Windows reboot persistence, sleep/resume, Wi-Fi/Ethernet switching, other Windows builds,
  hardware NICs, coexistence with other VPN/firewall products and domain machines.
- Windows: boot-time (pre-BFE) filters, NRPT/split DNS, power/network-change notification
  proof, multi-interface and link-local enforcement, MSI/upgrade/rollback, tray icon.
- Window: a screen-reader audit (keyboard/contrast/axe are done), more languages,
  favorites/tags, opt-in server health probes.
- Networking features not implemented anywhere: IPv6 through the tunnel, split tunnel, LAN
  access while connected. Do not add switches for them before there is enforcement and a
  leak test; the Advanced page lists them as not available.
- Server key rotation, PSK lifecycle (online enrollment is done; see enrollment.md), updater with verified metadata,
  fuzzing, SBOM/provenance, independent security review (unchanged).

## KNOWN BUGS AND LIMITS

- No known failing test. Real-host bugs remain unmeasured (see REMAINING).
- The Windows `vm-e2e.ps1` leak detector allows DHCP (UDP 68/67) because the policy permits
  it; the capture also tolerates the lab's management SSH to the host address. Both are in
  the script, not hidden.
- `lovpn-ui` is not usable without the service; it says so rather than guessing.
- Windows `lovpn logs` shows service events only; there is no Event Log integration.
- The wireguard-nt vendor publishes no hash; the pin is trust-on-first-download plus the
  Authenticode check. Review before changing it.
- The fixed Linux route-table number and nft ownership comments are conventions, not kernel
  ownership primitives; the code refuses conflicts but cannot stop a hostile root process.
- Windows machine-scope DPAPI means any Administrator/SYSTEM process can unseal the key.

## SECURITY CONCERNS

- Never reintroduce `ip route flush table 19567` or any whole-table cleanup without
  an independently verified ownership proof. Prefer exact route deletion and
  refuse foreign entries.
- Never release the kill switch on crash, reconnect failure, failed observation or
  unknown state. Explicit release is a deliberate authenticated local action.
- Keep the kill switch installed before creating/configuring the tunnel and keep
  policy rules fail-closed if the interface disappears.
- Do not accept profile-supplied commands, paths, nft expressions, hooks or
  arbitrary interfaces in a privileged request. Keep fixed program allowlists and
  typed validated arguments.
- Never log, print, serialize or place in argv/environment a private key, token,
  password, profile secret or sensitive request body. WireGuard private keys go to
  the tool through zeroized stdin only.
- Preserve server/client key separation and out-of-band server-key verification.
  A QR code or profile file is transport, not authentication.
- Treat unknown, stale or contradictory observations as unknown/degraded, never
  `Protected`. Do not turn a handshake into a routing/DNS claim.
- Do not run networking experiments in the host namespace. Keep namespace tests
  disposable and verify unrelated nftables/routing state survives.
- (Windows) Never remove the WFP filters on crash, reconnect failure, failed observation
  or unknown state; only an explicit release (`lovpn disconnect --release-kill-switch`,
  `lovpn reset`, or the offline `lovpn-service release`). Install the policy *before* the
  adapter exists and permit tunnel traffic only after addressing, routes and DNS.
- (Windows) Keep `unsafe` inside `lovpn-win` with a `SAFETY` note on every block. The
  WireGuardNT DLL must stay pinned by SHA-256 and signature; changing the pin is a reviewed
  source change. Never accept a path, command or filter text from a request.
- (Window) `lovpn-ui` must keep: loopback only, per-launch secret cookie, Host and Origin
  checks, strict CSP, `textContent`-only DOM, and an *allowlist* sanitizer. Do not add
  `innerHTML`, remote assets, or a way to pass a path to the service.
- (Both) Never present an unobserved check as verified: green means observed this poll.


## NEXT TASKS

1. Run the Windows scenarios on a second Windows version/hardware and add a reboot and a
   real sleep/resume test (VM snapshot + power actions; keep the SYSTEM watchdog).
2. Repeat `tests/linux-vm` on Debian/Ubuntu (the lab is Fedora-specific only in package names
   and cloud-init) and on physical hardware.
3. Build and runtime-test the MSI (it now includes `lovpn-tray.exe`); prove the tray menu on Windows.
4. Screen-reader audit of the window (axe and browser tests exist).
5. Design and implement LAN access and split tunneling per platform with separate leak
   matrices; then IPv6 through the tunnel.
6. Online enrollment is implemented and was run on real units and in the Windows VM.
   Remaining: QR/URI encoding and a rotation overlap period.
7. Re-review every security claim in README, SECURITY.md and the feature docs against the
   evidence before any release.

## HOW TO RE-RUN THE WINDOWS TESTS

Lab server (host, no root): `LAB_DIR=/tmp/lovpn-lab tests/windows/lab-server.sh`; enroll the
VM with the real flow (`lovpn identity generate --name vm` on Windows, `lovpn-server peer
create/export` via `tests/windows/lab-exec.sh`, `lovpn profile import ... --expect-server-key`).
Copy `tests/windows/vm-e2e.ps1`/`vm-recovery.ps1` to the VM, arm a SYSTEM watchdog
(`lovpn-service.exe release` after N minutes), run the script as a SYSTEM scheduled task and
read its result file after the VM's network returns. Do not run these over a session you
need: a strict kill switch intentionally cuts it.
