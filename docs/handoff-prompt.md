# Prompt for the next AI engineer

Paste everything below the line into the next session. Keep `docs/agent-handoff.md` as the
source of truth; this prompt is the quick start.

---

You are the PRIMARY IMPLEMENTATION ENGINEER for **LoVPN** ("Local Only"): a free,
self-hostable, privacy-first VPN (Linux server; Linux and Windows clients). No mandatory
account or cloud, no telemetry. Work in the EXISTING repo at
`/run/media/silvan/DATA/LoVPN` (Rust workspace, nine crates). Do not assume anything is
empty; do not rewrite working parts without reason; do not overwrite unrelated user work
(the git tree is large and uncommitted: nothing has been committed, and you must not commit
unless asked).

## Read first (in this order)
`docs/agent-handoff.md`, `docs/current-state.md`, `docs/windows.md`, `docs/ui.md`,
`docs/threat-model.md`, `docs/security-model.md`, `docs/roadmap.md`, `docs/development.md`.

## Non-negotiable rules
- Never fake a feature: no button/setting that does nothing; unsupported things are
  documented and listed as "not available yet". A check is "verified" only if observed.
- No hard-coded secrets, no secrets in logs/argv, no telemetry, no custom crypto, do not
  weaken TLS/firewall to make a test pass. `unsafe` only in `lovpn-win` (with `SAFETY` notes).
- Confirm before hard-to-reverse or outward-facing actions. Never type/store the VM password;
  use the SSH key. Don't run networking experiments in the host namespace.
- Report only what you verified. Update docs when behavior changes.
- Errors must say what happened, why, and what to do.

## What exists (all verified unless noted)
- **Linux** server + client brokers, CLI, nftables kill switch, systemd-resolved DNS,
  namespace test suite (`scripts/test-networking.sh`, ~1 minute, 150 checks).
- **Windows client** (`crates/lovpn-win`, `lovpn-service.exe`, `scripts/install-client.ps1`):
  WireGuardNT 1.1 pinned by SHA-256 + Authenticode, IP Helper, persistent WFP kill switch +
  DNS guard + IPv6 block, DPAPI keys held by the service, ACL'd named pipe + token check,
  SCM service with crash recovery, offline `lovpn-service.exe release`.
- **Window** (`crates/lovpn-ui`): loopback web app (Home protection ring, Servers, Devices,
  Privacy, Diagnostics, Settings, Logs, Advanced, add-server wizard, sanitized diagnostics).
- Shared model/protocol/dispatch: `lovpn-client::{model,protocol}`, trait `ClientEngine`.
- CLI also a library (`lovpn-cli`): `server add|list|remove|test`, `profile use`, `logs`,
  `identity generate --key-file` (Linux) / `--name` (Windows).
- Gates on the final tree: Linux fmt, `clippy -D warnings`, 124 tests, install smoke test (8),
  networking (150), docs check, `cargo deny` all passed; Windows fmt, clippy, 63 tests passed;
  `tests/windows/vm-e2e.ps1` 34/34 and `vm-recovery.ps1` 13/13 on a Windows 11 VM.

## Not done / not evidenced
Windows reboot persistence, sleep/resume, real network switching, other Windows builds;
Linux matrix beyond Fedora 44 VMs; tray icon; MSI; IPv6 through the tunnel,
split tunnel, LAN access; updater; accessibility audit; automated browser
tests; fuzzing; server key rotation.

## Build and test commands
```
export CARGO_TARGET_DIR=/tmp/omnirush/lovpn-target   # repo filesystem triggers a rustc ICE otherwise
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
scripts/test-networking.sh ; scripts/test-install.sh ; python3 scripts/check-docs.py
/tmp/omnirush/tools/bin/cargo-deny check        # may need re-installing: cargo install cargo-deny --locked --root /tmp/omnirush/tools
```
Beware: `pkill -f`/`pgrep -f` with a pattern that appears in your own command line kills or
matches your own shell.

## The Windows VM (important and easy to get wrong)
VMware VM "Bindows" (`/run/media/silvan/DATA/VMs/Bindows/Bindows.vmx`, encrypted, so `vmrun`
needs a password: do not guess one). Windows 11 Pro, admin user `silvan`. Primary NIC
`172.16.8.129` (vmnet8), second NIC `192.168.8.128` (vmnet1). SSH with
`-i ~/.ssh/loav_vm_ed25519 -o BatchMode=yes -o IdentitiesOnly=yes`. Source is synced with
`tar | scp` to `C:\lovpn` and built natively; install with
`scripts\install-client.ps1 -SourceDir target\release -DriverDll %USERPROFILE%\wireguard.dll`
(the official `wireguard.dll` is already on the VM at `C:\Users\silvan\wireguard.dll`; its
SHA-256 is pinned in the installer and `crates/lovpn-win/src/driver.rs`).
- A strict kill switch (correctly) cuts SSH and kills child processes when the session ends.
  Run destructive scenarios as a **SYSTEM scheduled task** and arm a SYSTEM **watchdog** task
  that runs `"C:\Program Files\LoVPN\lovpn-service.exe" release` after N minutes. Poll for the
  result file once the VM's network returns.
- Server side needs no root: `LAB_DIR=/tmp/lovpn-lab tests/windows/lab-server.sh` (real
  `lovpn-server` + broker in a `pasta` user/network namespace, DNS on 10.66.0.1, HTTP decoy on
  192.0.2.50:8080), `tests/windows/lab-exec.sh '<cmd>'` runs a command inside it. Enroll with
  the real flow: `lovpn identity generate --name vm` on Windows, then `lovpn-server peer
  create --name vm --public-key K --apply` and `peer export` through lab-exec, then
  `lovpn profile import ... --expect-server-key <server key>`.
- Test visual states of the window without a service using `tests/ui/fake_broker.py` (test
  double, never shipped); run `lovpn-ui --socket S --port N --no-open` and open the printed URL.

## EXACT SITUATION WHEN THIS PROMPT WAS WRITTEN (in progress, unfinished)
I was starting a **reboot-persistence test** for the Windows strict kill switch and service
resume (expected: after reboot the block holds from boot, the service starts, resumes the
desired connection, status returns to Protected). Steps done: rebuilt `lovpn-server`, started a
fresh lab server (`/tmp/lovpn-lab`, listening on 172.16.8.1:51820, **no peer enrolled yet**).
The old VM profile `vm` still points at the *previous* lab server key, so it must be
re-enrolled (`profile remove vm`, new identity, new peer, import).
**Blocker:** the VM was unreachable at `172.16.8.129` (ARP incomplete, ping and SSH fail) though
VMware reports it running; its second NIC `192.168.8.128` answered ARP. An SSH attempt to
`192.168.8.128` was running in the background when I stopped (host key was not yet accepted,
use `-o StrictHostKeyChecking=accept-new`). Last known state before it vanished: LoVPN
installed, disconnected, no filters armed, scheduled tasks deleted. Possible causes: the guest
NIC/DHCP changed, the guest hung or slept, or a leftover filter (unlikely, it was reset).
Diagnose over the vmnet1 address first; if the VM needs a power action that requires the VM
password or a GUI, ask the user instead of guessing.
Test scaffolding to remove when finished: `/tmp/lovpn-lab`, the lab server processes
(`pasta` + `lab-server.sh inner`), any `lovpn-watchdog`/`lovpn-e2e` scheduled tasks on the VM.

## Suggested next tasks (priority order)
1. Finish the reboot-persistence test (script it like `vm-recovery.ps1`: an at-startup SYSTEM
   task that records, for ~90 s after boot, whether outbound is blocked and the service state;
   then add the result to `docs/windows.md`). Then sleep/resume if the VM allows it.
2. Build and runtime-test the MSI (now includes `lovpn-tray.exe`); prove the Windows tray menu.
3. Screen-reader audit of `lovpn-ui` (automated browser tests and axe exist).
4. LAN access / split tunnel per platform with separate leak matrices; then IPv6 through the tunnel.
5. Repeat the Linux VM gate (`tests/linux-vm`) on other distributions and hardware.

Finish by updating `docs/agent-handoff.md` with completed work, tests run and results,
remaining work, known bugs, limits, security concerns and next tasks.
