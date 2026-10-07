# Windows client

Status: **implemented slice, verified on one Windows 11 VM against a disposable Linux
server. Not a production release.** Read [Limits](#limits-and-what-is-not-evidenced) before
relying on it.

The Windows client is the same product as the Linux client: the same profile format, the
same offline enrollment, the same states (`protected`, `degraded`, `blocked`, ...), the same
`lovpn` commands and the same window. Only the platform layer differs.

## What runs where

| Component | Runs as | Role |
| --- | --- | --- |
| `lovpn-service.exe` (service `LoVPNClient`) | LocalSystem, automatic start, restart on failure | Owns the tunnel, routes, DNS, firewall policy and keys. The only Windows component with privilege. |
| `lovpn.exe` | the user | Command line. Talks to the service over a named pipe. |
| `lovpn-ui.exe` | the user | The window ([ui.md](ui.md)). Talks to the service exactly like `lovpn.exe`. |
| `wireguard.dll` | loaded by the service | Official **WireGuardNT 1.1** (kernel driver API), Authenticode-signed by WireGuard LLC. |

Everything unsafe is confined to the `lovpn-win` crate (the rest of the workspace still
forbids `unsafe_code`). Each `unsafe` block carries a `SAFETY` note and clippy enforces it
(`undocumented_unsafe_blocks`).

## Install

From an elevated PowerShell, with the official `wireguard.dll` (`amd64`) from
`wireguard-nt-1.1.zip` at <https://download.wireguard.com/wireguard-nt/>:

```powershell
cargo build --release --workspace
.\scripts\install-client.ps1 -SourceDir .\target\release -DriverDll C:\path\to\wireguard.dll
.\scripts\install-client.ps1 -SourceDir .\target\release -DriverDll C:\path\to\wireguard.dll -WhatIfOnly   # plan only
.\scripts\install-client.ps1 -Uninstall            # add -Purge to also delete profiles and keys
```

The installer refuses to proceed unless the DLL's SHA-256 equals the pinned
`b1b85e07...a6461d3` **and** its Authenticode signature is valid and issued to WireGuard
LLC. The service repeats the hash check before every load. Nothing is downloaded by
LoVPN. Files land in `%ProgramFiles%\LoVPN` (writable only by Administrators and SYSTEM)
and state in `%ProgramData%\LoVPN`. A Start Menu shortcut starts the window.

## First use

```powershell
lovpn identity generate --name home          # the service makes and keeps the key; prints the public key
# give that public key to the server administrator; they run: lovpn-server peer create / export
lovpn profile import home.toml --name home --expect-server-key <server key from the admin, separately>
lovpn connect home
lovpn status
```

On Windows the client private key **never exists as a file**: the service creates it,
seals it with DPAPI (machine scope) and never shows it. `--key-file` is Linux-only.

## Security design

- **Order of operations (fail closed).** Connect installs the firewall policy *before* the
  adapter exists; tunnel traffic is permitted only after the adapter, address, routes and
  DNS are in place. A failed connect keeps a `strict` profile blocked and does not strand
  other profiles offline.
- **Kill switch = persistent WFP filters** in a LoVPN-owned provider and sublayer, installed
  and replaced in a single transaction. They survive a service crash and a reboot, so a
  crash does not open the network. Only an explicit release (`lovpn disconnect
  --release-kill-switch` or `lovpn reset`) removes them. The compiled policy is a pure
  function ([`policy.rs`](../crates/lovpn-win/src/policy.rs)), unit-tested on every platform;
  status compares the *installed* filter set with the *expected* one.
- **DNS guard and IPv6 block** are filters, active whenever connected, even if the kill
  switch is off: DNS (port 53) is blocked except through the tunnel; all IPv6 except loopback
  is blocked.
- **Transport pinning.** The only non-tunnel traffic permitted is UDP to the server endpoint
  from the service executable, plus DHCP and loopback.
- **Control channel.** A named pipe whose DACL grants SYSTEM and Administrators full control
  and the installing user read/write but *not* the right to create pipe instances (so the
  name cannot be squatted); first-instance flag, remote clients rejected, a listening
  instance always exists. Each caller is also re-identified from its access token.
- **Secrets.** DPAPI-sealed keys; a state directory owned by SYSTEM/Administrators with a
  protected DACL, checked on every start (links, junctions and foreign owners are refused);
  requests, errors and logs never contain keys.
- **Driver supply chain.** Pinned digest plus signature; the DLL is loaded by absolute path.

## Recovery without the service

```powershell
& "C:\Program Files\LoVPN\lovpn-service.exe" release     # elevated; removes LoVPN's filters
```

`lovpn reset` and `lovpn disconnect --release-kill-switch` do the same through the service.
Uninstalling the service does not touch the filters, on purpose.

## Evidence

All run on Windows 11 Pro 10.0.26200 (VM), service installed with the installer above,
against a real `lovpn-server` + broker running in a disposable user/network namespace
(`tests/windows/lab-server.sh`). The profile was enrolled through the real offline flow.

`tests/windows/vm-e2e.ps1` (34 checks, 0 failures on the final build) covers: connect to
*Protected* with every check observed; a tunnel-only decoy address reachable and system DNS
answered by the tunnel resolver; IPv6 blocked; MTU applied; strict kill switch blocking
internet, decoy and DNS after disconnect; reconnect from blocked; **service killed** (SCM
restarts it and it resumes to Protected); reconnect keeps the kill switch armed; server host
route deleted behind its back (auto-repair); adapter disabled and default route removed
externally (auto-repair); malformed and wrongly-keyed profile imports refused with nothing
stored; release restoring normal networking; an independent `netsh wfp` dump showing no
LoVPN filters remain; and a `pktmon` capture of the physical NICs for the whole protected
period proving that only WireGuard transport (and the lab's management SSH) left the
machine. `cargo fmt`, `clippy -D warnings` and `cargo test` pass natively, including the
Windows-only storage tests (DPAPI round-trip, directory ACL, profile rules).

`tests/windows/vm-recovery.ps1` (13 checks, 0 failures) covers the worst case: a strict kill
switch armed and the **service stopped**. The block holds with the service gone; the offline
command `lovpn-service.exe release` (Administrator) restores the internet without the
service; a restarted service reports *disconnected* and does not re-arm; a graceful stop leaves
no host route behind; and connecting after a release and restart works. The e2e scenario also
plants a stale host route before the first connect.

Bugs this testing found and fixed (kept here so they are not reintroduced): the tunnel
address stayed in duplicate-address-detection *Tentative* state and was unroutable (DAD is
now disabled and the address created *Preferred*); `ImpersonateNamedPipeClient` needs a
prior read; `DisconnectNamedPipe` discarded the unread reply (flush first); a stale host route
from a stopped or released service made the next connect fail (`add-route`), so routes are now
added idempotently and removed on graceful stop and offline release; the uplink-change
check mis-fired for an on-link server and re-"repaired" every 3 s.

## Limits and what is not evidenced

- One VM, one Windows build, one server. No other Windows version, hardware NIC, Wi-Fi,
  VPN/firewall product coexistence or domain-joined machine was tested.
- **Sleep/resume and real network changes (Wi-Fi to Ethernet) are not evidenced.** The code
  rebuilds the tunnel on a resume event and when the physical route moves; only the route
  deletion/repair path was exercised.
- Boot persistence was not tested by an actual reboot.
- The DPAPI key is machine-scoped: any Administrator or SYSTEM process on that machine can
  unseal it. That is inside the trust boundary (they can already change the firewall).
- Windows Defender Firewall rules that *block* are independent and may still apply.
- WFP filters cover IPv4 and IPv6 ALE connect/accept layers. Non-ALE paths and software
  that talks to the network below ALE are not claimed protected.
- Same product gaps as Linux: IPv4 full tunnel only, IPv6 blocked rather than tunnelled, no
  split tunnel, no LAN access while connected, no updater. Online enrollment exists in the CLI
  (`lovpn enroll --identity`) but has only been compiled for Windows, not run there.
- No tray icon and no MSI. Installation is the PowerShell script.
