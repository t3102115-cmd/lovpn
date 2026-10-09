# Feature and implementation matrix

This compares feature **categories**, not proprietary implementations or vendor
marketing. Target means architecture only. No production VPN release exists.

| Common VPN capability | LoVPN evidence / current limitation | Target / backlog |
| --- | --- | --- |
| Self-hosted, no account | Offline CLI has no account or cloud code | Direct user-owned Linux server; SRV-01 |
| Zero telemetry | No runtime networking in CLI; privacy report and tests | Retain zero-telemetry default in all components |
| VPN connectivity | Linux client broker (fixed tools) and **Windows service (WireGuardNT)**: full IPv4 lifecycle; Linux namespace gate **and a Fedora 44 VM gate** (real systemd services, enforcing SELinux, resolved, NetworkManager, reboot, suspend; `tests/linux-vm`); Windows verified in one VM against a real server ([windows.md](windows.md)); no production claim | Other Linux distributions and hardware NICs; more Windows builds and hardware; LIN-01, WIN-01 |
| CLI | Config validate, firewall preview, status, diagnostics, privacy, version; connect/disconnect/reconnect/repair/reset, `server add\|list\|remove\|test`, `profile list\|use\|import\|remove`, `logs`, `identity`, `--json` on Linux and Windows | Broader platform adapters |
| Server/device management | Peers, IPv4 pool, revoke/rotate/export, atomic generations; broker applies to a Linux host (WireGuard, forwarding, nft); revoke enforced live; tested with real WireGuard in a namespace | Real-host service run, health metrics, LAN/non-NAT/split modes; SRV-01 |
| Enrollment | Offline public-key exchange; online enrollment over pinned TLS 1.3 with hashed one-time tokens, atomic redemption, idempotent retry and persistent rate limits (client key stays local; namespace-tested with a real handshake) | Real-service run, TLS identity rotation, QR/URI, Windows run; ENR-01 |
| Key storage | Linux: 0600 key files, broker-held keys; **Windows: DPAPI-sealed keys the service creates and never shows, in an ACL-protected directory**; zeroizing redacting types; no server key rotation | Server key rotation; KEY-01 |
| Kill switch | Linux: owned nftables policy before tunnel. **Windows: persistent WFP filters (survive crash and reboot), verified against an independent WFP dump and a physical-NIC packet capture.** VPN-only/Strict lifecycle, crash/interface-loss recovery. **Linux VM gate: real reboot, ACPI suspend/resume, daemon SIGKILL, server outage and a NetworkManager restart with DHCP renewal produced no non-DHCP IPv4 frame on the physical NIC (captured outside the guest).** | Other distributions/hardware, NDP/RA, NetworkManager-managed tunnels; Windows reboot/sleep matrix |
| DNS protection | Linux: systemd-resolved per-link adapter. **Windows: tunnel resolvers via the DNS API plus a WFP guard blocking port 53 outside the tunnel.** Unmanaged mode is explicitly degraded. Linux: real systemd-resolved verified in the VM gate | Fallback/multi-adapter leak tests; DNS-01 |
| IPv6 | IPv6 is blocked (Linux nft/rules, Windows WFP); IPv6 endpoint/tunnel/NDP/RA unsupported | IPv6 underlay/tunnel remains unavailable |
| Full tunnel | Linux client installs policy route, fwmark endpoint exception and fail-closed rules; isolated gate | Real-host coexistence and route verification; LIN-01 |
| Split tunneling | Explicitly refused by the client and compiler | Route split first; app split later, RT-02 |
| LAN access | No bypass exception; LAN/NDP allowances unavailable | Explicit destination policies and conflict checks |
| Profiles/favorites/tags | One public profile can be validated; no persistent profile manager | Local-only profile inventory; UX-01 |
| Auto-connect/reconnect | Both platforms: monitor repair, service-restart recovery (Windows: SCM restart + resume of the desired state), route/adapter loss repair; no automatic network-change connect; sleep/resume handler exists but is **not evidenced** | Real network-change/resume matrix |
| Trusted networks | Not implemented | Later, never trust SSID alone |
| Health/latency/statistics | No fabricated observations or automatic probes | Local measurements; disclose each probe |
| Diagnostics | Observed checks on both platforms; sanitized, allowlist-built report (CLI `diagnostics`, window "Copy sanitized diagnostics") | Export with stale-evidence handling |
| GUI/tray/accessibility | **Window implemented** (`lovpn-ui`, [ui.md](ui.md)): Home, Servers, Devices, Privacy, Diagnostics, Settings, Logs, Advanced, onboarding; English/German, axe-audited (0 violations) with automated browser tests; Linux and Windows tray and notifications; Orca partly run (two bugs found and fixed), no NVDA/JAWS/VoiceOver | NVDA/VoiceOver audit; Windows tray menu proof; more languages; UX-01/02 |
| Updates/signed releases | No downloader, verifier or installer | Offline-verifiable signed metadata; REL-01/02 |
| Linux/Windows builds | Native builds, clippy, tests on both; Windows runtime scenario `tests/windows/vm-e2e.ps1` | Native service/driver/firewall matrix on more hosts |
| Firewall reset | Client broker reset removes only an observed owned table; preview compiler remains non-executing; namespace-tested | Real-host recovery and interrupted-upgrade evidence; REC-01 |
| Backup/uninstall | Server teardown + installer and Linux client staged installer; real installers/uninstallers run on the Linux VMs; client uninstall keeps root-owned profiles/keys and never runs network cleanup; a rebooted server restores itself from persisted state | Interrupted-upgrade recovery, other distributions |
| Lo Security / LoOS | Separate boundaries designed; no fake AV/OS | Out of initial VPN scope |
| Public directory | Optional independent design only | Later, never core dependency |

## Platform differences to preserve

Linux M3 uses nftables and rtnetlink/generic netlink through the root client broker,
with an optional systemd-resolved adapter; NetworkManager coordination is not yet
implemented. Windows uses WFP, the IP Helper API,
WireGuardNT, a named pipe with an ACL and DPAPI (see [windows.md](windows.md)). Linux nft text is never applied on Windows.
Network splitting is portable conceptually; process splitting and split DNS need
distinct platform implementations and cannot share an unchecked "supported" flag.
