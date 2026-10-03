# Feature and implementation matrix

This compares feature **categories**, not proprietary implementations or vendor
marketing. Target means architecture only. No production VPN release exists.

| Common VPN capability | LoVPN evidence / current limitation | Target / backlog |
| --- | --- | --- |
| Self-hosted, no account | Offline CLI has no account or cloud code | Direct user-owned Linux server; SRV-01 |
| Zero telemetry | No runtime networking in CLI; privacy report and tests | Retain zero-telemetry default in all components |
| VPN connectivity | Kernel WireGuard used in isolated tests only; no client/server backend | Linux netlink / Windows WireGuardNT; LIN-01, WIN-01 |
| CLI | Config validate, firewall preview/static validation, status, diagnostics, privacy, version | Connect/reconnect/profiles/repair after actual adapters |
| Server/device management | Peers, IPv4 pool, revoke/rotate/export, atomic generations; broker applies to a Linux host (WireGuard, forwarding, nft); revoke enforced live; tested with real WireGuard in a namespace | Real-host service run, health metrics, LAN/non-NAT/split modes; SRV-01 |
| Enrollment | Offline public-key exchange implemented (client key stays local); online enrollment design only | Pinned TLS one-time tokens; ENR-01 (M2c) |
| Key storage | Unix 0600 key files (client identity, server key); zeroizing redacting types; no Windows storage; no key rotation of the server key | Windows DPAPI/ACL, server key rotation; KEY-01 |
| Kill switch | nft compiler + isolated enforcement tests; no installed/lifecycle service | Off/VPN-only/Strict, crash/boot persistence; LIN-02/WIN-02 |
| DNS protection | DNS address/route validation; real-kernel DNS-port confinement tests | OS resolver control/leak tests remain DNS-01 |
| IPv6 | Block/tunnel policy compiler tested inside IPv4-underlay WireGuard | IPv6 underlay/NDP and Windows enforcement remain unavailable |
| Full tunnel | Required default routes validated; route installation unavailable | Policy routing and route verification; LIN-01 |
| Split tunneling | Network schema validation only; compiler explicitly refuses it | Route split first; app split later, RT-02 |
| LAN access | No bypass exception in generated policy | Explicit destination policies and conflict checks |
| Profiles/favorites/tags | One public profile can be validated; no persistent profile manager | Local-only profile inventory; UX-01 |
| Auto-connect/reconnect | Not implemented | Service lifecycle and network-change state machine |
| Trusted networks | Not implemented | Later, never trust SSID alone |
| Health/latency/statistics | No fabricated observations or automatic probes | Local measurements; disclose each probe |
| Diagnostics | Sanitized capability report; no actual host protection claim | OS observations and export with stale-evidence handling |
| GUI/tray/accessibility | Design tradeoffs documented; no GUI | Accessibility-gated stack decision; UX-01/02 |
| Updates/signed releases | No downloader, verifier or installer | Offline-verifiable signed metadata; REL-01/02 |
| Linux/Windows builds | See development evidence; not OS VPN support | Native service/driver/firewall matrix required |
| Firewall reset | Scoped removal text preview, tested only in namespace | Authenticated owned-resource recovery; REC-01 |
| Backup/uninstall | Server: copyable state directory, `teardown --yes` (owned resources only), `install-server.sh --uninstall` (keeps state); installer tested into a staging directory only | Real-host installer evidence, client installers |
| Lo Security / LoOS | Separate boundaries designed; no fake AV/OS | Out of initial VPN scope |
| Public directory | Optional independent design only | Later, never core dependency |

## Platform differences to preserve

Linux will use nftables and rtnetlink/generic netlink, coordinating with
systemd-resolved/NetworkManager. Windows requires WFP, IP Helper/adapter APIs,
service ACLs and resolver policy. Linux nft text is never applied on Windows.
Network splitting is portable conceptually; process splitting and split DNS need
distinct platform implementations and cannot share an unchecked "supported" flag.
