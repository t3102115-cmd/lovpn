# Troubleshooting

The client broker reports observed state, not a successful request alone. Start
with:

```bash
lovpn status
lovpn diagnostics
systemctl status lovpn-clientd
journalctl -u lovpn-clientd --no-pager
```

## Common cases

| Symptom/code | Action |
| --- | --- |
| Service not running / `broker.unreachable` | Check `systemctl status lovpn-clientd`; confirm `/etc/default/lovpn-client` contains the intended numeric `LOVPN_OWNER_UID`, then inspect the journal. |
| `auth.denied` | Run `lovpn` as the configured owner UID or root. Do not make the socket world-writable. |
| `connect.dns-unsupported` | Managed DNS requires a working systemd-resolved setup with `/etc/resolv.conf` pointing into `/run/systemd/resolve`. Start/fix resolved, or explicitly choose the unmanaged backend and accept degraded DNS protection. |
| `dns-unmanaged` / degraded | DNS was intentionally not managed. The tunnel may carry packets, but LoVPN does not claim resolver protection. |
| `connect.foreign-interface`, `connect.foreign-table`, `connect.foreign-rule` | LoVPN found a same-named resource it cannot prove it owns. It refuses to overwrite it; inspect and resolve the collision manually. |
| `connect.endpoint-unsupported` | The server endpoint is IPv6. M3 requires a literal IPv4 endpoint. |
| `connect.routing-unsupported` or `connect.ipv6-tunnel-unsupported` | M3 supports full IPv4 routing with IPv6 blocked only; split and IPv6 tunnel profiles are not implemented. |
| `connect.command-failed` | The broker rolled back where possible and leaves an armed kill switch armed. Check the journal and run `lovpn status`; use `lovpn repair` only after fixing the reported host condition. |
| `enroll.pin-mismatch` | The server's certificate does not match the pin; nothing was sent. Re-check the address and the pin (`lovpn-server enroll pin` on the server) and do not retry over an untrusted network. If the administrator rotated the TLS identity (`enroll tls-rotate`), they must give you the new pin; a pending token stays valid. |
| `enroll.denied` | Deliberately undifferentiated: wrong, expired, revoked or already-used token, or a key already in use. Ask the administrator for a new token (`lovpn-server enroll token create`). Retrying the *same* token with the *same* key works only within 10 minutes of a successful redemption. |
| `enroll.rate-limited`, connection reset or timeout during enrollment | The server drops sources after repeated failures (30 s up to 1 h). Wait, then retry once with the correct values. Administrators: failures are counted per source and globally in `enroll-limits.json`. |
| `enroll.clock` / `enroll.token-state` / `enroll.no-identity` | The server clock is behind the last time recorded in its state; a token can only be revoked while pending; or run `lovpn-server enroll tls-init` once first. |
| Enrolled but `applied: false` | The server recorded the peer but could not apply it through the broker. The administrator runs `lovpn-server apply`. |
| After a server reboot clients stay blocked | The server broker unit re-applies the persisted state at start (`startup-apply` in `journalctl -u lovpn-server-broker`). If that line shows a non-`ok` code (for example `state.storage` for missing state or `state.rollback`), fix the cause and run `lovpn-server apply`. Strict clients stay blocked meanwhile on purpose. |
| `state`/profile permission errors | Keep `/var/lib/lovpn-client` and its files root-owned and mode 0700/0600. Do not replace them with symlinks or group-writable files. |

## Windows

| Symptom/code | Action |
| --- | --- |
| `service.unreachable` | Open Services and start **LoVPN Client**; check `%ProgramData%\LoVPN\logs\service.log` (`lovpn logs` needs the service). If the service stops at once, the log says why (for example a missing `service.json` or a driver hash mismatch: re-run the installer with the official `wireguard.dll`). |
| `auth.denied` | Only the user who installed the service, Administrators and SYSTEM may use it. Re-run the installer from the account that should control LoVPN. |
| `connect.command-failed` with a step name | A Windows networking step failed; the message names the step and the Win32 error number. A `strict` profile stays blocked: run `lovpn disconnect --release-kill-switch` or `lovpn reset` to get your internet back, then `lovpn diagnostics`. |
| Internet is blocked and the service is not running | By design the `strict` kill switch survives a crash and a reboot. Start the service (**LoVPN Client**; it resumes the connection), or, if it will not start, run from an elevated terminal: `"C:\Program Files\LoVPN\lovpn-service.exe" release`. That removes LoVPN's firewall filters and records that nothing is armed, without needing the service. `lovpn-service.exe uninstall` deliberately does **not** remove them. |
| Status says *Not fully protected* with `endpoint-route` | The route to your server no longer matches the physical uplink (for example after switching network). The monitor repairs this within seconds; `lovpn repair` forces it. |
| `profile.key-file-unsupported` | Windows keeps the key inside the service. Use `lovpn identity generate --name N`, then import without `--key-file`. |
| The window says the service isn't running | Same as `service.unreachable`; the window only shows what the service reports. |

## Recovery and uninstall

If the tunnel disappears, the broker monitor or a restart should restore owned
state without releasing protection. `lovpn reconnect` recreates only the tunnel;
it does not lower the kill switch. `lovpn repair` reconciles a connected desired
state. For intentional recovery, `lovpn reset` disconnects, releases the owned
policy and forgets the selected profile; `lovpn disconnect` without
`--release-kill-switch` keeps a strict profile blocked.

Before uninstalling, run `lovpn reset` and verify normal networking. The client
installer never deletes profiles or keys, even with `--uninstall`; remove them
through `lovpn profile remove` or delete the retained state only as a separate,
explicit administrative decision. Static unit checks and namespace tests do not
replace a real-host recovery or suspend/reboot test.
