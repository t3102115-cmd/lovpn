# Client (Linux M3; Windows in [windows.md](windows.md); window in [ui.md](ui.md))

The M3 Linux client has a root **`lovpn-clientd`** broker and an unprivileged
**`lovpn`** CLI. The broker owns only resources it can identify as LoVPN-owned;
the CLI sends authenticated requests over `/run/lovpn-client/broker.sock`. The
implementation, the disposable namespace client gate and the Fedora 44 virtual-machine
gate (`tests/linux-vm`) cover connect, reconnect, strict/vpn-only disconnect, interface
loss, broker restart, real reboot and real suspend/resume. They do not establish
production support on other distributions or real hardware.

## Install and start

Build first, then review the plan. The installer is dry-run by default:

```bash
./scripts/build-linux.sh
./scripts/install-client.sh --owner-user "$USER"
sudo ./scripts/install-client.sh --owner-user "$USER" --yes
sudo systemctl enable --now lovpn-clientd
```

`--destdir DIR --owner-uid UID --yes` stages files without root, users or
systemd. `--uninstall --yes` stops the service and removes the binaries, unit
and owner-UID defaults file, but **never removes** `/var/lib/lovpn-client` or
its profiles and private keys. Run `lovpn reset` first to release active
network policy; uninstall itself never runs a firewall, route or resolver
command.

## Privileges and files

| Component/path | Owner/mode | Purpose |
| --- | --- | --- |
| `lovpn-clientd` | root, bounded systemd service | Owns the tunnel lifecycle and fixed `ip`, `wg`, `nft` and `resolvectl` operations; no shell or profile-supplied command is executed |
| `CAP_NET_ADMIN` | service capability | WireGuard link, addresses, policy routes/rules and nftables |
| `CAP_CHOWN` | service capability | Gives the 0600 socket to the configured controlling UID |
| `/var/lib/lovpn-client/` | root, 0700 | Session record, public profiles and client private keys |
| `/var/lib/lovpn-client/profiles/` | root, 0700; files 0600 | Broker-owned `<name>.toml` and `<name>.key` files |
| `/run/lovpn-client/broker.sock` | controlling UID, 0600 | One-request Unix socket; kernel peer credentials are checked per operation |
| `/etc/default/lovpn-client` | root, 0644 | Non-secret `LOVPN_OWNER_UID` used by the unit |

The unit intentionally does **not** set `PrivateNetwork`: it must configure the
host namespace and preserve an outer route to the IPv4 server endpoint. It does
not claim `CAP_NET_RAW`, `CAP_DAC_*`, module, sysctl or broad capabilities.
Capabilities reduce accidental authority; a compromised root broker is still a
networking authority.

## Supported M3 behavior

- Full-tunnel IPv4 through a literal IPv4 WireGuard endpoint only.
- The broker installs an owned `inet lovpn_client` nftables policy before the
  tunnel, an endpoint fwmark exception, a tunnel route and fail-closed rules.
  It does not flush unrelated nftables tables or routes.
- The firewall permits only loopback, the marked endpoint UDP flow, the tunnel,
  and IPv4 DHCP client renewal (`UDP 68 -> 67`). DHCP is only an nft exception:
  LoVPN does not run a DHCP client or manage lease lifecycle.
- IPv6 payload is blocked. IPv6 server endpoints, IPv6 tunnel mode, NDP/RA,
  IPv6 DHCP, LAN bypass and split routing are unsupported and rejected rather
  than partially applied.
- With the default `--dns-backend resolved`, `systemd-resolved` receives the
  profile resolvers on the tunnel link with `~.` and default-route enabled;
  `/etc/resolv.conf` is not rewritten. `--dns-backend unmanaged` leaves DNS
  alone and status reports `dns-unmanaged`/degraded; it is not DNS protection.
  Resolvers other than systemd-resolved are unsupported by the managed mode.
- A monitor repairs missing owned state and nudges handshakes after an observed
  resume or stale handshake. The durable record re-arms strict protection on
  restart. In strict mode an intentional disconnect remains `blocked` until
  the user explicitly releases the kill switch; the controlling owner or root
  can lift it. This is deliberate recovery authority, not protection from a
  compromised local account.

## Commands

| Command | What it does |
| --- | --- |
| `lovpn status`, `diagnostics`, `privacy`, `firewall status` | observed state; `--json` for scripts |
| `lovpn connect [name]`, `disconnect`, `reconnect`, `repair`, `reset` | session control through the service |
| `lovpn server add\|list\|remove` | same as `lovpn profile import\|list\|remove` |
| `lovpn profile use <name>` | choose the default server without connecting; refused while a session is active |
| `lovpn server test <name>` | verifies the stored profile only. It does **not** test reachability: a WireGuard server is silent to unauthenticated probes, so only a connection with an observed handshake proves it |
| `lovpn logs [--lines N]` | Linux: the `lovpn-clientd` journal via `journalctl` (needs journal read access). Windows: the service's own log, via the service |
| `lovpn enroll --server ADDR --pin sha256:… --token-file F --name N (--key-file K --generate-key \| --identity)` | redeems a one-time token over pinned TLS 1.3 and imports the returned profile. Sends only the token and your PUBLIC key; the token is read from a file or `-`, never argv. Whether the server applied the peer is reported honestly (`applied`). `--identity` uses the service-held key named like `--name` (Windows; run in the Windows VM) |
| `lovpn identity generate --key-file F` (Linux) / `--name N` (Windows) | Linux writes a new 0600 key file; Windows has the service create and keep the key. Prints only the public key |
| `lovpn-ui` | the window ([ui.md](ui.md)) |

## Evidence and limits

Unit syntax and offline systemd security analysis are static checks only. The
installer is tested in a staging directory. The service has **not** been started
on a physical host. The Fedora 44 VM gate did run it as a real service with real
`systemd-resolved`, NetworkManager, reboot ordering, suspend/resume and DHCP; existing
firewall/VPN state, IPv6, LAN access, other distributions and physical NICs have not been
exercised. The namespace client test uses unmanaged DNS, so it is not evidence for
resolver behavior; the VM gate is. Use `lovpn status` and `lovpn diagnostics`; a
missing or unknown observation is not `protected`.
