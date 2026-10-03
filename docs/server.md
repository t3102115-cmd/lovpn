# Server administration (M2a + M2b)

`lovpn-server` manages server identity, peers and state, and — through a small
privileged **broker** — applies that state to a Linux host: a WireGuard interface,
the enrolled peers, IPv4 forwarding and LoVPN's own nftables tables. It is tested
end to end with real WireGuard in disposable namespaces (see
[Evidence](#evidence-and-what-it-does-not-prove)). It is not yet a finished product:
read [Known limitations](#known-limitations) before relying on it.

## What is implemented

| Capability | Status |
| --- | --- |
| Server identity generation (OS CSPRNG, WireGuard-compatible X25519) | implemented, tested |
| `setup --dry-run` (validates, previews, writes nothing) / `setup --write-state` | implemented, tested |
| Peers: create / list / export / revoke / rotate, IPv4 pool leases | implemented, tested |
| Atomic, locked, generation-checked state; crash recovery | implemented, tested |
| Privileged broker: authenticated socket, per-operation authorization | implemented, tested |
| `apply`: WireGuard interface + peers (atomic `wg syncconf`), address, MTU, forwarding, nft tables | implemented; verified with real WireGuard in a namespace |
| Revocation / rotation enforced on the live interface | implemented (`--apply` or `apply`); verified with real traffic |
| Rollback protection for applied state | implemented; verified |
| `status --live`, `firewall status/repair`, `teardown` | implemented; verified |
| systemd unit, sysusers/tmpfiles, install/uninstall script | written; `systemd-analyze verify` and a staged install tested; **never run as a real service** |
| Structured sanitized broker logs | implemented (JSON lines to stderr/journal) |
| IPv6 | only the explicit `block` policy |
| Online (token) enrollment | design only |
| Server key rotation, split-tunnel/LAN-gateway modes, DNS forwarding, resource metrics | **not implemented** |

## Quick start

Everything below can be tried as an unprivileged user **except** `apply`, which needs the
broker running as root. To try it without touching your host, use the disposable
namespace test (`./scripts/test-networking.sh`, see [development.md](development.md)).

```bash
# 1. Review the plan. Writes nothing.
lovpn-server --state-dir ./lovpn-state setup --dry-run \
  --endpoint 203.0.113.10:51820 --pool 10.66.0.0/24 --wan-interface eth0 --dns 10.66.0.1

# 2. Create the state directory, server key and state (mode 0700 / 0600). Still no network change.
lovpn-server --state-dir ./lovpn-state setup --write-state \
  --endpoint 203.0.113.10:51820 --pool 10.66.0.0/24 --wan-interface eth0 --dns 10.66.0.1
```

On the client device (private key never leaves it):

```bash
lovpn identity generate --key-file ~/.config/lovpn/laptop.key   # prints only the public key
```

Send **only that public key** to the administrator, then:

```bash
lovpn-server --state-dir ./lovpn-state peer create --name laptop --public-key <PUBLIC_KEY> --apply
lovpn-server --state-dir ./lovpn-state peer export laptop --output laptop.toml
```

Deliver `laptop.toml` to the client and give them the server public key over a
separate channel (`lovpn-server status`). The profile holds no secret, but an attacker
who can alter it in transit could point the client at their own server; that is why the
key comparison is out of band. `--dns` must name a resolver reachable **through the
tunnel**; LoVPN does not run one.

> The **client** side that turns a profile into a connected, leak-protected VPN is not
> built yet. The server test configures its test clients by hand with `wg` and `ip`.

## Installing the broker on a host

```bash
./scripts/build-linux.sh                         # release binaries
./scripts/install-server.sh                      # prints the plan, changes nothing
sudo ./scripts/install-server.sh --yes           # installs files; starts nothing, changes no network
sudo -u lovpn-server lovpn-server setup --write-state --endpoint <ip>:51820 --pool 10.66.0.0/24 --wan-interface <uplink> --dns <resolver>
sudo systemctl enable --now lovpn-server-broker
sudo -u lovpn-server lovpn-server apply          # <- this is the moment networking changes
sudo -u lovpn-server lovpn-server status --live
```

Before exposing the server you must also (LoVPN does not do these for you): allow the
UDP listen port in your host firewall, and provide a resolver that answers on the
tunnel address you passed as `--dns`.

Uninstall: `sudo lovpn-server teardown --yes` first (removes LoVPN's interface, nft
tables and restores `ip_forward`), then `sudo ./scripts/install-server.sh --uninstall --yes`
(keeps `/var/lib/lovpn-server`; add `--purge` to also reset the broker record). Deleting
the state directory is a manual decision: it destroys the server identity and
invalidates every exported profile.

## Commands

- `peer create|list|export|revoke|rotate` as before; `--apply` on create/revoke/rotate
  enforces the change through the broker and **fails loudly** if applying fails (the
  state is saved, the host keeps the previous configuration).
- `--expected-generation N` fails without change if the state moved since you read `N`.
- `apply [--expected-generation N]`: reconcile the host with the current state.
  Idempotent. Refuses a state older than anything already applied (`state.rollback`).
- `status [--live]`: with `--live` the broker compares host and state and lists drift
  (`interface-missing`, `peers-missing`, `peers-unexpected`, `firewall-missing`,
  `firewall-generation-mismatch`, `forwarding-off`, ...). `in_sync` describes the
  **server's** configuration only, never a client's protection.
- `firewall show|validate` (offline), `firewall status|repair` (through the broker).
- `teardown --yes` (root only): remove only LoVPN-owned resources. Clients lose service.
- `reset --plan`: prints the removal steps; deletes nothing.
- `broker --owner-user lovpn-server --broker-dir /var/lib/lovpn-broker`: the daemon.
- Peer names: 1-64 of letters, digits, `-`, `_`, `.`, not all digits (digits are ids).
  Revoked peers' addresses are quarantined and their keys burned.
- A public key shaped like a clamped private key is refused unless `--confirm-public-key`.

## Privileges (every one)

| Component | Runs as | Needs |
| --- | --- | --- |
| `lovpn-server` CLI (state, peers, export) | `lovpn-server` user | read/write its own 0700 state directory; connect to the broker socket |
| `lovpn-server broker` | root with a bounded capability set | `CAP_NET_ADMIN` (link, addresses, nftables, `ip_forward`), `CAP_DAC_READ_SEARCH` (read the service user's state), `CAP_CHOWN` (give the socket to that user); read-only state, read-write only `/var/lib/lovpn-broker` |
| external tools | children of the broker | `ip`, `wg`, `nft` from `/usr/sbin:/usr/bin:/sbin:/bin`, absolute path, no shell, cleared environment |

The broker never reads a command, path, interface name or address from a request: a
request is an operation (`ping`, `status`, `apply`, `repair-firewall`, `teardown`) and
optionally an expected generation. Interface, tables and addresses come from validated
state. Capabilities are not a sandbox against a compromised broker.

## Broker protocol and authorization

One JSON line per connection, at most 4 KiB, strict schema (unknown fields and
operations are rejected), 3-second I/O timeouts, requests handled one at a time. The
socket (`/run/lovpn-server/broker.sock`) is `0600` and owned by the service user, **and**
every caller is checked with kernel peer credentials per operation: `ping`, `status`,
`apply`, `repair-firewall` allow root or the service user; `teardown` is root only.
Logs record the operation, caller uid and result code, never payloads, keys or peers.

## Filesystem locations and permissions

| Path | Mode / owner | Contents |
| --- | --- | --- |
| `/var/lib/lovpn-server/` | 0700, `lovpn-server` | state directory (override with `--state-dir`) |
| `.../server.key` | 0600 | server private key, one base64 line; created exclusively, never overwritten; one hard link |
| `.../state.json` | 0600 | schema version, generation, settings, **public** keys, peer table; max 1 MiB |
| `.../state.lock`, `state.json.tmp` | 0600 | advisory lock; transient write file |
| `/var/lib/lovpn-broker/applied.json` | 0600 in a 0700 root dir | highest applied generation (anti-rollback), interface the broker owns, previous `ip_forward` |
| `/run/lovpn-server/broker.sock` | 0600, service user | broker socket |
| exported profiles | 0600 | public profile from `--output`; never overwritten |

Client key files (`lovpn identity generate --key-file`) are 0600, created exclusively,
refuse symlinks/hard links/foreign owners/group- or world-writable directories; no
implicit location. No Windows key storage yet.

## Network and firewall behavior

LoVPN makes **no outbound connection**. It listens on the configured UDP port (kernel
WireGuard) and on the local Unix socket. `apply` makes exactly these changes:

1. creates interface `lovpn-srv0` (WireGuard) if the broker's record shows it owns none,
   sets key and peers with `wg syncconf` (existing sessions of unchanged peers continue),
   sets the server address (first host of the pool), MTU and brings it up;
2. sets `net.ipv4.ip_forward=1`, remembering the previous value for `teardown`;
3. installs two nftables tables atomically, each marked `comment "lovpn-owned gen=<N>"`:
   `inet lovpn_server` — forward chain, **policy accept** (LoVPN never drops host traffic):
   drop all IPv6 to/from the tunnel; drop tunnel traffic from any source that is not an
   active lease (no active peers: drop all); drop peer-to-peer forwarding; peers may reach
   only the uplink interface, and only the uplink may reach peers. `ip lovpn_server_nat` —
   masquerade the pool out of the uplink.

Ownership: an interface is modified only if the broker's record says it created it and
it is WireGuard; a table only if it carries the marker. A same-named foreign
interface or table is reported (`apply.foreign-interface`, `apply.foreign-table`) and
left untouched. LoVPN cannot override another table's verdicts: a host whose own
firewall drops forwarded traffic must allow it. LoVPN does not open the UDP port in the
host firewall and does not flush any ruleset.

DNS: the profile's resolver addresses are pushed to clients; the server runs no
resolver and changes no resolver state. IPv6: profiles use the `block` policy.

## Key handling

Private keys are generated from OS randomness, held in zeroizing types with redacting
`Debug`, and reach `wg` only through its standard input, never argv, logs, JSON output,
profiles or errors (tests scan outputs and recorded command lines for the secret).
Zeroization is best effort. A *private* key pasted as a public key is shape-confusable
about 1 time in 16, hence the confirmation flag; never paste secrets into commands.

## Troubleshooting and recovery

| Code | Meaning / action |
| --- | --- |
| `broker.unreachable` | The broker is not running or you are neither root nor the service user. Nothing was applied. |
| `auth.denied` | Operation not allowed for your uid (`teardown` is root only). |
| `state.rollback` | The state is older than what was applied (restored old backup?). Restore the newer state. Never delete `/var/lib/lovpn-broker` just to get past this unless you accept losing rollback protection. |
| `apply.foreign-interface` / `apply.foreign-table` | Something not created by LoVPN uses LoVPN's name. Rename or remove it yourself; LoVPN will not. |
| `apply.command-failed` | A step failed and this run's changes were rolled back; check `journalctl -u lovpn-server-broker`, then `status --live`. |
| `state.permissions` / `state.invalid` / `state.version` | Directory/file mode or ownership wrong, state corrupt or from another schema. Nothing is overwritten; restore a backup. |
| `state.busy` / `state.generation-conflict` | Retry / re-read and retry. |
| `server.pool-exhausted` | Quarantined leases fill the pool; use a larger pool (no purge command yet). |

Recovery paths: a crash while writing leaves the previous complete state; if the host
loses the interface or tables (reboot, manual deletion), `status --live` shows the exact
drift and `apply` (or `firewall repair`) restores it; `teardown --yes` removes everything
LoVPN created without touching anything else. After a server interface is recreated,
connected clients re-handshake on their own after WireGuard's rekey timeout (measured
at about 16 s in the test), not instantly.

## Evidence and what it does not prove

Real WireGuard, a real broker process and two client namespaces were exercised in a
disposable user+network+pid namespace (`tests/networking/server_e2e.py`): enrollment,
apply, observed in-sync state, two peers reaching an upstream network through the tunnel
with NAT, real handshakes, peer isolation (with the dropping rule's counter checked),
revocation, rollback refusal, key rotation, recovery after losing interface and tables,
`firewall repair`, foreign-table refusal and teardown. It does **not** prove: behavior as
a systemd service, running on a real host with an existing firewall/VPN/NAT, reboot
persistence, IPv6, throughput, or anything about a client.

## Known limitations

- The broker unit has been verified syntactically and scored by `systemd-analyze`
  (offline exposure 2.8, "OK") but never started as a real service; installation was
  tested only into a staging directory.
- No client lifecycle: a connected, DNS- and IPv6-protected client does not exist yet.
- Only full-tunnel/Internet-gateway style routing with NAT is implemented; no LAN-gateway
  or non-NAT routing mode, no split-tunnel policy, no DNS forwarder, no IPv6 tunneling.
- No daemon health socket beyond `status --live`; no resource metrics.
- The anti-rollback counter protects against restored old state only for the broker's
  applied generation; if `/var/lib/lovpn-broker` is lost the counter resets.
- Wall-clock time is used only for timestamps, never for security decisions.
- No server key rotation, PSK distribution, peer purge, or online enrollment.
- Linux only; the server compiles to a stub elsewhere and was not built on Windows this
  slice.
