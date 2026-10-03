# Enrollment and privilege-broker design

Status: **offline enrollment and the Linux server broker are implemented** (see
[server.md](server.md)). Online enrollment, the Windows broker and the *client*
broker are **designs only; no code exists**.

## Offline enrollment (implemented)

1. Client: `lovpn identity generate --key-file F` creates the key pair locally; the
   private key stays in `F` (0600) and is never printed. Only the public key is shown.
2. Administrator: `lovpn-server peer create --name N --public-key K`.
3. Server: allocates the lowest free pool address, records the peer, bumps the
   generation. Keys and addresses are never reused after revoke/rotate.
4. Server: `peer export N` emits a schema-v1 public profile, **re-validated by the
   same `lovpn-config` parser a client uses** before it is emitted.
5. Client imports the profile and verifies the server public key through a separate
   channel. LoVPN does not authenticate the server for the user; the file alone is not
   proof.

Evidence: unit/integration/CLI tests (replay of keys, name/lease rules, secrets absent
from outputs) and `tests/networking/server_e2e.py`, where two peers enrolled this way
complete real WireGuard handshakes with a broker-applied server. The test clients are
configured by hand from the exported profile: the Linux client lifecycle does not exist.

## Online enrollment (design, not implemented)

Goals: let an administrator add a device without moving files, with no LoVPN-operated
service. Optional; offline enrollment remains the baseline.

- **Transport**: TLS 1.3 only, using a maintained TLS library (candidate: rustls with
  a vetted crypto provider; the license/audit review is a precondition). The server
  certificate is self-generated; its SPKI hash is distributed **out of band** with the
  token. The client pins it; no fallback to system roots or "trust on first use", and
  certificate validation is never disabled.
- **Token**: at least 256 bits from the OS CSPRNG, shown once to the administrator
  (stdin/QR/file, never argv or logs), valid for a short administrator-set window
  (default 15 minutes, hard cap 24 hours). The server stores only a keyed digest
  (BLAKE2s/SHA-256 via a maintained crate) plus metadata: id, expiry, bound state,
  creator generation. QR codes are only an encoding.
- **Request** (bounded, e.g. 4 KiB, strict schema, unknown fields rejected):
  `{version, token, client_public_key, proof}`. The token is carried in the TLS body,
  never in a URL or header that proxies/logs record. The private key is never sent.
  The client public key is bound to the token at first redemption.
- **Redemption** is one durable state transaction under the same lock/generation
  discipline as `Store::update`: verify unexpired and not revoked, constant-time digest
  compare, create the peer, mark the token `redeemed(client_public_key, peer_id)`.
- **Retries / lost responses**: a repeat with the *same* token digest **and the same
  client public key** returns the already-created profile (idempotent). Any other key,
  or a repeat after the lost-response window closes, fails as replayed. The token is
  never reusable for a different key.
- **Expiry and clocks**: expiry is checked against a monotonic-plus-persisted clock
  record; persisted time that moves backwards is rejected, not silently extended.
- **Rate limiting**: before parsing the body or doing digest work, per-source and
  global failure budgets with exponential back-off; budgets persist across restart.
- **Errors/logs**: uniform failure responses that do not distinguish unknown, expired
  and replayed tokens to the caller; logs record event class and token *id*, never
  token text, request bodies or client IPs by default.
- **Required tests before release**: expired, replayed, revoked, concurrent redemption,
  crash during redemption (before/after commit), malformed, oversized, wrong server
  identity (pin mismatch), wrong client key, token leakage via logs/errors/panics.

## Privileged broker

The GUI, CLI and `lovpn-server` management commands never run as root. A small broker
is the **only** component allowed to configure TUN/WireGuard interfaces, routes,
nftables/WFP, resolver state, and privileged state files.

**Implemented (Linux server broker, `lovpn-server broker`)**: the 0600 Unix socket,
kernel peer-credential checks and per-operation authorization (`teardown` root-only),
4 KiB strict-schema requests with timeouts and serialized handling, expected-generation
checks, no paths/commands/interface names in requests, ownership checks for the
interface (broker record) and nft tables (comment marker), an anti-rollback record in a
root-only directory, rollback of partial applies, and sanitized structured logs. The
systemd unit exists but has never run as a real service. **Not implemented**: the
client-side broker (TUN, routes, kill switch, resolver), Windows service/named pipe.

The text below is the full design the implemented part follows, and the requirements
for the client broker.

Linux:

- Authenticated Unix socket under a root-owned directory; mode restricts to a
  dedicated group. `SO_PEERCRED` (uid/gid/pid) is read from the kernel; the pid is not
  trusted for identity decisions beyond logging.
- **Operation-level authorization**: a fixed enum (`apply-server-state`,
  `client-connect`, `client-disconnect`, `status`, `repair`, ...) each mapped to
  allowed uids/groups. Socket access alone authorizes nothing.
- Requests: length-prefixed, max 64 KiB, strict schema, bounded queue depth, expected
  generation required for mutations (stale requests fail without change).
- **No arbitrary paths or command arguments.** Requests reference LoVPN-owned state by
  id; the broker reads the state from its own protected directory and runs the pure
  compilers itself. It never executes a string from a profile, state or request.
- Ownership: the broker acts only on interfaces and tables it can prove it created
  (name prefix plus a recorded creation record verified against kernel state); it
  never flushes the host ruleset or unrelated routes/resolver state.
- Persistent monotonic generation counter owned by the broker (implemented: the
  applied-generation record; it closes the rollback gap for applied state).
- systemd hardening (to be verified with `systemd-analyze security`): `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `CapabilityBoundingSet=CAP_NET_ADMIN`
  (`CAP_NET_RAW` only if shown necessary), `RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6`,
  `SystemCallFilter=@system-service`, explicit `ReadWritePaths`. `PrivateNetwork` is
  not used because the service manages host networking. Capabilities are not a sandbox
  against a compromised broker.

Windows (later): dedicated service, ACL-restricted named pipe, caller-token
authorization; only after Linux behavior is real and tested natively in the VM.
