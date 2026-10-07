# Enrollment and privilege-broker design

Status: **offline enrollment, the Linux server broker and the Linux client broker are
implemented**, as is the Windows service (see [server.md](server.md), [client.md](client.md)
and [windows.md](windows.md)). Online enrollment is implemented (below). On Windows the client
key is created by the service (`lovpn identity generate --name N`), so there is no key file.

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
complete real WireGuard handshakes with a broker-applied server. That server gate's
test clients are configured by hand; the separate client gate exercises
`lovpn-clientd` in a disposable namespace, and `tests/linux-vm` runs the real units on Fedora VMs.

## Online enrollment (implemented, M2c)

Goal: add a device without moving files, with no LoVPN-operated service. It is optional;
offline enrollment remains the baseline. Evidence: `crates/lovpn-server/tests/enroll.rs`,
`enroll_cli.rs`, `crates/lovpn-enroll` unit tests, and the `enrollment_gate` in
`tests/networking/server_e2e.py` (real TLS, real broker apply, real WireGuard handshake).

Flow:

1. Administrator, once: `lovpn-server enroll tls-init` creates the enrollment TLS identity
   and prints its **pin** (`sha256:` + SHA-256 of the certificate DER). It never
   overwrites an existing identity, because that would silently change the pin. To
   replace it deliberately, `lovpn-server enroll tls-rotate --yes` (below).
2. Administrator, per device: `lovpn-server enroll token create --name laptop` prints a
   one-time token **once** (not stored) together with the pin.
3. Administrator: `lovpn-server enroll serve --listen ADDR` (as the service user, never
   root; or the `lovpn-server-enroll` unit). Open that TCP port in your own firewall.
4. Give the client the token and the pin over a channel you trust. The pin is not secret
   but must not be attacker-controlled; the token is a short-lived bearer secret.
5. Client: `lovpn enroll --server ADDR --pin sha256:… --token-file F --name home
   --key-file client.key --generate-key` (token from a file or `-` for stdin, never argv).

What is implemented and how:

- **Transport**: TLS 1.3 only (`rustls`, ring provider; TLS 1.2 is not compiled in).
  The certificate is self-generated (`rcgen`). The client trusts exactly one
  certificate: the one whose SHA-256 equals the pin. There is no fallback to system
  roots, no trust-on-first-use and no switch to disable verification. The handshake
  completes (and the signature is verified against the pinned certificate) **before**
  the request is written, so a wrong pin never discloses the token. Documented
  deviation from the original sketch: the pin covers the whole certificate, not only
  its public key (SPKI); renewing the certificate therefore means re-distributing the
  pin. This avoids an ASN.1 parser in the trust path.
- **Token**: `lovpn1-<16 hex id>-<43 base64url>`; 256-bit secret from the OS CSPRNG,
  default lifetime 15 minutes, hard cap 24 hours. The server stores only a SHA-256 digest
  of the secret (a 256-bit random secret needs no slow KDF) and compares in constant time.
  The id is a non-secret handle used in listings and logs. QR codes are not implemented.
- **Request** (one JSON line, at most 4 KiB, unknown fields and versions rejected):
  `{version, token, client_public_key}`. The token travels in the TLS body only. The
  private key is never sent. There is deliberately **no proof of possession**:
  WireGuard keys cannot sign, an invented proof would be home-made cryptography, and
  registering a key one does not hold only yields an unusable peer.
- **Redemption** is one `Store::update` commit under the state lock: creating the peer
  and marking the token redeemed are the same atomic write. The peer name is chosen by
  the administrator when issuing the token, never by the client. A crash before the
  commit leaves the token pending; after it, an identical retry succeeds (below).
- **Retries / lost responses**: the same token **and the same client key** within 10
  minutes of redemption returns the same profile and changes nothing. Any other key, or
  the same pair later, is `denied`. The token is never reusable for another key.
- **Uniform failures**: unknown id, wrong secret, expired, revoked, already used,
  duplicate key and pool exhaustion all answer `enroll.denied`. Only malformed requests
  and rate limiting differ. Details exist only as event classes in the server log.
- **Expiry and clocks**: the state records a high-water time. A clock that is more than
  120 s behind it makes issuing and redeeming fail (`enroll.clock`); time is never
  silently extended.
- **Rate limiting**: before any TLS work or parsing, a source (IPv4 address or IPv6 /64)
  with an exhausted budget (5 failures per 15 minutes) is dropped with exponential
  back-off from 30 s to 1 h; a global budget (60 failures per 15 minutes) bounds
  distributed guessing. Budgets persist across restarts (`enroll-limits.json`, 0600).
  A throttled client sees a dropped connection, not a distinguishable error.
- **Identity rotation**: `enroll tls-rotate --yes` generates a new certificate and key
  and replaces the one identity file (`enroll-tls.json`, certificate and key together, 0600)
  with a single atomic rename, so a crash can never leave a mismatched pair. The old pin
  stops working **at once** (there is no overlap period, by design: two valid pins would
  double the pin-distribution problem); pending tokens stay valid and simply need to be
  handed out together with the new pin. A running listener notices the changed file on its
  next connection and switches without a restart (it logs `enroll-identity-reloaded`);
  an unreadable replacement keeps the previous identity serving and is logged. Rotate
  between enrollment windows. Evidence: unit tests, and the real-host gate rotates under
  the live `lovpn-server-enroll` systemd unit and shows the old pin refused and the new one
  accepted.
- **Apply**: after commit the listener asks the broker to apply the new peer. If that
  fails the client is still enrolled and the response says `applied: false` so neither
  side is misled; the administrator runs `lovpn-server apply`.
- **Logs**: JSON event class, token id and peer id only. Never token text, request
  bodies, client addresses or keys (checked by tests that scan the real process output).

Limits that remain: one connection is served at a time with a 10 s deadline (a
determined attacker can queue connections but is rate limited per source and globally);
the listener cannot distinguish clients behind one NAT; a compromised service user can
forge tokens or peers (the service user is trusted for peer administration); the pin
channel is the administrator's responsibility; QR/URI encodings are not implemented
and rotation has no overlap period.

## Privileged broker

The GUI, CLI and `lovpn-server` management commands never run as root. A small broker
is the **only** component allowed to configure TUN/WireGuard interfaces, routes,
nftables/WFP, resolver state, and privileged state files.

**Implemented (Linux server broker and Linux client broker)**: authenticated 0600 Unix
socket(s),
kernel peer-credential checks and per-operation authorization (`teardown` root-only),
4 KiB strict-schema requests with timeouts and serialized handling, expected-generation
checks, no paths/commands/interface names in requests, ownership checks for the
interface (broker record) and nft tables (comment marker), an anti-rollback record in a
root-only directory, rollback of partial applies, and sanitized structured logs. The
client broker additionally owns the WireGuard link, policy routing, kill switch and
optional resolved adapter. The units were run as real systemd services in the Fedora 44 VM gate (`tests/linux-vm`).
**Windows**: `lovpn enroll --identity` (the key is held by the Windows service under the profile name created with `lovpn identity generate --name`) was run in the Windows 11 VM against a Linux listener: a wrong pin was refused with nothing sent, a valid token enrolled and imported the profile, an identical retry returned the same profile, and the test profile and identity were removed afterwards. No tunnel was brought up in that test.

The text below records the shared broker requirements and the remaining platform work.

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
- systemd hardening (statically checked for the Linux units): `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `CapabilityBoundingSet=CAP_NET_ADMIN`
  (`CAP_NET_RAW` only if shown necessary), `RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6`,
  `SystemCallFilter=@system-service`, explicit `ReadWritePaths`. `PrivateNetwork` is
  not used because the service manages host networking. Capabilities are not a sandbox
  against a compromised broker.

Windows (implemented, see [windows.md](windows.md)): dedicated service, ACL-restricted named
pipe, caller-token authorization.
