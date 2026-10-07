# Security model

This document distinguishes implemented M3 Linux components from the remaining
platform designs. Update execution is not implemented; online enrollment is
implemented for the Linux server and the CLI client (see below).

## Privileges and IPC

The Linux server broker is implemented as described in
[server.md](server.md#privileges-every-one). The Linux client broker is implemented
as described in [client.md](client.md#privileges-and-files); the Windows service and
online-enrollment listener (an unprivileged `lovpn-server enroll serve`, no capabilities)
is described in [enrollment.md](enrollment.md).


Linux uses narrow brokers with `CAP_NET_ADMIN` and, for client socket ownership,
`CAP_CHOWN` only where needed. Firewall/routing authority remains powerful;
capabilities are not a sandbox against a compromised broker. The M3 client unit uses
NoNewPrivileges, protected system/home paths, private temporary/device views, bounded
address families/syscalls and explicit writable state. systemd policy must
include NoNewPrivileges, read-only system paths, private temporary storage, bounded
address families/syscalls and explicit writable state paths. Do not enable
PrivateNetwork on a service that must manage host networking. Avoid blanket root
GUI use or shelling out using user-controlled arguments.

Authenticate Unix-socket callers via kernel peer credentials; authorize each
operation, not merely socket access. On Windows use service-SID-scoped ACLs and
named-pipe caller-token checks; do not trust a supplied username. Profile import
cannot choose arbitrary interfaces/files/capabilities without broker revalidation.
Bound request size and queue depth; stale generation requests fail without mutation.

## Keys and enrollment (key types and offline enrollment implemented)

Implemented: `lovpn-keys` (role-typed server/client keys, OS-random generation via
`getrandom`, X25519 via `x25519-dalek`, `zeroize` on drop, redacting `Debug`, strict
canonical-base64 parsing, rejection of low-order/non-canonical public keys and
unclamped private keys), Unix key files (0600, exclusive create, no symlinks/hard
links, owner and parent-directory checks), offline enrollment, and the Linux client
broker's root-owned profile/key store. Windows: the service creates the client key, seals it with DPAPI (machine scope) in an
ACL-protected directory and never shows it ([windows.md](windows.md)). Not implemented:
server key rotation, PSK delivery and management credentials. Online enrollment tokens
(SHA-256 digest at rest, 256-bit secrets, single use) are implemented.
Residual risks: a moved key value can leave an unscrubbed copy;
a pasted private key is shape-indistinguishable from a public key ~1/16 of the time,
so the server CLI asks for confirmation when the shape matches.


WireGuard uses its established Noise-based protocol and cryptographic suite
(Curve25519, ChaCha20-Poly1305, BLAKE2s and HKDF). LoVPN does not implement these.
Generate keys using maintained libraries/platform components and OS randomness.
Use separate zeroizing, non-serializable, redacted secret types; never put private
keys in argv, environment passed to child processes, logs or public configuration.
An optional WireGuard PSK is a distinct secret, not a substitute for identity.

Offline enrollment first: the device generates a key and sends only its public
key to the administrator. The administrator adds a peer and returns a public
profile containing a server key, literal endpoint, addresses and policy. Verify
the server key out of band. A QR code is a transport, not authentication.

Optional online enrollment (implemented, [enrollment.md](enrollment.md)) uses TLS 1.3
with an independently pinned certificate (SHA-256 over the certificate, distributed out
of band; SPKI pinning is not used). Use a mature TLS stack; never disable certificate
validation for a self-signed server. A minimum 256-bit random bearer token expires,
is revocable, is stored only as a cryptographic digest, and is consumed in the same
durable transaction as peer creation. Request bodies, URLs and access logs must not
expose tokens. Do not send client private keys. Bind a successful redemption to the
device public key; a lost response requires a safe recovery/reissue protocol, not
allowing token replay. Rate-limit before expensive operations. Wall-clock rollback
must not extend validity silently; reject inconsistent persisted time state.

Revocation removes the peer from the kernel and durable inventory, not merely from
the UI. Rotation is a staged, explicitly bounded transition; never indefinitely
accept old credentials. Server WireGuard and TLS identity rotation are separate.

## Storage and configuration

Implemented Linux locations (the offline foundation CLI alone does not create them):

| Data | Linux | Windows |
| --- | --- | --- |
| Public client profiles/settings | `/var/lib/lovpn-client/profiles` (root-owned broker store) | `%ProgramData%\LoVPN\profiles` (SYSTEM/Administrators only) |
| Broker policy, keys, journal | `/var/lib/lovpn-client` (client), `/var/lib/lovpn` (server) | `%ProgramData%\LoVPN`: DPAPI-sealed `*.key`, `session.json`, SYSTEM/Administrators ACL |
| Runtime IPC | `/run/lovpn-client/broker.sock` | `\\.\pipe\lovpn-client`, DACL + token check |
| Logs | rate-limited journal, no packet metadata | `%ProgramData%\LoVPN\logs\service.log` (1 MiB rotation), readable via `lovpn logs` |
| Diagnostic export | explicit user-selected destination | explicit user-selected destination |

Secret directories are mode 0700 and files 0600, owner-checked. Use systemd
credentials or an OS key store where feasible; unattended services still need a
documented key-unlocking model. DPAPI is paired with restrictive Windows ACLs.
Public profiles contain no private keys. Import treats every byte as untrusted;
normal import is not authorization for privileged mutation.

Privileged persistence must use handle-relative, no-follow directory traversal,
ownership/mode/ACL validation, private temporary files on the same filesystem,
flush → atomic rename → directory flush. Locks plus expected-generation checks
prevent lost updates. Symlink, reparse-point, hard-link, power-loss and concurrent
write tests block release. The M3 client implements bounded root-owned profile and
session writes with ownership/mode checks, atomic replacement and no-follow key and
session-record opens; its route cleanup also inspects the fixed policy table and
refuses to flush foreign routes. Real-host power-loss and upgrade matrices remain
open. Unknown schema versions fail;
there is no automatic downgrade or speculative migration. Add explicit tested
migrations only when a second supported schema exists.

## Logs and diagnostics

Support error/warn/info/debug/trace only with redaction at type boundaries. Never
log tokens, keys, passwords, packets, destinations, browsing history or DNS names.
Parser errors expose stable codes/field descriptions, not raw input snippets.
Sanitized reports exclude profile endpoints, addresses and names by default.
An unknown measurement is unknown, not healthy. Local stats remain local. No crash
reporting exists; any future exporter must be opt-in, inspectable and self-hostable.

## Updates and supply chain (planned; no updater in this milestone)

Use a maintained TUF implementation after dependency review, not a home-grown
signature protocol. Distinct offline root and release roles, threshold signing,
metadata expiration, artifact hashes/lengths, persisted highest accepted versions
and trust-root rotation are required. Reject unsigned or rolled-back releases.
Offline bundles use the same verifier; expired metadata requires an explicit
documented recovery process, not silently disabled checks. Mirrors are configurable
and self-hostable. Verification never means permission to execute an installer.

Commit Cargo.lock, pin direct dependencies and the tested Rust toolchain, audit
licenses/advisories, review dependency build scripts and generate an SPDX/CycloneDX
SBOM at release. CI must not mask audit failures. Do not claim an audit occurred
when tools/databases were unavailable. Target reproducible binaries and publish
provenance; do not claim reproducibility without independent matching builds.
