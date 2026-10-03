# Protocol boundaries

LoVPN does not define a replacement VPN protocol. The encrypted data plane is
WireGuard and remains responsible for peer authentication, confidentiality and
replay protection. LoVPN configuration and management must not be confused with
WireGuard's cryptographic protocol.

## Planes

| Plane | Initial choice | Trust / status |
| --- | --- | --- |
| Data | WireGuard UDP and kernel/maintained platform implementation | Selected; isolated kernel tests only |
| Public profile | Versioned bounded TOML containing endpoint, public server key, tunnel addresses, routes, DNS and explicit policy | Implemented offline; no private keys |
| Local control | Authenticated Unix socket / Windows named pipe to a small privileged broker | Planned; no daemon yet |
| Optional enrollment | Offline public-key exchange first; future TLS 1.3 endpoint with out-of-band pin and one-time token | Planned; never required for core |
| Update metadata | Future signed, expiring, anti-rollback metadata | Planned; no updater |

## Public profile

The current schema is intentionally boring and explicit. It has no arbitrary
commands, hooks, scripts, plugin paths, remote includes, private keys, passwords or
opaque policy blobs. The parser caps input at 64 KiB, rejects unknown fields and
versions, validates literal endpoint addresses, and requires routing/DNS/IPv6 policy
to agree. It does not authenticate the server key; administrators must verify the
public key out of band until an enrollment system exists.

The synthetic file in `examples/client.toml` is for parser/policy tests. Its
documentation endpoint and public key are not credentials or a reachable server.

## Enrollment sequence (offline implemented; online planned)

The offline path (steps 1-4 below, with out-of-band key verification) is implemented
and tested; see [server.md](server.md). Steps 5-6 and online tokens are not
implemented; the online design is in [enrollment.md](enrollment.md).


1. The device creates its own WireGuard private/public key pair locally.
2. The administrator receives only the device public key through a deliberate local
   exchange or an authenticated, pinned enrollment channel.
3. The server allocates a non-overlapping address and records a peer generation.
4. The client receives a public profile containing the server public key, literal
   endpoint, address, policy and an explicit generation.
5. The client verifies the server key out of band, then asks its local broker to
   validate and apply the profile.
6. The broker verifies tunnel, route, resolver, firewall and handshake observations
   before exposing a Protected state.

Future online enrollment tokens are bearer capabilities only during their short
validity window. Store only a digest server-side; bind redemption to the device
public key; consume atomically; rate-limit and never log them. A QR code is a
transport encoding, not an authentication factor. Never transmit the device private
key.

## Versioning and downgrade behavior

The public schema carries a required version. Unknown versions fail closed; there is
no guessing or silent migration. Any future migration must be a bounded, separately
tested transformation that writes a new generation atomically and preserves a
recoverable previous state. A lower protocol/configuration generation is never
accepted merely because it parses.

## Compatibility discipline

WireGuard keys and profile policy are separate from management authorization, TLS
pinning and release signing. Rotating one identity does not silently rotate or
authorize another. Linux generic-netlink, nftables and resolver adapters and Windows
WireGuardNT/WFP/resolver adapters must each report their own capabilities; shared
configuration types do not imply shared enforcement.
