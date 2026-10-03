# Security policy

LoVPN is early-stage software. The current repository is not a production VPN and
must not be relied on for traffic-leak prevention. The implemented foundation has no
privileged service, live enrollment, GUI, update executor or production key store.

## Supported versions

There is no supported production release yet. Development snapshots are useful for
review and testing only. The exact implementation status is in
[`docs/feature-matrix.md`](docs/feature-matrix.md); an unchecked roadmap item is not
implemented behind a hidden flag.

## Reporting a vulnerability

Until a private security contact is published, report vulnerabilities through the
repository's private security advisory mechanism if available. If it is unavailable,
open a minimal public issue titled **Private security contact needed** without
including exploit details, secrets, private keys, enrollment tokens, live endpoints,
or personal/network data. Maintainers should establish a private contact before
requesting sensitive reproduction material.

Include only the minimum reproducible information:

- affected revision and platform;
- security impact and threat assumptions;
- safe reproduction steps or a redacted test;
- whether a real system, key or network was exposed.

Do not test against systems you do not own or have permission to test. Do not attempt
to bypass a user's kill switch, access a server, or exfiltrate credentials.

## Architecture overview

The target data plane is WireGuard. The target control plane is a local,
caller-authenticated IPC service with a small privileged broker for network, firewall
and resolver operations. The GUI and CLI are not intended to run with root or
Administrator privileges. Public profiles are bounded and reject unknown fields,
executable hooks, unsupported routes and ambiguous DNS/IPv6 policy.

The foundation's nftables compiler is pure and non-executing. Its generated rules
are tested in disposable Linux namespaces, but that evidence does not prove host
protection. A future broker must verify interface provenance and table ownership,
serialize generations, apply atomic transactions, persist boot-time policy, and
report observed state rather than desired state.

## Cryptography

LoVPN does not implement cryptographic primitives. The design uses WireGuard's
established protocol and maintained platform/library implementations. Future
enrollment requires independently distributed TLS identity/pinning and one-time,
expiring, revocable tokens; client private keys must never be uploaded. Release
verification will use independently reviewed signed metadata rather than a custom
update signature protocol.

## Known limitations

LoVPN cannot make a compromised client/server OS trustworthy, provide anonymity,
prevent a server operator from observing egress traffic, stop traffic correlation,
protect applications that implement their own network stack, or automatically
handle unsupported DNS/IPv6/OS states. A self-hosted VPN transfers trust; it does
not remove it. See [`docs/threat-model.md`](docs/threat-model.md).

Current state (M2b): the only privileged component is the Linux server broker
(`lovpn-server broker`), which applies server state and has been tested in disposable
namespaces but never run as a systemd service on a real host. There is no client
lifecycle, no client kill switch/DNS/IPv6 protection and no Windows or GUI component.
Online enrollment is a design only. See [`docs/server.md`](docs/server.md).

## Security claims

Do not describe LoVPN as unhackable, anonymous or military-grade. A feature may be
called protected only after its implementation and independent failure/leak tests
support that exact claim on a named platform and configuration.
