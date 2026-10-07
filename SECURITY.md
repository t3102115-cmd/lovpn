# Security policy

LoVPN is early-stage software. The current repository is not a production VPN and
must not be relied on for traffic-leak prevention on an untested host. M3 includes
Linux privileged brokers and a first Windows client service and window, but not a
production service, live enrollment, update executor or tray. The Windows client was run
in one VM only ([`docs/windows.md`](docs/windows.md)).

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

The data plane is WireGuard. The Linux control plane now has local,
caller-authenticated IPC services with small privileged brokers for network, firewall
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

Current state (M3): Linux has a root `lovpn-server` broker and a root `lovpn-clientd`
broker. The client owns a marked nftables kill switch, full IPv4 policy routing,
WireGuard lifecycle and an optional systemd-resolved link configuration. Both service
units have static checks, namespace evidence and a Fedora 44 virtual-machine gate
(real systemd services, enforcing SELinux, real systemd-resolved, NetworkManager restart
and DHCP renewal, real reboot ordering and ACPI suspend/resume, with leaks measured from
outside the guest). Other distributions, physical NICs, several uplinks, rogue DHCP/RA and
NetworkManager-managed tunnel interfaces remain untested. IPv6 endpoints,
IPv6 tunnel mode, split routing, LAN bypass and NDP/RA are rejected or unavailable;
unmanaged DNS is reported degraded. The controlling owner can explicitly lift the
client kill switch, so it is not a defense against that account or root. Online
enrollment (pinned TLS, one-time tokens) is implemented for the Linux server and the CLI; the Windows client and window are verified only as described
in [`docs/windows.md`](docs/windows.md) and [`docs/ui.md`](docs/ui.md). See [`docs/client.md`](docs/client.md)
and [`docs/server.md`](docs/server.md).

## Security claims

Do not describe LoVPN as unhackable, anonymous or military-grade. A feature may be
called protected only after its implementation and independent failure/leak tests
support that exact claim on a named platform and configuration.

## Windows and the window: additional trust notes

- Windows runs the service as LocalSystem with the `unsafe` code confined to the
  `lovpn-win` crate. Administrators and SYSTEM are inside the trust boundary: the DPAPI
  machine-scope key, the state directory and the WFP policy are protected from other
  users, not from administrators. A compromised service, Administrator account or kernel
  is out of scope.
- The WireGuardNT DLL is pinned by SHA-256 and signature and loaded from an
  Administrator-only directory; the installer refuses anything else. Updating it requires
  changing the pin in source after review.
- `lovpn-ui` is unprivileged and loopback-only; it authenticates the browser with a
  per-launch secret, checks `Host` and `Origin`, and sends a strict CSP. A malicious
  process running as the **same user** can still read the window's URL from its command
  line or process memory and drive the same actions that user can already take.
