# LoVPN

> Your VPN should not require trusting a VPN company.

LoVPN (**Local Only**) is an open-source, self-hostable VPN project for connecting
devices to VPN servers operated by you or your organization. The planned data plane
is WireGuard; LoVPN is intended to add a safer, easier management and operating-system
integration layer around it, not to replace its cryptography.

## Honest status

This repository is an **offline security foundation**, not a production VPN client or
server. It currently provides:

- strict schema-v1 public profile parsing with bounded input and sanitized errors;
- deterministic Linux nftables full-tunnel policy generation for laboratory review;
- an unprivileged CLI for validation, policy previews, privacy and capability reports;
- real isolated Linux-kernel tests using WireGuard and nftables;
- Windows-native Rust build, test and clippy coverage in the available VM;
- architecture, threat model, security model, networking design and release gates.

- (M2a) WireGuard-compatible key handling with zeroizing, redacting types and
  protected key files; a Linux `lovpn-server` that manages server identity, an IPv4
  address pool and peers (create/list/export/revoke/rotate) in atomic, locked,
  generation-checked state, and **offline enrollment**: the client generates its key
  locally and only its public key reaches the server.
- (M2b) A privileged **server broker** (authenticated Unix socket, peer-credential and
  per-operation authorization, anti-rollback record) that applies server state to a
  Linux host: WireGuard interface and peers, forwarding, and LoVPN-owned nftables
  tables, with observed drift reporting, firewall repair and scoped teardown. Revocation
  and key rotation take effect on the live interface. Verified end to end with real
  WireGuard, two peers and NAT in a disposable namespace; a hardened systemd unit and
  an install/uninstall script exist (never run as a real service).

It does **not** yet include a client that connects: there is no Linux client lifecycle,
kill switch, DNS or IPv6 protection on the client side, no Windows client, no GUI, no
online enrollment, and the broker has not been run as a systemd service on a real host.
The CLIs deliberately report protection as `not-verified`. See
[`docs/server.md`](docs/server.md) for the exact boundaries,
[`docs/feature-matrix.md`](docs/feature-matrix.md) and
[`docs/roadmap.md`](docs/roadmap.md).

## Principles

- No LoVPN account, subscription, developer-operated VPN backend or mandatory cloud.
- Zero telemetry and advertising by default; no hidden analytics or crash reporting.
- Self-hostable on a private LAN or public Internet, once the server milestone lands.
- WireGuard and established platform cryptography, never a custom VPN protocol.
- Least privilege: GUI/CLI will use a small authenticated privileged broker.
- Fail closed for requested protection, with documented recovery paths.
- No fake toggles: a security control is not exposed as working until implemented,
  tested, documented and integrated.

Local-only operation does not make a user anonymous. A self-hosted server operator
can observe traffic exiting that server, and the ISP can observe the tunnel endpoint,
timing and volume. See [`docs/threat-model.md`](docs/threat-model.md).

## Try the current foundation

Requirements: Rust 1.97.1 or newer compatible stable toolchain, Linux or Windows for
the Rust workspace, and a regular readable profile file. The sample uses documentation
addresses and a synthetic public key; it is not a usable server identity.

```bash
cargo test --locked --workspace
cargo run --locked -p lovpn-cli -- config validate examples/client.toml
cargo run --locked -p lovpn-cli -- status
cargo run --locked -p lovpn-cli -- privacy --json
cargo run --locked -p lovpn-cli -- firewall show examples/client.toml --reset-preview
```

Offline enrollment walk-through: [`docs/server.md`](docs/server.md). Design for online
enrollment and the privileged broker: [`docs/enrollment.md`](docs/enrollment.md).

The firewall command prints a static lab policy only. It does not invoke `nft`, inspect
the host, install rules or prove a kill switch. Never apply the sample or generated
policy to a host or remote machine.

## Development checks

```bash
./scripts/test.sh                 # Rust tests and local documentation links
./scripts/lint.sh                 # fmt and clippy with warnings denied
./scripts/build-linux.sh          # Linux release workspace build
./scripts/test-networking.sh      # disposable namespaces; Linux only
```

The Windows VM has native Rust tests, clippy and release-build coverage. From a native
PowerShell checkout, use `scripts/build-windows.ps1`. A Linux cross-target check is
not a Windows service, WFP, driver or leak test. Audit and license checks are described
in CI and [`docs/development.md`](docs/development.md).

## Planned user flow

1. Install the Linux server and review a dry-run setup plan.
2. Generate a server identity and a device enrollment package.
3. Import the public profile on a Linux or Windows client; the client key stays local.
4. Connect after verified routing, DNS and firewall state are observed.
5. Revoke or rotate devices locally; recover or uninstall only LoVPN-owned state.

No email registration is part of that flow. Optional future directory/enrollment
services must be independently deployable and never a core dependency.

## Project map

```text
crates/lovpn-config       bounded public configuration and validation
crates/lovpn-keys         WireGuard key types, redaction, protected key files
crates/lovpn-firewall     pure nftables policy compilers (client and server)
crates/lovpn-server       Linux server state, peers, offline enrollment (lovpn-server)
crates/lovpn-cli          offline client CLI (lovpn), incl. identity generation
tests/networking          disposable kernel enforcement tests
docs                      architecture, security, networking and roadmap
```

## License and security

LoVPN is MIT licensed. See [`SECURITY.md`](SECURITY.md) for responsible disclosure,
[`CONTRIBUTING.md`](CONTRIBUTING.md) for development rules, and
[`docs/security-model.md`](docs/security-model.md) for the security boundary. Do not
send private keys, enrollment tokens or sensitive network data in an issue.
