# LoVPN

> Your VPN should not require trusting a VPN company.

LoVPN (**Local Only**) is an open-source, self-hostable VPN project for connecting
devices to VPN servers operated by you or your organization. The planned data plane
is WireGuard; LoVPN is intended to add a safer, easier management and operating-system
integration layer around it, not to replace its cryptography.

## Honest status

This repository is an **M3 implementation slice**, not a production VPN release. It
currently provides:

- strict schema-v1 public profile parsing with bounded input and sanitized errors;
- deterministic Linux nftables full-tunnel policy generation for laboratory review;
- an unprivileged CLI for validation, policy previews, privacy and capability reports;
- real isolated Linux-kernel tests using WireGuard and nftables;
- a **Windows client** (service, WireGuardNT, WFP kill switch, DPAPI keys) verified in a Windows 11 VM, see [`docs/windows.md`](docs/windows.md);
- a **window** (`lovpn-ui`) for Windows and Linux, see [`docs/ui.md`](docs/ui.md);
- native Windows Rust build, test and clippy coverage;
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
  an install/uninstall script exist (run as real services in the VM gate).

The M3 slice also includes a Linux `lovpn-clientd` root broker and unprivileged `lovpn`
CLI with full IPv4 tunnel lifecycle, an owned nftables kill switch, fail-closed policy
routing, optional systemd-resolved per-link DNS, reconnect/restart recovery and staged
packaging. The client gate exercises these paths in disposable namespaces, and
`tests/linux-vm` runs the server broker, the enrollment listener and the client broker as
**real systemd services** on two Fedora 44 virtual machines (enforcing SELinux, real
systemd-resolved and NetworkManager, real reboots and ACPI suspend/resume, leaks measured
from outside the guest; see [`docs/development.md`](docs/development.md#real-host-gate--2026-10-07)).

M3 is still not a production claim: the real-host evidence is one distribution (Fedora 44),
virtual NICs, one uplink and no IPv6 underlay, hardware Wi-Fi, rogue DHCP/RA or
Debian/Ubuntu run. M3 rejects IPv6 endpoints and tunnel mode, split routing,
LAN bypass and NDP/RA; unmanaged DNS is explicitly degraded. The owner can explicitly
release the kill switch. Online enrollment (pinned TLS, one-time tokens) exists for the Linux server and the CLI
client ([`docs/enrollment.md`](docs/enrollment.md)). There is a tray icon (Linux and Windows) but no updater, and the
Windows client has only been run in one VM (see [`docs/windows.md`](docs/windows.md#limits-and-what-is-not-evidenced)). See
[`docs/server.md`](docs/server.md) for the exact boundaries,
[`docs/client.md`](docs/client.md),
[`docs/feature-matrix.md`](docs/feature-matrix.md) and
[`docs/roadmap.md`](docs/roadmap.md).

## Principles

- No LoVPN account, subscription, developer-operated VPN backend or mandatory cloud.
- Zero telemetry and advertising by default; no hidden analytics or crash reporting.
- Self-hostable on a private LAN or public Internet, once the server milestone lands.
- WireGuard and established platform cryptography, never a custom VPN protocol.
- Least privilege: the window and the CLI run as the user and use a small authenticated privileged service.
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

On Windows, from a native PowerShell checkout, use `scripts/build-windows.ps1`, then
`scripts/install-client.ps1` (see [`docs/windows.md`](docs/windows.md)). The Windows runtime
scenario is `tests/windows/vm-e2e.ps1`; a Linux cross-target check is not a Windows test.
Audit and license checks are described in CI and [`docs/development.md`](docs/development.md).

## Planned user flow

1. Install the Linux server and review a dry-run setup plan.
2. Generate a server identity and a device enrollment package.
3. Import the public profile on a Linux or Windows client; the client key stays local.
4. Import and connect after observed routing, DNS and firewall state are reviewed.
5. Revoke or rotate devices locally; recover or uninstall only LoVPN-owned state.

No email registration is part of that flow. Optional future directory/enrollment
services must be independently deployable and never a core dependency.

## Project map

```text
crates/lovpn-config       bounded public configuration and validation
crates/lovpn-keys         WireGuard key types, redaction, protected key files
crates/lovpn-firewall     pure nftables policy compilers (client and server)
crates/lovpn-server       Linux server state, peers, offline enrollment (lovpn-server)
crates/lovpn-client       Linux root broker (lovpn-clientd), lifecycle and recovery
crates/lovpn-cli          offline client CLI (lovpn), incl. identity generation
tests/networking          disposable kernel enforcement tests
docs                      architecture, security, networking and roadmap
```

## License and security

LoVPN is MIT licensed. See [`SECURITY.md`](SECURITY.md) for responsible disclosure,
[`CONTRIBUTING.md`](CONTRIBUTING.md) for development rules, and
[`docs/security-model.md`](docs/security-model.md) for the security boundary. Do not
send private keys, enrollment tokens or sensitive network data in an issue.
