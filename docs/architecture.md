# LoVPN architecture

Status: architecture accepted for an initial implementation; **not a released VPN**.
Implementation truth lives in [feature-matrix.md](feature-matrix.md) and test evidence
in [development.md](development.md). Design statements below are requirements, not
claims that a backend already exists.

## Purpose and trust

LoVPN means Local Only: the client connects to a server chosen and operated by its
user or organization. No LoVPN account, directory, license server, analytics,
advertising, or developer-operated control plane is required. Public Internet and
isolated intranet operation must use the same core flow. Local Only does not mean
traffic never leaves the LAN, nor that a self-hosted exit hides its operator's IP.

First complete user flow: install a Linux server, review setup changes, enroll a
device with locally generated keys, import its public profile on Linux or Windows,
connect with verified routing/DNS/firewall state, reconnect without bypass, revoke
the device, and recover or uninstall without disturbing unrelated networking.

## Decisions

1. **WireGuard data plane.** Linux kernel WireGuard via generic netlink; evaluate
   WireGuardNT's documented API for Windows. Wintun alone is only a TUN driver, not
   an encryption implementation. Do not write a new tunnel or cryptography. Driver
   license, redistribution, signature and supported-version review block shipping.
2. **Rust control plane.** A small privileged broker owns device, route, firewall
   and resolver operations. CLI and GUI never run as root/Administrator. Platform
   adapters consume typed, validated policy rather than scripts supplied by a UI.
3. **Local management by default.** Linux Unix sockets with peer-credential checks;
   Windows named pipes with explicit ACLs and caller-token authorization. No local
   unauthenticated TCP control API. Remote management is off by default.
4. **Separate identities.** WireGuard keys identify tunnel peers. A separately
   pinned TLS identity authenticates optional enrollment; release signing keys and
   local IPC authorization are not reused as tunnel keys.
5. **No shell hooks.** Imported profiles contain no pre/post-up commands, executable
   paths, plugins, arbitrary nft expressions or arbitrary privileged file paths.
6. **Typed evidence.** Desired policy, applied generation and observed protection
   are different objects. Missing, stale or contradictory evidence means unknown
   or degraded, never Protected. A handshake alone proves neither routing nor DNS.
7. **No online behavior in the foundation CLI.** It parses public profiles and
   prints policies and honest capability reports. It cannot connect or install
   rules. It is intentionally not a simulation of a working tunnel.

## Boundaries and repository shape

| Component | Responsibility | Authority |
| --- | --- | --- |
| `lovpn-config` | Bounded, versioned public configuration and semantic validation | No networking, secrets or system writes |
| `lovpn-firewall` | Deterministic, constrained nft policy compiler | No process execution or rule installation |
| `lovpn-cli` | Offline validation, policy inspection, privacy/capability output | Unprivileged |
| Linux client (`lovpn-clientd` + `lovpn`) | Lifecycle/reconnect orchestration and profiles | Calls a narrow authenticated broker API; M3 full IPv4 slice |
| Future Windows broker | Reconcile owned OS resources, verify state | Minimum platform privileges |
| Future server | Peer inventory, address leases, enrollment and health | Separate management and networking authority |
| Future key store | OS-backed private key creation/access | Accessible only to relevant broker/identity owner |
| Future update verifier | Offline signature/metadata checks | No automatic installer execution |
| Future GUI | Accessible presentation and explicit consent | No direct networking privilege |

Start with three real crates, not twelve empty ones. Split a crate when an actual
privilege boundary or dependency boundary warrants it. Keep adapters testable with
injected OS observations, but never expose mock observations in production status.

## M2a components

`lovpn-keys` (key types/files), `lovpn-server` and the server compiler in
`lovpn-firewall`. `lovpn-server` is split by privilege:

- unprivileged, no process execution: pure state model (`state`), locked atomic store
  (`store`), CLI (`cli`);
- privileged, the only code that executes anything: `applier` (fixed-argv `ip`/`wg`/`nft`,
  ownership checks, rollback of partial applies, observation) behind `broker` (Unix
  socket, peer credentials, per-operation authorization, bounded strict requests).

The CLI never changes host networking itself: it asks the broker. The policy compilers
(`lovpn-firewall`, `state::render_profile`) stay pure and are tested without privileges;
the applier is tested with a fake host (unprivileged) and with the real kernel in
namespaces. The Linux client-side broker (WireGuard link, routes, kill switch, resolver
adapter) is implemented in M3; real-host/systemd/resolved evidence remains open. The
Windows service (`lovpn-win`) implements the same lifecycle with WireGuardNT, IP Helper and
persistent WFP filters ([windows.md](windows.md)); the pure policy compiler is shared in
spirit with the Linux one and tested on every platform.

## Lifecycle and persistence

The broker is the sole writer for its state. Serialize changes with a bounded
request queue; include schema version, request ID and expected generation in IPC.
Authorize the caller before parsing complex payloads, bound message size, disallow
arbitrary path/command parameters, and never pass secrets in argv or error strings.

Connection transaction: validate → install persistent deny policy → verify policy
→ configure endpoint exception/device/routes/DNS → verify observed state → publish
Connected/Protected. On any partial failure, retain deny policy, undo only newly
owned resources, and publish Blocked with an actionable recovery reason. Journal
intent and committed generation using atomic, permission-checked persistence.

On resume, interface change or service restart, invalidate old observations and
reconcile while blocked. Never flush the host ruleset. Kernel firewall enforcement
must outlive the GUI and daemon. Boot-time enforcement and Windows boot-time WFP
filters require separate tests; persistent runtime filters alone are insufficient.

## GUI decision

**Decided and implemented: a loopback-only local web app (`lovpn-ui`)**, described in
[ui.md](ui.md). The candidates below were weighed first. Tauri needs WebKitGTK/WebView2
and a JavaScript toolchain; egui and iced need platform accessibility work and a large
native dependency tree. A small server plus a plain page needs no new native dependency,
gets platform accessibility, and one UI serves both systems; its extra attack surface (a
local HTTP listener) is handled explicitly in ui.md. Original comparison, kept for the
record:

| Candidate | Strengths | Costs / security considerations |
| --- | --- | --- |
| Tauri 2 | Mature desktop integration; HTML accessibility/localization tooling | Webview dependencies, JS supply chain, tightly scoped IPC/CSP; no remote UI |
| egui/eframe | All-Rust, fast iteration, minimal web attack surface | Consumer forms, screen-reader/platform accessibility and tray need validation |
| iced | Rust-native declarative UI and clear message flow | Platform integration and accessibility need a prototype on supported OS versions |

**Superseded: Tauri 2 was the provisional preference and was not adopted.** Select only after keyboard/screen-reader/high-contrast, offline asset,
Linux webview packaging, Windows WebView2 offline installation, and privilege
boundary prototypes pass. Fedora inspection found no GTK3/WebKitGTK development
packages. Do not install a frontend now. Bundle fonts/icons locally, deny remote
web content, allowlist IPC methods, and keep strings in localization resources.

## Extension limits

An optional directory is a separately deployable, opt-in signed manifest service;
publishing a server exposes metadata and does not make it trusted. Import remains
possible offline. No automatic discovery or probing of third parties.

Lo Security and LoOS may consume sanitized local events through a versioned,
least-privilege interface. Neither receives tunnel private keys. No antivirus,
operating system, additional platform or additional protocol is part of this work.
