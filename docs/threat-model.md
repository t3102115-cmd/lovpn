# Threat model

Status: design and release criteria; controls not explicitly marked implemented in
[feature-matrix.md](feature-matrix.md) remain unimplemented. Review after every
privilege, protocol, storage, dependency or routing change.

## Assets and boundaries

- Client/server private keys, separate TLS identity and release root keys.
- Public configurations whose integrity controls routing, DNS and endpoints.
- Traffic and DNS confidentiality/integrity between device and chosen server.
- Enrollment tokens, device identity, address leases and revoked-peer state.
- Firewall state, route state, resolver state and their crash-safe journals.
- Local diagnostic metadata and any exported report.

Boundaries: untrusted imported bytes → validator; GUI/CLI → authenticated broker;
broker → OS/kernel/driver; enrollment connection → pinned server; server tunnel →
LAN/Internet; release bytes → offline verifier. A UI is not an authority source.

## Adversaries, controls and required evidence

| Adversary / scenario | Desired property and control | Required tests |
| --- | --- | --- |
| Hostile Wi-Fi/Internet interception | WireGuard authenticates configured peer; TLS pin authenticates enrollment | Wrong peer/pin, MITM, captive portal and endpoint changes |
| Malicious LAN DHCP/RA/DNS | No fallback DNS/data bypass; tightly scoped bootstrap traffic | Spoofed RA, DHCP changes, rogue DNS, multiple adapters |
| Compromised VPN server | No remote code/config execution; local policy retains authority | Malicious profile, routes, DNS and management responses |
| Compromised unprivileged local process | No broker command injection/arbitrary writes; IPC caller authorization | Unauthorized UID/SID, oversized messages, replay/stale generation |
| Fully compromised client OS/admin | Outside prevention boundary; minimize retained secrets | Document limit; audit key access and crash dumps |
| Malicious configuration | Bounded strict parsing; typed addresses and identifiers; no hooks | Unknown fields/versions, malformed and oversized data, injection/fuzzing |
| Token thief/replay attacker | Short lifetime, hashed storage, atomic one-time redemption, revocation | Expiry boundary, race, replay, crash during redemption, rate limits |
| Supply-chain attacker | Locked dependencies, provenance, signed update metadata, anti-rollback | Wrong signature/role/version, expiry/freeze, truncated artifact |
| Administrator error | Dry run, explicit changes, no global flush, scoped rollback | Existing firewall/VPN, route conflicts, partial failure, reset |
| Service or UI crash | Persistent kernel deny policy; recovery begins blocked | Kill daemon/UI, reboot, restart, socket failure, resume |

## Security goals

Authenticate the intended server and peers; protect tunnel traffic against the
intermediate network; prevent unintended bypass when protection is requested;
retain configuration and key integrity; disclose all application network contacts;
avoid retaining browsing/packet metadata. Fail closed on unsupported protection,
with an explicit local-console recovery procedure.

## Non-goals and residual risks

- This is not anonymity software. The ISP sees a tunnel endpoint/timing/volume;
  the server sees inner traffic and DNS as routed. Destination TLS still matters.
- A malicious server can drop/correlate traffic and inspect unencrypted egress.
  Owning a server transfers trust; it does not eliminate trust in hosting or OSes.
- Root/Administrator or a compromised kernel can read keys and bypass filters.
  Same-user malware may read unprivileged memory; encryption at rest is not a cure.
- No protection against phishing, malicious downloads, endpoint malware, traffic
  correlation, a compromised browser, or traffic before boot-time enforcement.
- Loopback is a local exception. A malicious local proxy with another egress path
  is not defeated merely by permitting loopback. Containers, forwarding, raw L2,
  alternate namespaces and other VPNs require separate coverage or explicit refusal.
- OS update checks and other applications' connections are not LoVPN telemetry.
  The Privacy page must distinguish LoVPN-generated connections from OS activity.
- Denial of service and physical seizure cannot be eliminated. Debug logs/exported
  reports can reveal metadata; sanitize and require deliberate export.

## M2a additions

- **Secret pasted as a public key**: a client private key given to the administrator.
  Mitigation: clamped-shape confirmation, never printing private keys in the client
  flow; residual: confirmation can be bypassed by a careless admin.
- **State tampering or rollback**: write access to the state directory can swap or
  restore state. Mitigations: 0700/0600 + owner checks, full revalidation on load,
  atomic writes; the broker keeps the highest applied generation in a root-only
  directory and refuses older state (tested, including that a restored pre-revocation
  state does not re-enable the revoked peer). Residual: the service user (or anyone
  with write access to the state directory) can still forge a *newer* valid state, so
  the service user is trusted for peer administration; if the broker's record is lost
  the counter resets.
- **Address reuse after revoke**: leases are quarantined, never reused; keys burned.
- **Peer spoofing / lateral movement through the server**: the installed policy drops
  non-lease sources and peer-to-peer forwarding. Peer isolation was verified with real
  traffic and the dropping rule's counter; the anti-spoof rule is only checked for
  presence (WireGuard's cryptokey routing already rejects spoofed sources).
- **Revocation enforcement**: now applied to the live interface by `apply`/`--apply`
  and verified with real traffic; a failed apply leaves the previous configuration and
  reports the failure. Until applied, state and host differ and `status --live` says so.
- **Broker abuse**: a local user trying to drive the broker. Mitigations: 0600 socket
  owned by the service user, kernel peer credentials checked per operation
  (`teardown` root-only), strict 4 KiB schema, no paths/commands/interfaces in
  requests, fixed-argv tools without a shell. Residual: a compromised service user can
  still `apply` states it can write; a compromised broker is root-equivalent for networking.
- **Collision with existing network state**: LoVPN modifies only an interface it created
  and tables bearing its ownership marker, and refuses same-named foreign ones.
  Residual: `ip_forward` is a host-wide setting that LoVPN enables and later restores.

## Review checkpoint

At each milestone inspect cryptography, key lifetime, privileges, route/DNS/IPv6
escape paths, configuration trust, update rollback, network disclosures and whether
the UI can overstate protection. Record evidence and unresolved risks in development
notes. Until both platform leak suites pass, no production security claim is made.
