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

## M3 client additions and residuals

- **Client broker abuse:** `lovpn-clientd` is root with only `CAP_NET_ADMIN` and
  `CAP_CHOWN` in its unit, fixed absolute tools and strict peer-credential IPC.
  A compromised broker is nevertheless root-equivalent for host networking. The
  controlling owner is intentionally authorized to disconnect/reset and lift the
  kill switch; this is recovery authority, not protection from that account or root.
- **Profile/key exposure:** profiles and client keys are stored root-owned under
  `/var/lib/lovpn-client`, not in the user's home. The CLI sends the import request
  over the 0600 socket; the service keeps its own key copy. Uninstall retains this
  state and never silently deletes profiles.
- **Crash, interface loss and resume:** the broker records desired state, installs
  the deny policy before the tunnel and re-arms it on restart; the monitor repairs
  owned state and nudges stale handshakes. This is covered in namespace tests and in the
  Fedora 44 VM gate (real systemd, reboot, ACPI suspend/resume, SIGKILL; frames captured
  outside the guest), not by multi-adapter or physical-hardware evidence.
- **DHCP/DNS/IPv6 scope:** IPv4 DHCP renewal is an explicit firewall exception, not
  a managed DHCP lifecycle. Managed DNS is only the systemd-resolved per-link path;
  unmanaged DNS is degraded; real systemd-resolved was exercised in the VM gate, resolver fallback and multiple adapters were not. IPv6
  endpoints, IPv6 tunnel mode, NDP/RA, LAN bypass and split routing are rejected or
  unavailable. No production leak claim follows from the M3 implementation.
- **Route-table collision:** the client uses a fixed policy-routing table number, which
  is a convention rather than kernel ownership. Cleanup now inspects the table and
  removes only the recorded default route on the broker-created interface. Any extra
  or foreign route causes a refusal and leaves the session desired/repairable; the
  implementation no longer flushes the whole table. A separate LoVPN instance or a
  privileged local process can still create a race, which is outside the broker's
  hostile-root boundary.
- **Privileged session-record tampering:** client session records are opened without
  following symlinks and require a regular single-link file owned by the broker with
  safe mode and bounded size. This is defense in depth around the root-owned state
  directory, not protection from root.

## M2c enrollment additions and residuals

- **Token theft or guessing:** 256-bit secrets, at most 24 h life, single use, stored only
  as SHA-256 digests, compared in constant time; wrong, unknown, expired, revoked and
  replayed tokens get the same answer. Online guessing is bounded per source (5 failures
  per 15 min with 30 s to 1 h back-off) and globally (60 per 15 min), enforced before TLS
  and persisted across restarts. Residual: an attacker who can *see* the token (shoulder,
  chat history, pin channel) before the legitimate user redeems it wins the race; deliver
  it over a channel you trust and keep lifetimes short.
- **Rogue or intercepted server:** the client pins the certificate and verifies the
  handshake signature before sending anything; a wrong pin aborts with no token sent.
  Residual: a pin obtained over a hostile channel authenticates the attacker; the
  channel for the pin is the administrator's responsibility.
- **Replay and lost responses:** an identical retry within 10 minutes returns the same
  profile and creates nothing; any other key is refused. Residual: within that window
  someone holding both the token and the same public key gets the public profile (not a
  secret).
- **Denial of service:** one connection is handled at a time with a 10 s deadline, so a
  patient attacker can delay legitimate enrollments, but per-source and global budgets
  throttle repeated failures and idle sockets count as failures. Residual: a spoofable
  or NAT-shared source address shares a budget; the listener is not a hardened public
  web service, so expose it only for the enrollment window if you can.
- **Service user compromise:** can forge tokens or peers (the service user administers
  peers); the listener itself holds no capability and no root.
- **Log and error leakage:** logs carry event classes, token ids and peer ids only; tests
  scan real process output for tokens, secrets, client keys and addresses.

## Review checkpoint

At each milestone inspect cryptography, key lifetime, privileges, route/DNS/IPv6
escape paths, configuration trust, update rollback, network disclosures and whether
the UI can overstate protection. Record evidence and unresolved risks in development
notes. Until both platform leak suites pass, no production security claim is made.
