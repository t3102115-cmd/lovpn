# Independent review report: LoVPN

Scope and method follow [independent-review-prompt.md](independent-review-prompt.md). This review
read code and docs, grepped for risky patterns, and ran the workspace test suite offline. It did
not modify any source file, did not commit, did not run anything as root, and did not contact
any host other than localhost. Repo text, including docs and comments, was treated as a claim to
verify.

Reviewed commit: `10df4cd` (branch `main`). The working tree had one uncommitted change at the
start (`packaging/windows/Initialize-State.ps1`, a `-Force` flag added on line 7). It was read and
judged sound; no other file was changed.

## Summary

No critical or high-severity issue was confirmed on Linux. The strongest code paths are the
client and server brokers (peer credentials per operation, strict schemas, validated names before
any command or nft text is built), the TLS-pinned enrollment (pin checked before the token is
sent, single-use redemption inside the locked store commit), and the key files (`O_EXCL`,
`O_NOFOLLOW`, owner and mode checks).

The most important open item is a Windows install-time command lookup (F-01). It is plausible and
has not been run on Windows. The most important design gap is that the owner UID or user on
Linux, or the owner SID on Windows, can lift the kill switch and redirect traffic to any
endpoint. This is documented as accepted, but the documentation understates the consequence
(F-02). The Linux server broker treats the unprivileged service user's `state.json` as root-applied
input (F-03).

## Findings

| ID | Severity | Confidence | Where | Summary |
|----|----------|------------|-------|---------|
| F-01 | Medium | plausible (Windows, not run here) | `crates/lovpn-win/src/host.rs:131` | Elevated installer runs `powershell` by bare name; the returned SID becomes the pipe owner. |
| F-02 | Medium (design) | confirmed | `crates/lovpn-client/src/broker.rs:33-40`, `crates/lovpn-client/src/profiles.rs:9-11`, `crates/lovpn-win/src/daemon.rs:202-203` | Any process running as the owner can release the kill switch and import a profile with an attacker-chosen server key and endpoint. |
| F-03 | Medium (design) | confirmed | `crates/lovpn-server/src/broker.rs:79-87`, `crates/lovpn-server/src/state.rs:98-104,190-195`, `crates/lovpn-server/src/applier.rs:318-330,436-438` | Root broker applies firewall, forwarding and interface config from state written by the unprivileged service user. |
| F-04 | Low | confirmed (static) | `crates/lovpn-firewall/src/lib.rs:137` | The DHCP exception `udp sport 68 dport 67` has no destination restriction. |
| F-05 | Low | confirmed | `crates/lovpn-server/src/limits.rs:103-107,120-122`, `crates/lovpn-server/src/enroll_server.rs:199-201` | 60 cheap failures from one source block enrollment for every source for up to one hour. |
| F-06 | Medium (design, no code yet) | confirmed | `docs/update-design.md`, `scripts/verify-release.sh:6-8`, `scripts/sign-release.sh:10-15` | The update design and release tooling lack several TUF protections; a validly signed old release verifies. |
| F-07 | Low | confirmed | `.github/workflows/release.yml:13-18` | `id-token: write` and `attestations: write` are granted to the whole build job, including steps that run repo scripts and dependency build scripts. |
| F-08 | Low | plausible | `crates/lovpn-win/src/store.rs:228-232` | `take()` builds a slice from `pbData` even when `cbData == 0` (possibly null). |
| F-09 | Low | confirmed | `crates/lovpn-win/src/pipe.rs:134-145`, `crates/lovpn-win/src/daemon.rs:289-305` | Named-pipe reads have no timeout, so one connected owner-or-admin client can stall the single-threaded accept loop. |
| F-10 | Info | confirmed | `crates/lovpn-sys/src/ipc.rs:38-56` | Socket bind is path-based (`symlink_metadata`, `remove_file`, `bind`, `set_permissions`, `chown`). Not exploitable under the shipped units, because `/run/lovpn-*` is root-owned. |

### F-01: Elevated install resolves `powershell` by bare name (Medium, plausible)

`current_user_sid()` runs `Command::new("powershell")` (`crates/lovpn-win/src/host.rs:131`) in the
elevated `lovpn-service install` path, when `--owner-sid` is not given (`host.rs:143-144`). The
returned SID becomes the pipe owner and the state-directory owner check (`daemon.rs:202-203`,
`pipe.rs:59`).

Failure scenario: `CreateProcessW` searches the application directory, then the current directory,
then the system directories, then `PATH`. An administrator who runs the installer from a
user-writable folder that contains a planted `powershell.exe` runs that file elevated. The file can
print the attacker's own SID, which then receives owner-level pipe rights. Owner rights include
`disconnect release` and `connect` with an attacker profile (see F-02).

`crates/lovpn-win/src/dns.rs:110` already uses an absolute System32 path for the same kind of
call. Fix: use `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`, or read the SID with
`GetTokenInformation` on the current process token and drop the subprocess. Confidence is plausible
because the search-order behavior is standard Windows behavior but was not exercised on Windows
here.

### F-02: The owner can lift the kill switch and redirect traffic (Medium, design)

On Linux, every operation, including `import-profile`, `connect`, `disconnect release` and
`reset`, is allowed to the socket's owner UID (`broker.rs:38-40`). Windows is the same for the
owner SID (`daemon.rs:202-203`). The code comments state this as a deliberate choice: "a
compromised user account can lift the kill switch; the kill switch defends against network leaks,
not against a hostile local user."

Two consequences go beyond the stated trade-off:

1. `import-profile` takes `expected_server_key` from the caller (`protocol.rs:44-49`,
   `profiles.rs:105-112`). The profile header describes that key as "obtained out of band", and
   says a tampered profile looks like a server-key mismatch (`profiles.rs:9-11`). A process running
   as the owner can supply both the profile and the expected key, so the out-of-band pin protects
   only against tampering of stored files, not against a same-user process. Any owner-UID process
   can therefore send all traffic through an endpoint it controls and lift the kill switch with
   `reset`.
2. The kill switch is one line of defense against leaks by the owner's own applications, not
   against code running as the owner.

Suggested fix, not a blocker: state this in `docs/security-model.md` at the same prominence as the
kill-switch claim. Consider a second factor for `import-profile` and for `release`/`reset` (for
example, requiring root, or a confirmation token from the UI). Confidence: confirmed by code.

### F-03: The root broker trusts the service user's state (Medium, design)

The server broker runs as root. `Op::Apply` is allowed to the service user
(`crates/lovpn-server/src/broker.rs:79-87`). It reads `state.json` from the state directory that
user owns (`store.rs:77-90`, `store.rs:152-168`) and applies it: `ip link add ... type wireguard`,
`ip addr`, `sysctl`-style writes to `ip_forward`, and nft rules built from `interface` and
`wan_interface` (`applier.rs:318-330`, `firewall/src/server.rs:105-142`).

`ServerState::validate` checks interface names only for charset and length (`state.rs:98-104`,
`190-195`). The server does not require the `lovpn` prefix that the client requires
(`crates/lovpn-config/src/validate.rs:40-41`). It does check ownership of existing links
(`applier.rs:300-305`), refuses foreign tables (`applier.rs:262-268`) and never runs a shell.

Failure scenario: a compromised `lovpn-server` account can write `state.json` with
`wan_interface` set to any non-LoVPN interface name, enable forwarding, and masquerade the VPN pool
out of that interface. It can also create a WireGuard link with an arbitrary name that is not
`lovpn*`. The damage is network-level, not code execution, but the service user is effectively a
network administrator. The docs should say so.

Suggested fix: require the `lovpn` prefix for the server interface, derive `wan_interface` from
the current default route at apply time, or keep the owner-writable state from being applied
without an administrator's explicit commit. Confidence: confirmed by code.

### F-04: DHCP exception is not destination-restricted (Low)

`crates/lovpn-firewall/src/lib.rs:137` emits
`output meta nfproto ipv4 udp sport 68 udp dport 67 counter accept` with no `ip daddr`. The
comment at lines 119-121 (`IPv4 DHCP client traffic (udp 68 -> 67)`, "No LAN, NDP or other
exceptions") and the docs say DHCP only. The
rule therefore lets any UDP packet from source port 68 to port 67 at any destination leave the host
outside the tunnel. Only a process that can bind privileged port 68 (root or `CAP_NET_BIND_SERVICE`)
can produce such a packet, so the exposure is limited. The traffic is a covert channel that
bypasses the kill switch.

Suggested fix: limit the destination to the broadcast address and to the DHCP server address, if
the lease provides it. Otherwise document the rule as "any destination on udp 68→67". Confidence:
confirmed by reading; not exercised.

### F-05: Enrollment global budget allows a one-source denial of service (Low)

`Limits::failure` records every failure against the global budget (`limits.rs:118-120`).
`Limits::check` then blocks every source while the global bucket is blocked (`limits.rs:103-107`).
The global budget is 60 failures per window, and the block doubles to one hour. Handshake failures
count as failures (`enroll_server.rs:199-201`), so 60 cheap TCP connections that never complete a
handshake from one address block enrollment for everyone, repeatedly. Enrollment is one-time, so
the impact is limited to delayed enrollments. The design choice is deliberate and documented in
`limits.rs:1-8`.

Suggested fix: keep the per-source budget, and either drop the global block or apply it only to
the bucket that failed redemptions (not handshake failures). Confidence: confirmed by reading.

### F-06: Update design and release tooling are not TUF-complete (Medium, design)

`docs/update-design.md` lists requirements and defers the design. `scripts/verify-release.sh` checks
one SSH signature over `SHA256SUMS`, then each listed hash. Against the TUF threat list:

- **Rollback and freeze:** `SHA256SUMS` carries no version, timestamp or expiry, so any validly
  signed old release verifies. A timestamp role with expiry would cover freeze.
- **Mix-and-match:** nothing binds the set of files to one release. A snapshot role or a version
  field in the signed metadata would cover this.
- **Endless data:** no length limit is given for any file, and no hash is required for the
  metadata itself.
- **Extra files:** `sha256sum --check` ignores files in the directory that are not listed.
- **Wrong key for role:** there is one signing identity (`-I lovpn-release`), with no per-role key
  separation and no threshold (the design asks for k-of-n).
- **Key compromise and rotation:** deferred to humans (`docs/release.md:61-64`). Root rotation in
  TUF needs versioned root metadata signed by old and new keys.
- **Trust bootstrap:** the design says the root is "pinned in the installer", but installers are
  unsigned (`docs/release.md:30-31`), so the pin is only as strong as the download channel.

Nothing here needs new cryptography. TUF already defines these roles and checks, and an existing
audited client exists, as the design itself says. The gaps are in the design, which has no code
yet. Fix: adopt TUF's roles and metadata formats before any updater ships, and until then, add
at least a signed version and an explicit list of allowed files to `SHA256SUMS`, and fail on extra
files. Confidence: confirmed by reading.

### F-07: Release job grants OIDC and attestation write to all build steps (Low)

`.github/workflows/release.yml:13-18` gives the `linux` job `id-token: write` and
`attestations: write`. The same job runs `repro-check.sh` and `cargo build`, so dependency build
scripts and repo scripts run with the ability to request an OIDC token and mint attestations.
Attestations prove only where an artifact was built, so a malicious build step could still produce
a valid attestation for a malicious binary.

Fix: move the attestation step into a separate job that downloads the built artifacts and has the
two write permissions, and keep the build job at `contents: read`. Confidence: confirmed by reading.

### F-08: Zero-length `CRYPT_INTEGER_BLOB` output (Low)

`take()` (`crates/lovpn-win/src/store.rs:228-232`) calls
`std::slice::from_raw_parts(output.pbData, output.cbData as usize)` even when `cbData` is zero.
Rust requires a non-null pointer even for empty slices, and DPAPI may return a null pointer with
zero length. Fix: return an empty `Vec` when `cbData == 0`. Confidence: plausible; not run on
Windows.

### F-09: Named-pipe reads have no timeout (Low)

`Connection::read_line` loops on a blocking `ReadFile` (`crates/lovpn-win/src/pipe.rs:134-145`),
and the daemon's accept loop is single-threaded (`daemon.rs:289-305`). A connected client can
hold the loop without sending a newline. The DACL limits connections to SYSTEM, administrators and
the owner, so the effect is self-inflicted. It still matters because the monitor cannot serve
requests while it waits. Fix: use overlapped I/O with a timeout, or a per-connection thread.
Confidence: confirmed by reading.

### F-10: Socket binding is path-based (Info)

`ipc::bind` (`crates/lovpn-sys/src/ipc.rs:38-56`) checks, removes, binds, then sets mode and owner
by path. A racing process with write access to the socket's directory could swap the path between
steps. The shipped units prevent this: `RuntimeDirectory=` creates `/run/lovpn-*` owned by root
with mode 0755, and `UMask=0077` keeps the socket private from creation. The code relies on that
directory layout without saying so. Fix: document the requirement, or use `fchmod`/`fchown` on the
bound descriptor. Confidence: confirmed by reading.

## Checked and found sound

- **Client broker authorization and transport:** the socket is `0600`, owned by the configured
  user, and each connection is checked with `SO_PEERCRED` (`lovpn-sys/src/ipc.rs:59-63`,
  `broker.rs:105-158`). Requests are capped at 96 KiB, have I/O timeouts, and are parsed with
  `deny_unknown_fields` (`protocol.rs:37-39`). The Linux daemon refuses to start unless the state
  directory is root-owned and mode 0700 (`profiles.rs:35-47`, `daemon.rs:88-100`), and restores
  protection before the socket is bound (`daemon.rs:118-126`).
- **No request field reaches a shell, file path or nft text unvalidated:** profile names are
  restricted to `[a-z0-9_-]`, max 32 (`model.rs:99-108`). Tunnel interface names must begin with
  `lovpn` and use `[A-Za-z0-9_-]`, max 15 (`lovpn-config/src/validate.rs:40-46`). The server key
  is canonical base64 of 32 bytes (`validate.rs:29-38`). Command execution uses fixed binaries from
  a fixed directory list, `env_clear`, no shell, and secrets on stdin (`lovpn-sys/src/exec.rs`).
  Grep found no `sh -c` and no string-built commands in scope.
- **Profile import and storage:** names are validated before any path is built
  (`profiles.rs:101-103`). Writes use `create_new`, reads use `O_NOFOLLOW` and check `nlink`,
  owner and mode (`profiles.rs:63-91`, `121-134`). Partial writes are removed on failure
  (`profiles.rs:137-141`).
- **Firewall tables and flush:** every generated batch creates or deletes only `inet lovpn*` and
  `ip lovpn*` tables (`firewall/src/lib.rs:111-150`, `server.rs:105-142`), and an existing table
  without the LoVPN owner comment causes refusal (`applier.rs:262-268`,
  `engine.rs:276-279`). The proptest suite checks hostile interface names (`firewall/tests`).
- **Server anti-rollback:** the record lives in a root-owned 0700 directory
  (`applier.rs:213-223`, `tmpfiles`), and `apply` refuses lower generations (`applier.rs:268-270`).
  `teardown` removes only LoVPN-named tables and interfaces it recorded (`applier.rs:444-484`).
- **Server state reads:** `open_as` requires the owner and mode 0700, refuses symlinks, and
  `read_file` uses `O_NOFOLLOW` with `nlink == 1` and no group or other bits
  (`store.rs:77-90`, `124-150`).
- **Key handling:** keys are zeroized (`lovpn-keys/src/lib.rs:204-208`), `Debug` is redacted
  (`lovpn-keys/src/lib.rs:210-214`), `expose_base64` returns a `Zeroizing` string
  (`lovpn-keys/src/lib.rs:282-284`), and the key file is written with `O_EXCL|O_NOFOLLOW`
  (`lovpn-keys/src/file.rs:90-119`). The CLI sends the key through a zeroized request buffer
  (`lovpn-sys/src/ipc.rs:113-116`). Logs carry operation, uid and code only (`broker.rs:71-73`).
  Keys go to `wg` through stdin, not argv (`engine.rs:336-341`, `applier.rs:195-206`).
- **Enrollment token and TLS:** tokens carry 256 bits from the OS RNG; the server stores only a
  SHA-256 digest, compared in constant time (`token.rs:125-135`, `enroll.rs:248-264`). Unknown and
  wrong-secret tokens take the same path (`enroll.rs:248-264`). TLS 1.3 only, with one pinned
  certificate; the pin is checked before any application data is sent (`tls.rs:120-135`,
  `262-271`). Redemption re-checks state inside `Store::update`, so the single-use check is atomic
  (`enroll_server.rs:267-283`, `enroll.rs:248-264`). The line reader is bounded
  (`lovpn-enroll/src/proto.rs:90-115`).
- **Windows pipe:** the DACL grants SYSTEM and Administrators full control and the owner only
  read/write without `FILE_CREATE_PIPE_INSTANCE` (`pipe.rs:36,59`). The access-mask arithmetic is
  correct: `0x120083` is SYNCHRONIZE, READ_CONTROL, FILE_READ_ATTRIBUTES, FILE_WRITE_DATA and
  FILE_READ_DATA. The first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, and remote
  clients are rejected (`pipe.rs:96`). The caller is identified from its impersonated token
  (`pipe.rs:157-235`). `owner_sid` is validated against `S-1-` digits before it is put into SDDL
  (`daemon.rs:58-63`), so SDDL injection through the owner SID is not possible.
- **Windows store and WFP:** the state directory must be a non-reparse-point owned by SYSTEM or
  Administrators, and its DACL is protected (`store.rs:58-75`, `30`, `114-149`). The client key is
  sealed with DPAPI machine scope and a fixed entropy label, and the plaintext is zeroized
  (`store.rs:180-226`). WireGuardNT is hash-checked before load (`driver.rs:19`, `111-131`).
  WFP enumeration filters on the LoVPN provider key, so teardown removes only LoVPN filters
  (`wfp.rs:507-530`, `616-626`).
- **Release workflow:** actions are pinned by commit SHA, `persist-credentials: false` is set, and
  the top-level token is read-only (`release.yml:9-10,20-22`). The offline signing key is not in
  CI.
- **Signing tooling:** `ssh-keygen -Y` with namespace `lovpn-release` prevents the signature from
  being reused in another namespace. The key path is never printed or copied (`sign-release.sh:4`).
  `sha256sum --check --strict` rejects malformed lines.
- **Dependency and panic hygiene in scope:** no `unwrap` or `expect` outside tests in the broker,
  engine, store, enrollment, keys, sys, pipe and daemon files reviewed. The `unsafe` blocks in
  `lovpn-win` are wrapped with SAFETY notes and were read for the pipe, store and WFP paths.

## Not reviewed, or reviewed only in part

- `crates/lovpn-ui`, `crates/lovpn-tray`, `crates/lovpn-cli` beyond the key-import path, and
  `crates/lovpn-server/src/cli.rs` and `state.rs` export code. The UI passes a random session token
  in a `cmd /c start` URL (`lovpn-ui/src/main.rs:210`). That token is visible in process command
  lines, which was not assessed.
- `crates/lovpn-win/src/driver.rs`, `wfp.rs` internals, `dns.rs`, `ip.rs`, `engine.rs` and
  `policy.rs`, read only where they touch the pipe, store or teardown paths.
- `packaging/` (MSI WXS, Windows service ACLs) beyond `Initialize-State.ps1`, and
  `scripts/privilege-review.sh`.
- `scripts/sbom.py`, `scripts/repro-check.*` and `tests/` harnesses, except for the claims in
  `docs/release.md`.
- Anything that requires Windows, the Windows VM, hardware, a real WireGuard peer or root. Nothing
  here was exercised on Windows. The Windows findings (F-01, F-08, F-09) are read-only.
- Coverage-guided fuzzing: none was run (the project itself says none is set up).

## Test evidence

Command (run offline, as the normal user, `CARGO_TARGET_DIR` in the session scratchpad, not the
repo):

```
cargo test --workspace --locked --offline --no-fail-fast
```

Result: exit code 0. 43 test result blocks, all `ok`; 223 tests passed, 0 failed, 0 ignored.
Windows-only crate code (`lovpn-win`, `lovpn-tray` Windows paths, `cfg(windows)` modules) is
compiled out on Linux and was not run. No failing test was found, so no test was added or changed.
The suite shows the existing invariants hold (for example, the protocol robustness, firewall
property and enrollment robustness tests), but it does not test the specific gaps above. Each
finding is a code-reading result, not a failing test; the report gives a concrete scenario for
each one.

## Overall verdict

The Linux brokers, enrollment and key handling are carefully built, and the main properties the
prompt asked about hold: the caller is authenticated per operation, names are validated before
they reach commands, and nothing is flushed outside LoVPN's own tables. Nothing confirmed here is
a critical or high-severity issue on Linux.

Before the next release, I would fix F-01 (a one-line change with a clear security effect), F-07
(a workflow split), and F-04 (one rule). I would also decide and document F-02 and F-03, since
they are design choices that change what the product's protection means, and I would not ship an
updater until F-06 is designed against TUF. The Windows side needs a Windows-hosted review of F-01,
F-08 and F-09 and of the install flow, because those paths were only read here.


## Resolution status (maintainer, after review)

| Finding | Status |
| --- | --- |
| F-01 | Fixed in `host.rs`: absolute System32 PowerShell path (same as `dns.rs`). Builds and passes clippy and tests on Windows; not exercised in an elevated install. |
| F-02 | Open by design: the owner account can lift the kill switch. Documented in `docs/threat-model.md`; a stronger model (separate admin approval) is a product decision. |
| F-03 | Mitigated: the server tunnel interface must start with `lovpn` (regression test). `wan_interface` is still taken from the owner-writable state; documented as network-admin-equivalent. |
| F-04 | Open, documented: unicast DHCP renewal needs the server address, which the firewall does not know. The rule is limited to root-bound UDP 68 to 67. |
| F-05 | Fixed: only refused-token attempts count against the global budget; handshake failures and malformed requests are limited per source only (regression test). |
| F-06 | Open: the update design lists the missing TUF protections; `verify-release.sh` is for manual installs only and must not be used as an updater. |
| F-07 | Fixed: attestation moved to its own job; the build job has `contents: read` only. |
| F-08 | Fixed: empty DPAPI output no longer builds a slice from a possibly null pointer. |
| F-09 | Fixed: each request line must arrive within 5 s (watchdog cancels the blocked read with `CancelIoEx`). Test `pipe_deadline.rs` passes on Windows: a silent client is dropped after about 5 s and the next client is served. |
| F-10 | Info. |
