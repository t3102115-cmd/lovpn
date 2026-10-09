# Update verification design (REL-01) — NOT IMPLEMENTED, needs independent review

LoVPN has no updater. Updates are manual downloads verified with `scripts/verify-release.sh`.
Before any updater ships, this design must be reviewed by someone who is not its author. It
deliberately invents no cryptography: it adopts **TUF** (The Update Framework) metadata and an
existing, audited client rather than a bespoke protocol.

Requirements, taken from the roadmap:

1. **Offline root.** Root keys live offline (hardware tokens). The root is pinned in the installer.
2. **Threshold signing.** Root and targets roles need k-of-n signatures.
3. **Expiry.** Timestamp/snapshot metadata expires quickly; an expired set is refused.
4. **Anti-rollback.** The client stores the highest accepted version of each role and refuses lower.
5. **Compromise recovery.** Root rotation signed by old and new keys; documented revocation.
6. **No code from the network is executed without verification**, and never as an unprivileged
   background action: installation stays an explicit user step.

Open decisions (human, not code): which TUF client library to use and who audits it; who holds
the root keys; threshold values; hosting; how the first root is delivered out of band.

## Manual tooling today (review F-06)

`sign-release.sh` / `verify-release.sh` now sign a manifest with a version and an expiry, refuse
a version below the caller's minimum, and refuse unlisted files. They are still **not an
updater**: they keep no state (the user supplies the minimum version), have a single signer and
no threshold, no separate timestamp/snapshot role, and no key-compromise recovery beyond manual
rotation. A real updater needs TUF's role separation, threshold signatures and persisted
anti-rollback state, reviewed independently.
