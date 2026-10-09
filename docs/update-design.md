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
