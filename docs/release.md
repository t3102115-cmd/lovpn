# Release hardening (M6): what exists and what does not

## Dependencies and licences (REL-02, partly)

* `Cargo.lock` is committed and every CI/build command uses `--locked`; dependency versions
  in `Cargo.toml` are exact (`=`).
* `cargo audit --deny warnings` and `cargo deny check` (advisories, bans, licences, sources)
  run in CI. Allowed licences are in `deny.toml`; `Unlicense` was added for `ksni` (tray).
* **SBOM:** `scripts/sbom.py [--target TRIPLE] -o FILE` writes a CycloneDX 1.5 JSON of every
  crate in `Cargo.lock` for that target (versions, licences, SHA-256 of each registry crate).
  Linux: 210 components, Windows MSVC: 131. It reads `cargo metadata`, so it needs no extra tool
  and no network. It does **not** include the WireGuard-NT driver DLL (a separate download with
  its own licence, [windows.md](windows.md)) and says nothing about vulnerabilities.

## Reproducible builds (REL-02, partly)

`scripts/repro-check.sh` builds the five Linux binaries twice in different directories with
path remapping and `--locked`, then compares SHA-256. **Result on the development machine:
identical for `lovpn-server`, `lovpn`, `lovpn-clientd`, `lovpn-ui`, `lovpn-tray`.** The claim
is limited to the same source, lockfile, toolchain (`rust-toolchain.toml`, 1.97.1) and
machine type. Not shown: other distributions, other CPUs, other Rust builds, or Windows. A CI
job repeats the check on Ubuntu 24.04.

## Not done, and why it is not faked

* **REL-01 update verification.** LoVPN has no updater, so there is nothing to verify and no
  update channel to trust. A TUF-style design (offline root, threshold signing, expiry,
  anti-rollback) is a cryptographic protocol that needs independent review before code; it was
  not written. Users update by installing a new package they verified themselves.
* **Signing keys, provenance, signed packages.** Nothing is signed. There is no release key,
  no custody procedure, no signed `.deb`/`.rpm`/MSI, and no build attestation. The hashes
  above are the only integrity evidence a reader can currently check.
* **Independent security review.** None has happened.

## Tests for hostile input (QA-02, partly)

Property tests (proptest, `cargo test`), not coverage-guided fuzzing:

* `lovpn-enroll/tests/robustness.rs`: arbitrary bytes never panic any enrollment parser; line
  reads never exceed their limit or read past the newline; a changed token never redeems the
  original record (the id is only a lookup handle; the digest covers the secret); unknown
  request fields are refused.
* `lovpn-ui` HTTP parser: arbitrary bytes and single-byte mutations of a valid request never
  panic or exceed the limits.
* `lovpn-firewall/tests/properties.rs`: for hostile interface names and server policies the
  compiler refuses or emits only statements on LoVPN's own tables, never `flush ruleset`.
* `lovpn-config`: arbitrary text, existing.

Not done: `cargo-fuzz` (needs nightly, not installed), fuzzing the WireGuard config text, the
broker JSON protocol and the Windows pipe protocol, state-machine property tests, and the
DNS/IPv6/routing leak matrix beyond the existing namespace and VM gates.

## Signing a release

`scripts/sign-release.sh <key> <outdir> <version> <valid-days> <files…>` writes `MANIFEST` (a
`version:` line, an `expires:` date, then `sha256sum` lines) and signs all of it with
`ssh-keygen -Y sign` (namespace `lovpn-release`). `scripts/verify-release.sh <allowed_signers>
<dir> [min-version]` refuses a bad signature, an expired manifest, a version below `min-version`
(the script keeps no state: pass the highest version you ever accepted), a changed file and any
file the manifest does not list. Standard tools only; no bespoke cryptography. Tested with a
throwaway key (valid, rollback, extra file, tampered file, edited manifest, expired).

### Key custody procedure (maintainer steps)

1. Generate the release key on a hardware token, offline machine: `ssh-keygen -t ed25519-sk
   -C lovpn-release -f lovpn-release` (touch required). Keep a second token as backup in a
   different place. Never put the key in CI, a cloud drive or chat.
2. Publish only the public part as `allowed_signers`: `lovpn-release <contents of lovpn-release.pub>`.
   Put it in the repository **and** on a second channel (project website, a signed git tag, a
   printed fingerprint) so users can compare. Users pin it on first install.
3. Sign each release on the offline machine: build artifacts from the tagged CI run, download
   them, run `sign-release.sh` with the next integer version and about 90 days, attach
   `MANIFEST`, `MANIFEST.sig` and the artifacts to the release.
4. Rotation or loss: generate a new key, publish its public part on both channels with a note
   signed by the old key if it still exists, and announce which version is the first signed by the
   new key. Revoke by removing the old line from `allowed_signers` and raising the minimum version.

CI attests *where* a binary was built (build provenance); the maintainer signature says *who
approved it*. Neither replaces the other. There is still no updater (REL-01): see
[update-design.md](update-design.md).

## Fuzzing status

Coverage-guided fuzzing is set up: `scripts/fuzz.sh [seconds]` (libFuzzer through `cargo-fuzz`,
nightly) runs five targets in `fuzz/`: WireGuard/profile config text, the enrollment wire format
and tokens, the broker/pipe request decoder, `ip -j` output parsers and key text. A 60 s run of
each (about 12 million executions in total) found no crash. CI job `fuzz` repeats it. This is a
short smoke run, not a long campaign; a long run before each release is recommended. Proptest
(`crates/*/tests`) still covers the same parsers plus firewall compilation.
