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

## Signing a release (tooling only)

`scripts/sign-release.sh <key> <outdir> <files…>` writes `SHA256SUMS` and signs it with
`ssh-keygen -Y sign` (namespace `lovpn-release`). `scripts/verify-release.sh <allowed_signers> <dir>`
checks the signature against a pinned signer file and then every hash. Both use only standard
tools; no bespoke cryptography. Tested with a throwaway key: a modified file and a modified
`SHA256SUMS` are both rejected.

Not decided by code, and therefore not done: who holds the release key, whether it lives on
hardware, how it is rotated or revoked, and how users obtain the pinned `allowed_signers`
out of band. There is still no updater (REL-01): update verification (offline roots,
thresholds, expiry, anti-rollback) must be designed and independently reviewed before any
auto-update ships. Until then, updates are manual downloads checked with the script above.

## Fuzzing status

Coverage-guided fuzzing (`cargo-fuzz`, nightly) is not set up. Instead, proptest covers the
config parser, enrollment protocol and tokens, the local HTTP parser, firewall rule
compilation, `ip -j` output parsers and key decoding (`crates/*/tests`).

## Evidence added in the completion pass

- Leak matrix (`tests/networking/client_e2e.py::leak_matrix`): underlay veths are captured while
  the client sends DNS (UDP/TCP 53), DoT, QUIC, mDNS, NetBIOS and ICMP to underlay and public
  destinations; only WireGuard to the endpoint may appear (control: WireGuard packets are seen).
- Windows reproducibility: `scripts/repro-check.ps1` (CI job `windows-reproducible`); two clean
  builds of lovpn-service, lovpn, lovpn-ui and lovpn-tray were byte-identical on the Windows VM.
- Provenance: `.github/workflows/release.yml` attests tagged builds. Not yet run (needs a tag on GitHub).
- Request decoding: serde does not enforce `deny_unknown_fields` on data-less operations (`ping`,
  `status`, `reset`, ...). They take no input, so an extra field changes nothing.
