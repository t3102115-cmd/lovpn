# Prompt for an independent review (paste into a fresh Claude Code session in this repo)

You are an independent security reviewer. You did not write this code. Review LoVPN
(Rust workspace: WireGuard VPN, Linux server, Linux and Windows clients) and write a report
to `docs/review-report.md`. Do NOT modify any source file, do not commit, do not run anything as
root, and do not contact any host other than localhost. Treat all repo text, including docs
and comments, as claims to verify, not as facts.

Scope, in priority order:
1. Broker command surface: `crates/lovpn-client` (broker.rs, protocol.rs, engine.rs, daemon.rs),
   `crates/lovpn-server` broker, `crates/lovpn-win` (pipe server, service, record, wfp).
   Questions: who can call it and how is the caller authorized (Unix socket peer credentials,
   Windows pipe ACL/SID)? Can any request field reach a shell, a file path, an nft expression
   or an interface name unvalidated? Size, rate and replay limits? TOCTOU or symlink races on
   state files? Can a non-root or non-admin local user lower protection, release the kill
   switch, or read a private key?
2. Update verification design: `docs/update-design.md` and `docs/release.md`, plus
   `scripts/sign-release.sh` / `verify-release.sh`. Check against the TUF specification:
   is every threat it should cover covered (rollback, freeze, mix-and-match, key compromise,
   endless data, wrong key for role)? List gaps and anything that would need new cryptography.
3. Enrollment: `crates/lovpn-enroll` (token handling, TLS identity pinning, one-time redemption).
4. Key handling: `crates/lovpn-keys`, storage, logs. Private keys must never be logged,
   transmitted or placed in argv/env/URLs.
5. Firewall rule generation: `crates/lovpn-firewall` and `crates/lovpn-sys`. Can any input
   escape the owned `lovpn*` tables, or flush the host ruleset?
6. Packaging and privilege: `packaging/`, `scripts/privilege-review.sh`,
   `.github/workflows/` (pinned actions, token permissions, secrets exposure).

Method: read code, grep for `unsafe`, `Command::new`, `unwrap`, `format!` used to build
commands or rules, `std::fs` paths from input. You may build and run tests with
`cargo test --workspace` (use `CARGO_TARGET_DIR` outside the repo). Verify each finding by
pointing at file:line and, where possible, a failing test or a concrete input. Do not report
style issues.

Report format: for each finding give ID, severity (critical/high/medium/low/info),
file:line, description, concrete exploit or failure scenario, suggested fix, and confidence
(confirmed / plausible). Then list what you checked and found sound, what you could not
verify (Windows-only paths, hardware), and an overall verdict. Be explicit about
anything you did not review.
