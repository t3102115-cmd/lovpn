# Contributing to LoVPN

LoVPN handles network and privilege boundaries. Small, reviewable changes with
evidence are preferred over broad scaffolding.

## Before a change

1. Read the relevant architecture, threat, security and networking documents.
2. Check the current working tree and preserve unrelated work.
3. Define the user-visible behavior, failure state and security property.
4. Explain new dependencies, privileges, outbound connections and platform limits.
5. Never use real private keys, enrollment tokens, passwords or live endpoints in
   tests, examples, logs, screenshots or commits.

## Coding rules

- Rust is the primary implementation language; use strong types and `Result`.
- Keep unsafe code out unless the platform boundary requires it and the block is
  narrowly documented, reviewed and tested.
- Do not shell out with user-controlled arguments. Do not implement cryptography.
- Revalidate at every trust/privilege boundary; reject unknown configuration fields.
- Security-sensitive errors must not echo input or secrets.
- Separate desired state, applied generation and observed protection state.
- Do not add UI toggles for unavailable behavior.
- Keep Linux and Windows adapters explicit; a cross-platform enum is not evidence
  that both platforms implement the behavior.

## Checks

Run the smallest meaningful checks while developing, then the full applicable set:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
python3 scripts/check-docs.py
./scripts/test-networking.sh       # Linux, disposable namespaces only
```

Native Windows contributors should run `scripts/build-windows.ps1`. Security and
dependency checks must not be described as passing if their tools or advisory data
were unavailable. Never run firewall experiments in the host namespace.

## Pull requests and commits

Use focused conventional commits such as `feat(server): add peer inventory`,
`security: reject unsafe route policy`, `test(network): cover reconnect`, or
`docs: clarify trust boundary`. A PR should state:

- what changed and why;
- files and platform scope;
- exact commands and results;
- untested paths and remaining security risk;
- any new network connection, privilege or dependency.

Reviewers should challenge claims of protection, resource ownership, rollback and
recovery—not just compile success.
