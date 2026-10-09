# Privilege review (QA-02)

Mechanical part, repeatable: `scripts/privilege-review.sh` scores each shipped systemd unit with
`systemd-analyze security --offline` and fails above 4.0. Measured on this tree:

| Unit | Exposure |
| --- | --- |
| `lovpn-clientd.service` | 2.4 |
| `lovpn-server-broker.service` | 2.8 |
| `lovpn-server-enroll.service` | 1.7 |

`lovpn-clientd` runs with `NoNewPrivileges=yes`, `CapabilityBoundingSet=CAP_NET_ADMIN CAP_CHOWN`,
no ambient capabilities and `ProtectSystem=strict`. The CLI, window and tray never run as root
or Administrator. Windows: the service runs as LocalSystem; its pipe ACL and the WFP filters are
described in [windows.md](windows.md). `unsafe` is confined to `lovpn-win` and the Windows part
of `lovpn-tray`, every block with a SAFETY comment (clippy-enforced).

Not covered: a human review of the broker command surface by someone other than the author, and
Windows token/ACL review beyond the author's tests. Both are listed as open in the roadmap.
