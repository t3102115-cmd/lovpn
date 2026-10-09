# Performance measurements (PERF-01)

`scripts/measure-performance.sh` builds release binaries and, in disposable user+network
namespaces (no sudo, no host change), connects the real `lovpn-clientd` to the real
`lovpn-server` over **kernel WireGuard on veth pairs on one machine**, then measures.

| Measure | Three runs |
|---|---|
| Connect (command until tunnel traffic flows) | median 0.20-0.21 s, worst 0.26 s |
| Reconnect (`lovpn reconnect` until traffic flows) | 5.6, 6.0, 6.0 s |
| Round trip through the tunnel, UDP echo | median 0.08-0.17 ms, p95 0.7-2.6 ms |
| TCP, 1 GiB, one stream, client to far side | 1566, 1639, 1658 Mbit/s |
| `lovpn-clientd` CPU during that transfer | 0.01 s |
| `lovpn-clientd` resident memory | 3.5-3.6 MiB |

Machine: Intel Core i7-10610U (8 threads), Fedora 44, kernel 7.2.8.

**What this means.** The data path is the kernel's WireGuard, not LoVPN code; LoVPN's own
process used almost no CPU while moving a gigabyte, and it is small. Connecting is fast
because everything is local. A reconnect takes about 6 seconds because the tunnel has to
re-handshake after the old session keys are dropped (WireGuard's rekey timeout is the floor;
this was not tuned).

**What this does not mean.** There is no real network here: no loss, no latency, no radio, no
second machine, no MTU or fragmentation effects, no NAT beyond the lab's, and no competing
traffic. Do not read these as internet speeds; a real link will be slower and more variable.
Nothing was measured on Windows (WireGuard-NT), on battery, or with many peers. The
**server's** cost with many clients is not measured. No performance claim beyond this table is
made anywhere in the project.
