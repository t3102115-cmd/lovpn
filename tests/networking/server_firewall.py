"""Kernel validation of the lovpn-server nftables policy in a disposable namespace.

Run only inside `unshare --user --map-root-user --net` (see scripts/test-networking.sh).
Covers: kernel syntax acceptance, idempotent apply, drop-rule presence, and that the
reset removes only LoVPN-owned tables. Does NOT cover packet forwarding, NAT behavior,
WireGuard handshakes or the (unimplemented) privileged applier.
"""
import os
import subprocess
import sys
import tempfile

from peer import run


def require(condition, description):
    if not condition:
        raise AssertionError(description)
    print(f"PASS: {description}", flush=True)


def nft(*args, input_text=None):
    return subprocess.run(["nft", *args], check=True, capture_output=True,
                          text=True, input=input_text).stdout


def main(host_netns, server_binary, client_binary):
    require(os.readlink("/proc/self/ns/net") != host_netns, "server firewall test runs outside the host network namespace")
    run("ip", "link", "add", "eth0", "type", "dummy")
    run("ip", "link", "add", "lovpn-srv0", "type", "dummy")
    with tempfile.TemporaryDirectory() as root:
        os.chmod(root, 0o700)
        state = os.path.join(root, "state")
        key_file = os.path.join(root, "client.key")
        common = [server_binary, "--state-dir", state]
        subprocess.run([*common, "setup", "--write-state", "--endpoint", "192.0.2.10:51820",
                        "--pool", "10.66.0.0/24", "--wan-interface", "eth0", "--dns", "10.66.0.1"],
                       check=True, capture_output=True)
        public = subprocess.run([client_binary, "identity", "generate", "--key-file", key_file],
                                check=True, capture_output=True, text=True).stdout.split()[-1]
        subprocess.run([*common, "peer", "create", "--name", "a", "--public-key", public,
                        "--confirm-public-key"], check=True, capture_output=True)
        rules = subprocess.run([*common, "firewall", "show"], check=True, capture_output=True, text=True).stdout
        reset = subprocess.run([*common, "firewall", "show", "--reset-preview"], check=True,
                               capture_output=True, text=True).stdout

    nft("-c", "-f", "-", input_text=rules)
    require(True, "kernel nft accepts the generated server policy in check mode")
    nft("add", "table", "inet", "unrelated_table")
    nft("-f", "-", input_text=rules)
    first = nft("list", "table", "inet", "lovpn_server")
    nft("-f", "-", input_text=rules)
    require(nft("list", "table", "inet", "lovpn_server") == first, "re-applying the policy is idempotent")
    require("saddr !=" in first and "10.66.0.2" in first and "oifname != \"eth0\"" in first,
            "installed policy contains anti-spoof and uplink-only forwarding rules")
    require("masquerade" in nft("list", "table", "ip", "lovpn_server_nat"), "NAT table installed")
    require("policy drop" not in first, "server policy does not set a drop policy on host traffic")
    nft("-f", "-", input_text=reset)
    tables = nft("list", "tables")
    require("lovpn_server" not in tables and "unrelated_table" in tables,
            "reset removes only LoVPN-owned tables and leaves unrelated tables")


if __name__ == "__main__":
    main(*sys.argv[1:4])
