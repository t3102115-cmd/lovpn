"""Real kernel policy tests inside disposable namespaces, never the host.

Uses kernel WireGuard with memory-only test keys. Does NOT test LoVPN's future
broker, DNS resolver configuration, persistence, enrollment or default routing.
"""
import errno
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile

from peer import install_key, run

PAYLOAD = b"lovpn-isolated-packet-test"


def require(condition, description):
    if not condition:
        raise AssertionError(description)
    print(f"PASS: {description}", flush=True)


def wait_line(process, expected):
    if not select.select([process.stdout], [], [], 10)[0]:
        raise RuntimeError("Isolated peer did not respond within 10 seconds")
    if process.stdout.readline().strip() != expected:
        raise RuntimeError("Isolated peer could not start; no credentials printed")


def udp_echo(address, port=9999, mark=None):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        if mark is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
        try:
            sock.sendto(PAYLOAD, (address, port))
            return sock.recv(4096) == PAYLOAD
        except (TimeoutError, PermissionError):
            return False


def denied_send(address, port, mark=None):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        if mark is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
        try:
            sock.sendto(PAYLOAD, (address, port))
        except OSError as error:
            return error.errno in (errno.EPERM, errno.EACCES)
        return False


def compile_plan(binary, profile):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml") as file:
        file.write(profile)
        file.flush()
        result = run(str(binary), "firewall", "show", file.name, "--json")
    return json.loads(result.stdout)


def apply(batch, check=False):
    args = ["nft", "-f", "-"]
    if check:
        args.insert(1, "--check")
    return run(*args, input=batch.encode())


def normalize(value):
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items()
                if key not in {"handle", "counter", "metainfo"}}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return value


def own_table():
    return normalize(json.loads(run("nft", "-j", "list", "table", "inet", "lovpn_client").stdout))


def set_peer(server_public):
    run("wg", "set", "lovpn0", "fwmark", "0x4c6f", "peer", server_public,
        "allowed-ips", "10.66.0.1/32,fd66::1/128", "endpoint", "192.0.2.1:51820")


def setup(process):
    for command in [
        ("ip", "link", "set", "lo", "up"),
        ("ip", "link", "add", "wan0", "type", "veth", "peer", "name", "peer0"),
        ("ip", "link", "set", "peer0", "netns", str(process.pid)),
        ("ip", "addr", "add", "192.0.2.2/24", "dev", "wan0"),
        ("ip", "-6", "addr", "add", "2001:db8::2/64", "dev", "wan0", "nodad"),
        ("ip", "link", "set", "wan0", "up"),
        ("ip", "route", "add", "default", "via", "192.0.2.1"),
        ("ip", "link", "add", "lovpn0", "type", "wireguard"),
        ("ip", "addr", "add", "10.66.0.2/32", "dev", "lovpn0"),
        ("ip", "-6", "addr", "add", "fd66::2/128", "dev", "lovpn0", "nodad"),
    ]:
        run(*command)
    client_private = run("wg", "genkey").stdout
    server_private = run("wg", "genkey").stdout
    client_public = run("wg", "pubkey", input=client_private).stdout.decode().strip()
    server_public = run("wg", "pubkey", input=server_private).stdout.decode().strip()
    install_key("lovpn0", client_private.decode())
    process.stdin.write(json.dumps({"server_private": server_private.decode(),
                                    "client_public": client_public}) + "\n")
    process.stdin.flush()
    del client_private, server_private
    wait_line(process, "configured")
    set_peer(server_public)
    run("ip", "link", "set", "lovpn0", "up")
    run("ip", "route", "add", "10.66.0.1/32", "dev", "lovpn0")
    run("ip", "-6", "route", "add", "fd66::1/128", "dev", "lovpn0")
    return server_public


def exercise(binary, server_public):
    require(udp_echo("192.0.2.1"), "IPv4 underlay reachable before policy")
    require(udp_echo("2001:db8::1"), "IPv6 underlay reachable before policy")
    require(udp_echo("10.66.0.1"), "real WireGuard IPv4 traffic before policy")
    require(udp_echo("fd66::1"), "real WireGuard IPv6 traffic before policy")
    existing = socket.create_connection(("192.0.2.1", 9998), timeout=2)
    existing.sendall(PAYLOAD)
    require(existing.recv(4096) == PAYLOAD, "pre-policy established TCP baseline")

    sample = Path("examples/client.toml").read_text()
    sample = sample.replace("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", server_public)
    block = compile_plan(binary, sample)
    dual_sample = sample.replace('["10.66.0.2/32"]', '["10.66.0.2/32", "fd66::2/128"]')
    dual_sample = dual_sample.replace('["0.0.0.0/0"]', '["0.0.0.0/0", "::/0"]')
    dual_sample = dual_sample.replace('ipv6 = "block"', 'ipv6 = "tunnel"')
    dual = compile_plan(binary, dual_sample)
    apply("add table inet unrelated_test\nadd chain inet unrelated_test sentinel\n")
    apply(block["ruleset"], check=True)
    require(True, "generated nft batch passes real-kernel validation")
    apply(block["ruleset"])
    apply(block["ruleset"])
    run("nft", "list", "chain", "inet", "unrelated_test", "sentinel")
    require(True, "repeated atomic apply preserves unrelated firewall table")

    # Clear the old session, so success needs a new handshake through the policy.
    run("wg", "set", "lovpn0", "peer", server_public, "remove")
    set_peer(server_public)
    require(udp_echo("10.66.0.1"), "new marked WireGuard handshake and IPv4 tunnel traffic under policy")
    require(udp_echo("10.66.0.1", 53), "DNS-port traffic allowed inside tunnel (not an OS resolver test)")
    for address, port, description in [
        ("192.0.2.1", 9999, "IPv4 underlay bypass blocked"),
        ("2001:db8::1", 9999, "IPv6 underlay bypass blocked"),
        ("192.0.2.1", 53, "IPv4 plaintext DNS-port bypass blocked"),
        ("2001:db8::1", 53, "IPv6 plaintext DNS-port bypass blocked"),
        ("fd66::1", 9999, "explicit IPv6 block also blocks tunnel IPv6"),
        ("192.0.2.1", 51820, "unmarked UDP cannot reuse endpoint exception"),
    ]:
        require(denied_send(address, port), description)
    require(denied_send("192.0.2.1", 9999, 0x4c6f), "mark does not allow an arbitrary UDP port")
    require(denied_send("192.0.2.99", 51820, 0x4c6f), "mark does not allow a different endpoint")
    try:
        existing.sendall(PAYLOAD)
        leaked = existing.recv(4096) == PAYLOAD
    except (TimeoutError, PermissionError):
        leaked = False
    finally:
        existing.close()
    require(not leaked, "established pre-policy TCP connection cannot bypass")

    before = own_table()
    broken = dual["ruleset"] + "delete chain inet lovpn_client nonexistent_chain\n"
    result = subprocess.run(["nft", "-f", "-"], input=broken.encode(), capture_output=True)
    require(result.returncode != 0, "invalid transaction rejected")
    require(own_table() == before, "failed transaction leaves previous policy intact")
    require(denied_send("fd66::1", 9999), "failed policy replacement remains IPv6-blocked")

    apply(dual["ruleset"], check=True)
    apply(dual["ruleset"])
    require(udp_echo("fd66::1"), "explicit dual-stack policy permits IPv6 inside WireGuard")
    require(udp_echo("fd66::1", 53), "IPv6 DNS-port traffic inside tunnel")
    require(denied_send("2001:db8::1", 53), "dual-stack mode still blocks underlay DNS bypass")
    run("ip", "link", "del", "lovpn0")
    require(denied_send("192.0.2.1", 9999), "policy persists after tunnel disappearance")
    require(denied_send("10.66.0.1", 9999), "removed tunnel route cannot fall back to underlay default")
    run("ip", "link", "add", "wan1", "type", "dummy")
    run("ip", "addr", "add", "198.51.100.2/24", "dev", "wan1")
    run("ip", "link", "set", "wan1", "up")
    require(denied_send("198.51.100.1", 9999), "new physical-style interface has no implicit bypass")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml") as file:
        file.write(sample)
        file.flush()
        reset = run(str(binary), "firewall", "show", file.name, "--reset-preview").stdout
    run("nft", "-f", "-", input=reset)
    run("nft", "list", "chain", "inet", "unrelated_test", "sentinel")
    require(udp_echo("192.0.2.1"), "explicit scoped reset restores test underlay and preserves unrelated rules")
    tables = json.loads(run("nft", "-j", "list", "tables").stdout)
    require(not any(item.get("table", {}).get("name") == "lovpn_client" for item in tables["nftables"]),
            "reset removes only the owned policy table")


def main():
    if len(sys.argv) != 3 or os.readlink("/proc/self/ns/net") == sys.argv[1]:
        raise SystemExit("Refusing to run without the script's disposable network namespace")
    binary = Path(sys.argv[2]).resolve(strict=True)
    process = subprocess.Popen(["unshare", "--net", sys.executable, "tests/networking/peer.py"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        wait_line(process, "ready")
        server_public = setup(process)
        exercise(binary, server_public)
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=5)
        if process.returncode != 0:
            # Never dump configuration, key pipes or peer stdout on failure.
            print("Isolated peer failed; inspect the test source and prerequisites.", file=sys.stderr)


if __name__ == "__main__":
    main()
