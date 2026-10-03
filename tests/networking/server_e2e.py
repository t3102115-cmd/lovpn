"""End-to-end server gate test: real WireGuard + real broker, in disposable namespaces.

Run only via scripts/test-networking.sh (user + network + pid namespaces, never the
host). Topology, all inside the sandbox:

    client1 --192.0.2.0/30--+                          +--198.51.100.0/24-- upstream
    client2 --192.0.2.4/30--+-- server (lovpn-srv0, NAT on eth0) --+

The "clients" are configured by hand with `wg`/`ip`: the Linux client lifecycle is not
implemented, so this verifies the SERVER only (enrollment, apply, NAT, isolation,
revocation, rotation, rollback protection, recovery, teardown). It is not a client
leak test and says nothing about kill switches or DNS.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib

TIMEOUT = 2.0


def require(condition, description):
    if not condition:
        raise AssertionError(description)
    print(f"PASS: {description}", flush=True)


def run(*command, check=True, input_text=None):
    return subprocess.run(command, check=check, capture_output=True, text=True, input=input_text)


class Namespace:
    """A network namespace held open by a sleeping process (no /run/netns needed)."""

    def __init__(self, host_netns):
        self.process = subprocess.Popen(["unshare", "--net", "sleep", "600"])
        for _ in range(100):
            try:
                if os.readlink(f"/proc/{self.process.pid}/ns/net") != host_netns:
                    return
            except FileNotFoundError:
                pass
            time.sleep(0.05)
        raise RuntimeError("namespace did not appear")

    def run(self, *command, check=True, input_text=None):
        return run("nsenter", "-t", str(self.process.pid), "-n", "--", *command,
                   check=check, input_text=input_text)

    def popen(self, *command):
        return subprocess.Popen(["nsenter", "-t", str(self.process.pid), "-n", "--", *command],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def close(self):
        self.process.terminate()


ECHO = ("import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
        "s.bind(('0.0.0.0',9999))\nwhile True:\n d,a=s.recvfrom(64);s.sendto(a[0].encode(),a)")
PROBE = ("import socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(%s)\n"
         "try:\n s.sendto(b'x',(sys.argv[1],9999));print(s.recv(64).decode())\n"
         "except Exception:\n print('timeout')" % TIMEOUT)


def probe(namespace, destination, attempts=3):
    """UDP echo through whatever path the namespace has; returns the echoed source IP."""
    for _ in range(attempts):
        answer = namespace.run("python3", "-c", PROBE, destination).stdout.strip()
        if answer != "timeout":
            return answer
    return "timeout"


def probe_within(namespace, destination, seconds):
    """Poll until the tunnel answers. After the server interface is recreated, a client
    holding old session keys re-handshakes only after WireGuard's rekey timeout (~15 s)."""
    deadline = time.monotonic() + seconds
    start = time.monotonic()
    while time.monotonic() < deadline:
        answer = namespace.run("python3", "-c", PROBE, destination).stdout.strip()
        if answer != "timeout":
            print(f"      (recovered after {time.monotonic() - start:.0f}s)", flush=True)
            return answer
    return "timeout"


class Lab:
    def __init__(self, host_netns, server_bin, client_bin):
        self.server_bin, self.client_bin = server_bin, client_bin
        self.root = tempfile.mkdtemp(prefix="lovpn-e2e-")
        os.chmod(self.root, 0o700)
        self.state = os.path.join(self.root, "state")
        self.broker_dir = os.path.join(self.root, "broker")
        os.mkdir(self.broker_dir, 0o700)
        self.socket = os.path.join(self.root, "broker.sock")
        self.broker = None
        self.namespaces = []
        self.clients = {}
        self.host_netns = host_netns
        self.helpers = []

    def server(self, *args, check=True):
        return run(self.server_bin, "--state-dir", self.state, "--socket", self.socket, *args, check=check)

    def new_namespace(self):
        namespace = Namespace(self.host_netns)
        self.namespaces.append(namespace)
        return namespace

    def start_broker(self):
        self.broker = subprocess.Popen(
            [self.server_bin, "--state-dir", self.state, "--socket", self.socket, "broker",
             "--owner-uid", "0", "--broker-dir", self.broker_dir],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if os.path.exists(self.socket) and run(self.server_bin, "--socket", self.socket,
                                                    "--state-dir", self.state, "status", "--live",
                                                    check=False).returncode in (0, 1):
                if os.path.exists(self.socket):
                    return
            time.sleep(0.05)
        raise RuntimeError("broker did not start")

    def stop_broker(self):
        if self.broker:
            self.broker.terminate()
            self.broker.wait()
            self.broker = None

    def live(self):
        return json.loads(self.server("status", "--live", "--json").stdout)["host"]

    def close(self):
        self.stop_broker()
        for helper in self.helpers:
            helper.terminate()
        for namespace in self.namespaces:
            namespace.close()
        shutil.rmtree(self.root, ignore_errors=True)


def wg_peers(interface="lovpn-srv0"):
    return set(run("wg", "show", interface, "peers").stdout.split())


def handshakes(interface="lovpn-srv0"):
    return {line.split("\t")[0]: int(line.split("\t")[1])
            for line in run("wg", "show", interface, "latest-handshakes").stdout.splitlines()}


def make_client(lab, name, server_veth_ip, client_veth_ip, upstream_unused=None):
    namespace = lab.new_namespace()
    server_end, client_end = f"srv-{name}", f"cli-{name}"
    run("ip", "link", "add", server_end, "type", "veth", "peer", "name", client_end)
    run("ip", "link", "set", client_end, "netns", str(namespace.process.pid))
    run("ip", "addr", "add", f"{server_veth_ip}/30", "dev", server_end)
    run("ip", "link", "set", server_end, "up")
    namespace.run("ip", "link", "set", "lo", "up")
    namespace.run("ip", "addr", "add", f"{client_veth_ip}/30", "dev", client_end)
    namespace.run("ip", "link", "set", client_end, "up")
    key_file = os.path.join(lab.root, f"{name}.key")
    public = run(lab.client_bin, "identity", "generate", "--key-file", key_file, "--json")
    public = json.loads(public.stdout)["public_key"]
    lab.server("peer", "create", "--name", name, "--public-key", public, "--confirm-public-key")
    profile_text = lab.server("peer", "export", name).stdout
    profile = tomllib.loads(profile_text)
    lab.clients[name] = {"ns": namespace, "key_file": key_file, "public": public,
                         "profile": profile, "server_ip": server_veth_ip,
                         "address": profile["tunnel"]["addresses"][0].split("/")[0]}
    return namespace


def bring_up_client(lab, name):
    client = lab.clients[name]
    namespace, profile = client["ns"], client["profile"]
    endpoint = f"{client['server_ip']}:{profile['profile']['endpoint'].split(':')[1]}"
    if not client.get("configured"):
        namespace.run("ip", "link", "add", "lovpn0", "type", "wireguard")
        namespace.run("ip", "addr", "add", f"{client['address']}/32", "dev", "lovpn0")
        namespace.run("ip", "link", "set", "lovpn0", "mtu", str(profile["tunnel"]["mtu"]), "up")
        namespace.run("ip", "route", "add", "default", "dev", "lovpn0")
        client["configured"] = True
    with open(client["key_file"]) as handle:
        key = handle.read()
    namespace.run("wg", "set", "lovpn0", "private-key", "/dev/stdin", "peer",
                  profile["profile"]["server_public_key"], "endpoint", endpoint,
                  "allowed-ips", "0.0.0.0/0", "persistent-keepalive", "1", input_text=key)


def counter(table_listing, pattern):
    for line in table_listing.splitlines():
        if re.search(pattern, line):
            match = re.search(r"packets (\d+)", line)
            return int(match.group(1)) if match else None
    return None


def main(host_netns, server_bin, client_bin):
    require(os.readlink("/proc/self/ns/net") != host_netns, "gate test runs outside the host network namespace")
    lab = Lab(host_netns, server_bin, client_bin)
    try:
        scenario(lab)
    finally:
        lab.close()


def scenario(lab):
    run("ip", "link", "set", "lo", "up")
    initial_forward = open("/proc/sys/net/ipv4/ip_forward").read().strip()
    upstream = lab.new_namespace()
    run("ip", "link", "add", "eth0", "type", "veth", "peer", "name", "up0")
    run("ip", "link", "set", "up0", "netns", str(upstream.process.pid))
    run("ip", "addr", "add", "198.51.100.1/24", "dev", "eth0")
    run("ip", "link", "set", "eth0", "up")
    upstream.run("ip", "link", "set", "lo", "up")
    upstream.run("ip", "addr", "add", "198.51.100.2/24", "dev", "up0")
    upstream.run("ip", "link", "set", "up0", "up")
    lab.helpers.append(upstream.popen("python3", "-c", ECHO))

    lab.server("setup", "--write-state", "--endpoint", "192.0.2.1:51820", "--pool", "10.66.0.0/24",
               "--wan-interface", "eth0", "--dns", "10.66.0.1")
    one = make_client(lab, "alpha", "192.0.2.1", "192.0.2.2")
    two = make_client(lab, "beta", "192.0.2.5", "192.0.2.6")
    lab.helpers.append(two.popen("python3", "-c", ECHO))
    alpha, beta = lab.clients["alpha"], lab.clients["beta"]
    require(alpha["profile"]["profile"]["server_public_key"] == json.loads(
        lab.server("status", "--json").stdout)["server_public_key"],
        "exported profile carries the server's public key")

    # Before anything is applied, nothing exists on the host and the server says so.
    lab.start_broker()
    status = lab.live()
    require(not status["in_sync"] and "interface-missing" in status["drift"],
            "before apply the broker observes drift (no interface), not a fake 'protected'")

    # Apply and verify the observed host matches state.
    lab.server("apply")
    status = lab.live()
    require(status["in_sync"] and status["drift"] == [], "broker observes host in sync after apply")
    require(status["firewall_generation"] == status["state_generation"], "firewall generation observed equals state generation")
    require(open("/proc/sys/net/ipv4/ip_forward").read().strip() == "1", "IPv4 forwarding enabled by apply")
    require(wg_peers() == {alpha["public"], beta["public"]}, "kernel WireGuard has exactly the two enrolled peers")
    require("lovpn-owned" in run("nft", "list", "table", "inet", "lovpn_server").stdout, "installed tables carry the ownership marker")
    require(subprocess.run(["ip", "-j", "link", "show", "lovpn-srv0"], capture_output=True, text=True).returncode == 0,
            "server WireGuard interface exists")

    # Two peers reach the upstream through the tunnel, NATed to the server's uplink address.
    bring_up_client(lab, "alpha")
    bring_up_client(lab, "beta")
    require(probe(one, "198.51.100.2") == "198.51.100.1", "peer 1 reaches upstream through the tunnel, source NATed to the uplink")
    require(probe(two, "198.51.100.2") == "198.51.100.1", "peer 2 reaches upstream through the tunnel, source NATed to the uplink")
    marks = handshakes()
    require(all(marks[p] > 0 for p in (alpha["public"], beta["public"])), "both peers completed a real WireGuard handshake")

    # Peer isolation: client-to-client forwarding is dropped by the server policy.
    require(probe(one, beta["address"], attempts=1) == "timeout", "peer-to-peer traffic through the server is blocked")
    table = run("nft", "list", "table", "inet", "lovpn_server").stdout
    dropped = counter(table, r'iifname "lovpn-srv0" oifname "lovpn-srv0"')
    require(dropped and dropped > 0, "the isolation rule (not routing luck) dropped the packets")

    # Revocation takes effect on the live interface.
    older_state = os.path.join(lab.root, "state-before-revoke.json")
    shutil.copy(os.path.join(lab.state, "state.json"), older_state)
    lab.server("peer", "revoke", "alpha", "--apply")
    require(wg_peers() == {beta["public"]}, "revoked peer is removed from the kernel interface")
    require(probe(one, "198.51.100.2", attempts=2) == "timeout", "revoked peer loses access")
    require(probe(two, "198.51.100.2") == "198.51.100.1", "other peer keeps working across the reload")
    require(lab.live()["in_sync"], "host in sync after revocation")

    # Rollback protection: restoring the pre-revocation state must not re-enable the peer.
    state_file = os.path.join(lab.state, "state.json")
    newer_state = os.path.join(lab.root, "state-after-revoke.json")
    shutil.copy(state_file, newer_state)
    shutil.copy(older_state, state_file)
    os.chmod(state_file, 0o600)
    refused = lab.server("apply", check=False)
    require(refused.returncode != 0 and "state.rollback" in refused.stderr, "applying a rolled-back state is refused")
    require(wg_peers() == {beta["public"]}, "revoked peer stays removed after the rollback attempt")
    require(probe(one, "198.51.100.2", attempts=2) == "timeout", "rolled-back state did not restore access")
    shutil.copy(newer_state, state_file)  # the administrator restores the real, newer state
    os.chmod(state_file, 0o600)
    lab.server("apply")
    require(lab.live()["in_sync"], "applying the genuine newer state succeeds again")

    # Key rotation: old key stops working, the new one works once the client switches.
    new_key = os.path.join(lab.root, "beta-new.key")
    new_public = json.loads(run(lab.client_bin, "identity", "generate", "--key-file", new_key, "--json").stdout)["public_key"]
    lab.server("peer", "rotate", "beta", "--public-key", new_public, "--confirm-public-key", "--apply")
    require(wg_peers() == {new_public}, "rotation swaps the peer key on the live interface")
    require(probe(two, "198.51.100.2", attempts=2) == "timeout", "old key no longer works after rotation")
    beta["key_file"] = new_key
    bring_up_client(lab, "beta")
    require(probe(two, "198.51.100.2") == "198.51.100.1", "new key works after the client switches")

    # Recovery: lose the firewall tables and the interface (like a reboot) and re-apply.
    lab.stop_broker()
    run("nft", "add", "table", "inet", "unrelated_sentinel")
    run("nft", "delete", "table", "inet", "lovpn_server")
    run("nft", "delete", "table", "ip", "lovpn_server_nat")
    run("ip", "link", "del", "lovpn-srv0")
    lab.start_broker()
    status = lab.live()
    require(not status["in_sync"] and {"interface-missing", "firewall-missing"} <= set(status["drift"]),
            "after losing interface and tables the broker reports exactly that drift")
    lab.server("apply")
    require(lab.live()["in_sync"], "re-apply restores the server")
    require(probe_within(two, "198.51.100.2", 40) == "198.51.100.1",
            "client reconnects on its own and traffic works after the server recovered")

    # firewall repair reinstalls only LoVPN tables.
    run("nft", "delete", "table", "inet", "lovpn_server")
    require(json.loads(lab.server("firewall", "status", "--json").stdout)["installed"] is False,
            "firewall status observes missing tables")
    lab.server("firewall", "repair")
    require(json.loads(lab.server("firewall", "status", "--json").stdout)["installed"] is True,
            "firewall repair restores the tables")
    require("unrelated_sentinel" in run("nft", "list", "tables").stdout, "repair left an unrelated table alone")

    # A same-named table without our marker is never touched.
    run("nft", "delete", "table", "inet", "lovpn_server")
    run("nft", "add", "table", "inet", "lovpn_server")
    blocked = lab.server("apply", check=False)
    require(blocked.returncode != 0 and "apply.foreign-table" in blocked.stderr, "foreign table with a LoVPN name is refused")
    require("lovpn-owned" not in run("nft", "list", "table", "inet", "lovpn_server").stdout, "foreign table was left unmodified")
    run("nft", "delete", "table", "inet", "lovpn_server")
    lab.server("firewall", "repair")

    # Teardown removes only LoVPN-owned resources.
    lab.server("teardown", "--yes")
    tables = run("nft", "list", "tables").stdout
    require("lovpn_server" not in tables and "unrelated_sentinel" in tables, "teardown removed LoVPN tables only")
    require(subprocess.run(["ip", "link", "show", "lovpn-srv0"], capture_output=True).returncode != 0, "teardown removed the interface")
    require(open("/proc/sys/net/ipv4/ip_forward").read().strip() == initial_forward, "teardown restored the previous forwarding setting")
    require(probe(two, "198.51.100.2", attempts=1) == "timeout", "clients lose service after teardown, as documented")
    lab.server("teardown", "--yes")
    require(True, "teardown is idempotent")


if __name__ == "__main__":
    main(*sys.argv[1:4])
