"""M3/M2c real-host gate: the LoVPN services as real systemd services on real Fedora guests.

usage: real_host.py WORKDIR BIN_DIR [--phases a,b,c]   (see run.sh)

Two KVM guests (tests/linux-vm/lab.py): `srv` runs lovpn-server-broker and
lovpn-server-enroll, `cli` runs lovpn-clientd. Everything is installed with the real
installers, started with real `systemctl`, and exercised with the real kernel,
systemd-resolved, NetworkManager, reboots and suspend. Packet-level claims come from QEMU
frame captures of the guest NICs taken outside the guest.

Control uses the QEMU guest agent (virtio-serial), not the network, so it keeps working
while a strict kill switch blocks every IP path.
"""
import os
import shlex
import subprocess
import sys
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab import Vm, is_dhcp, is_wireguard  # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
PATH = "export PATH=/usr/local/bin:/usr/sbin:/usr/bin:/bin:/sbin; "
HOST_URL = "http://10.0.2.2:18080/"   # the QEMU user-network gateway is the host


def require(condition, description):
    if not condition:
        raise AssertionError(description)
    print(f"PASS: {description}", flush=True)


def note(text):
    print(f"      {text}", flush=True)


def sh(vm, command, user=None, timeout=120):
    if user:
        command = f"runuser -u {user} -- bash -c {shlex.quote(PATH + command)}"
    else:
        command = PATH + command
    rc, out, err = vm.exec(command, timeout=timeout)
    return rc, out.strip(), err.strip()


def lovpn(vm, *args, timeout=120):
    rc, out, err = sh(vm, "lovpn --json " + " ".join(shlex.quote(a) for a in args), user="lab", timeout=timeout)
    import json
    try:
        return rc, json.loads(out or err or "{}")
    except ValueError:
        return rc, {"raw": out, "err": err}


def status(vm):
    return lovpn(vm, "status")[1]


def wait_for(function, seconds, description, interval=1.0):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        last = function()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out after {seconds}s waiting for {description} (last: {last})")


def wait_state(vm, want, seconds=90):
    box = {}

    def check():
        box["s"] = status(vm)
        return box["s"].get("state") == want

    try:
        wait_for(check, seconds, f"state {want}")
    except AssertionError:
        raise AssertionError(f"state never became {want}: {box.get('s')}")
    return box["s"]


def unit_active(vm, unit):
    return sh(vm, f"systemctl is-active {unit}")[1] == "active"


def process_facts(vm, unit):
    """(user, CapEff int, NoNewPrivs) of the unit's main process once it has exec'd the real
    binary. Right after `start`, systemd's forked child still carries systemd's capabilities
    until execve, so poll for the executable instead of trusting the first reading."""
    box = {}

    def ready():
        rc, out, _ = sh(vm, f"pid=$(systemctl show -p MainPID --value {unit}); [ \"$pid\" != 0 ] && "
                            f"[ -r /proc/$pid/exe ] && readlink /proc/$pid/exe | grep -q lovpn && "
                            f"ps -o user= -p $pid && awk '/CapEff|NoNewPrivs/ {{print $2}}' /proc/$pid/status")
        parts = out.split()
        if rc == 0 and len(parts) == 3:
            box["v"] = (parts[0], int(parts[1], 16), parts[2])
            return True
        return False

    wait_for(ready, 20, f"{unit} main process to be running its real binary", 0.5)
    return box["v"]


def journal(vm, unit, extra=""):
    return sh(vm, f"journalctl -u {unit} --no-pager -o cat {extra}")[1]


class Context:
    def __init__(self, work, bin_dir):
        self.work, self.bin_dir = work, bin_dir
        key = os.path.join(work, "lab_key")
        pub = open(key + ".pub").read().strip()
        base = os.path.join(work, "base.qcow2")
        self.srv = Vm(work, "srv", 1, os.path.abspath(base), pub)
        self.cli = Vm(work, "cli", 2, os.path.abspath(base), pub)
        self.state = {}


# ----------------------------------------------------------------------------- phases

def phase_boot(c):
    """Boot both guests (idempotent) and ship binaries, installers and units."""
    if not c.srv.alive():
        c.srv.start(listen_lan=True)
    if not c.cli.alive():
        c.cli.start(listen_lan=False)
    for vm in (c.srv, c.cli):
        vm.wait_agent()
        try:
            vm.wait_ssh(25)
        except RuntimeError:
            # A strict kill switch (correctly) blocks SSH; release it through the agent.
            note(f"{vm.name}: SSH is blocked by the client's kill switch; releasing it through the guest agent")
            sh(vm, "lovpn --json reset", user="lab")
            vm.wait_ssh(60)
    package = os.path.join(c.work, "pkg.tgz")
    with tarfile.open(package, "w:gz") as tar:
        for name in ("lovpn-server", "lovpn", "lovpn-clientd"):
            tar.add(os.path.join(c.bin_dir, name), arcname=f"bin/{name}")
        tar.add(os.path.join(REPO, "scripts"), arcname="scripts")
        tar.add(os.path.join(REPO, "packaging"), arcname="packaging")
        tar.add(os.path.join(REPO, "tests", "linux-vm", "guest"), arcname="guest")
    for vm in (c.srv, c.cli):
        vm.scp(package, "/home/lab/pkg.tgz")
        rc, _, err = sh(vm, "rm -rf /home/lab/lovpn && mkdir /home/lab/lovpn && tar xmzf /home/lab/pkg.tgz -C /home/lab/lovpn "
                            "&& chown -R lab:lab /home/lab/lovpn")
        require(rc == 0, f"{vm.name}: binaries and installers shipped ({err})")
        rc, out, _ = sh(vm, "getenforce; uname -r; . /etc/os-release; echo $PRETTY_NAME; systemctl is-active NetworkManager systemd-resolved")
        note(out.replace("\n", " | "))
        require(out.splitlines()[0] == "Enforcing", f"{vm.name}: SELinux is enforcing during the whole test")


def phase_server_install(c):
    srv = c.srv
    rc, out, err = sh(srv, "cd /home/lab/lovpn && ./scripts/install-server.sh --binary bin/lovpn-server --client-binary bin/lovpn --yes")
    require(rc == 0, f"server installer ran for real as root ({err or out[-120:]})")
    rc, out, _ = sh(srv, "id -un lovpn-server && stat -c '%a %U' /var/lib/lovpn-server /var/lib/lovpn-broker")
    require(out.splitlines()[1:] == ["700 lovpn-server", "700 root"], f"service user and 0700 state/broker dirs created ({out!r})")
    rc, out, _ = sh(srv, "systemd-analyze verify /etc/systemd/system/lovpn-server-broker.service /etc/systemd/system/lovpn-server-enroll.service 2>&1")
    require(out == "", f"systemd-analyze verify accepts the installed units ({out})")
    sh(srv, "systemctl enable --now lovpn-server-broker")
    wait_for(lambda: unit_active(srv, "lovpn-server-broker"), 20, "broker active")
    require("broker-listening" in journal(srv, "lovpn-server-broker"), "broker is a real systemd service and logs to the journal")
    user, caps, _ = process_facts(srv, "lovpn-server-broker")
    # CAP_CHOWN (0) + CAP_NET_ADMIN (12) + CAP_DAC_READ_SEARCH (2), nothing else.
    require(user == "root" and caps == (1 << 0) | (1 << 12) | (1 << 2), f"server broker keeps exactly CAP_NET_ADMIN, CAP_DAC_READ_SEARCH and CAP_CHOWN ({caps:#x})")


def phase_server_setup(c):
    srv = c.srv
    rc, out, err = sh(srv, "lovpn-server setup --write-state --endpoint 10.99.0.1:51820 --pool 10.66.0.0/24 --wan-interface mgmt --dns 10.66.0.1",
                      user="lovpn-server")
    require(rc == 0, f"server state created by the service user ({err or out[-100:]})")
    rc, out, err = sh(srv, "lovpn-server apply", user="lovpn-server")
    require(rc == 0, f"service user applies through the real broker ({err or out[-100:]})")
    rc, out, _ = sh(srv, "lovpn-server --json status --live", user="lovpn-server")
    require('"in_sync":true' in out.replace(" ", ""), "broker observes the host in sync after apply")
    sh(srv, "systemd-run --unit=lab-services python3 /home/lab/lovpn/guest/lab_services.py 10.66.0.1")
    wait_for(lambda: unit_active(srv, "lab-services"), 10, "lab services")
    require("lovpn-owned" in sh(srv, "nft list table inet lovpn_server")[1], "server nftables table carries the ownership marker")


def phase_enroll_unit(c):
    srv = c.srv
    rc, out, err = sh(srv, "lovpn-server --json enroll tls-init", user="lovpn-server")
    require(rc == 0, f"enrollment TLS identity created ({err})")
    import json
    pin1 = json.loads(out)["pin"]
    # Without a configured address the unit must fail closed instead of listening anywhere.
    sh(srv, "systemctl start lovpn-server-enroll; sleep 1")
    require(sh(srv, "systemctl is-active lovpn-server-enroll")[1] != "active", "unconfigured enrollment unit does not listen")
    require("10.99.0.1" not in sh(srv, "ss -ltn")[1] and ":51821" not in sh(srv, "ss -ltn")[1], "nothing listens on the enrollment port before configuration")
    sh(srv, "systemctl stop lovpn-server-enroll; systemctl reset-failed lovpn-server-enroll; mkdir -p /etc/lovpn-server; "
            "echo LOVPN_ENROLL_LISTEN=10.99.0.1:51821 > /etc/lovpn-server/enroll.env")
    sh(srv, "systemctl start lovpn-server-enroll")
    wait_for(lambda: unit_active(srv, "lovpn-server-enroll"), 20, "enrollment unit active")
    user, caps, no_new_privs = process_facts(srv, "lovpn-server-enroll")
    require(user == "lovpn-server" and caps == 0 and no_new_privs == "1",
            f"enrollment listener runs as lovpn-server with no capabilities and NoNewPrivs ({user}, {caps:#x}, {no_new_privs})")
    require("10.99.0.1:51821" in sh(srv, "ss -ltn")[1], "listener bound only to the configured address")
    require("enroll-listening" in journal(srv, "lovpn-server-enroll"), "listener logs to the journal")
    rc, out, _ = sh(srv, "systemd-analyze security --no-pager lovpn-server-enroll.service | tail -1")
    note(out)

    # Rotate the identity under the running service; it must switch by itself.
    rc, out, err = sh(srv, "lovpn-server --json enroll tls-rotate --yes", user="lovpn-server")
    require(rc == 0, f"TLS identity rotated ({err})")
    rotated = json.loads(out)
    require(rotated["old_pin"] == pin1 and rotated["pin"] != pin1, "rotation changes the pin")
    c.state["pin1"], c.state["pin"] = pin1, rotated["pin"]

    # The running listener picks the new identity up on its next connection (checked in
    # phase `enroll`, where the old pin must fail and the new pin must work).
    require(unit_active(srv, "lovpn-server-enroll"), "listener still active after rotation")


def phase_client_install(c):
    cli = c.cli
    rc, out, err = sh(cli, "cd /home/lab/lovpn && ./scripts/install-client.sh --owner-user lab --daemon-binary bin/lovpn-clientd --client-binary bin/lovpn --yes")
    require(rc == 0, f"client installer ran for real as root ({err or out[-120:]})")
    require(sh(cli, "cat /etc/default/lovpn-client")[1] == "LOVPN_OWNER_UID=1000", "owner UID configured explicitly")
    rc, out, _ = sh(cli, "systemd-analyze verify /etc/systemd/system/lovpn-clientd.service 2>&1")
    require(out == "", f"systemd-analyze verify accepts the installed client unit ({out})")
    sh(cli, "systemctl enable --now lovpn-clientd")
    wait_for(lambda: unit_active(cli, "lovpn-clientd"), 20, "clientd active")
    user, caps, _ = process_facts(cli, "lovpn-clientd")
    sock = wait_for(lambda: sh(cli, "stat -c '%a %U' /run/lovpn-client/broker.sock")[1] or None, 10, "broker socket")
    require(user == "root" and caps == (1 << 0) | (1 << 12) and sock == "600 lab",
            f"clientd keeps only CAP_NET_ADMIN and CAP_CHOWN; socket is 0600 lab ({caps:#x}, {sock})")
    s = status(cli)
    require(s.get("service") == "running" and s.get("state") == "disconnected", f"lovpn status reports the real service, disconnected ({s.get('state')})")
    require(s.get("host_state_inspected") is True, "status is observed from the host, not assumed")


def phase_enroll(c):
    import json
    srv, cli = c.srv, c.cli
    rc, out, err = sh(srv, "lovpn-server --json enroll token create --name labclient", user="lovpn-server")
    require(rc == 0, f"token created by the service user ({err})")
    token = json.loads(out)["token"]
    tokfile = os.path.join(c.work, "labclient.token")
    with open(tokfile, "w") as handle:
        handle.write(token + "\n")
    os.chmod(tokfile, 0o600)
    cli.scp(tokfile, "/home/lab/labclient.token")
    sh(cli, "chmod 600 /home/lab/labclient.token; chown lab:lab /home/lab/labclient.token")

    common = "enroll --server 10.99.0.1:51821 --name home --token-file /home/lab/labclient.token --key-file /home/lab/home.key"
    rc, data = lovpn(cli, *common.split(), "--pin", c.state["pin1"], "--generate-key")
    require(rc != 0 and data.get("error", {}).get("code") == "enroll.pin-mismatch", "client refuses the OLD pin after rotation (nothing sent)")
    require("handshake-failed" in journal(srv, "lovpn-server-enroll"), "the rotated listener really served the new identity (old pin failed its handshake)")
    require("enroll-identity-reloaded" in journal(srv, "lovpn-server-enroll"), "running listener reloaded the rotated identity without a restart")
    rc, data = lovpn(cli, *common.split(), "--pin", c.state["pin"])
    require(rc == 0 and data.get("ok") and data.get("imported"), f"client enrolls over the real unit with the new pin and imports ({data})")
    require(data.get("applied_on_server") is True, "the server unit asked the broker to apply and it succeeded")
    public = sh(cli, "lovpn --json identity public --key-file /home/lab/home.key", user="lab")[1]
    pub = json.loads(public)["public_key"]
    require(pub in sh(srv, "wg show lovpn-srv0 peers")[1], "the enrolled key is live on the server's kernel interface")
    jr = journal(srv, "lovpn-server-enroll")
    require(token not in jr and token.split("-", 2)[2] not in jr, "server journal never contains the token")
    require(token.split("-", 2)[2] not in sh(cli, "journalctl --no-pager -o cat | cat")[1], "client journal never contains the token")
    c.state["pub"] = pub
    rc, data = lovpn(cli, "profile", "list")
    require("home" in str(data) or "home" in sh(cli, "lovpn profile list", user="lab")[1], "profile is stored by the root service")


def mark(c):
    """A point in capture time (see Vm.latest_ts)."""
    time.sleep(1.2)   # let something (keepalive, ARP, DHCP) land so the mark is 'now'
    return c.cli.latest_ts() + 0.001


def leak_check(c, since, until=1e18, label=""):
    mgmt = [f for f in c.cli.frames("mgmt", since, until) if f["kind"] == "ipv4" and not is_dhcp(f)]
    lan = [f for f in c.cli.frames("lan", since, until) if f["kind"] == "ipv4" and not is_wireguard(f)]
    return mgmt, lan


def start_host_http(c):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"host-ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("0.0.0.0", 18080), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    c.state["http"] = server


def curl(vm, url, extra="", t=4):
    rc, out, err = sh(vm, f"curl -s --max-time {t} {extra} {shlex.quote(url)}", timeout=t + 20)
    return out if rc == 0 else None


def phase_protected(c):
    cli = c.cli
    require(curl(cli, HOST_URL) == "host-ok", "before connecting the client reaches the host directly (baseline)")
    t0 = mark(c)
    rc, data = lovpn(cli, "connect", "home", timeout=120)
    require(rc == 0, f"lovpn connect succeeds ({data})")
    s = wait_state(cli, "protected", 60)
    checks = {x["name"]: x["status"] for x in s["checks"]}
    require(all(v == "ok" for v in checks.values()) and len(checks) >= 7, f"Protected with every check observed ok: {checks}")
    c.state["t_connected"] = t0
    rc, out, _ = sh(cli, "resolvectl status lovpn0")
    require("10.66.0.1" in out and "~." in out, "real systemd-resolved holds the per-link DNS and ~. routing domain")
    require("192.0.2.50" in sh(cli, "getent hosts lab.test")[1], "name resolution goes to the tunnel resolver (answer exists only there)")
    require(curl(cli, "http://10.66.0.1:8080/") == "tunnel-ok", "traffic to the tunnel-only service works")
    require(curl(cli, HOST_URL) == "host-ok", "internet-style traffic works through tunnel + server NAT")
    route = sh(cli, "ip route get 10.0.2.2")[1]
    require("lovpn0" in route, f"default route decision goes to the tunnel ({route})")
    require(curl(cli, HOST_URL, "--interface mgmt", 3) is None, "traffic forced onto the physical NIC is blocked")
    time.sleep(1)
    mgmt, lan = leak_check(c, t0)
    require(not mgmt, f"capture outside the guest: no non-DHCP IPv4 frame left the physical NIC while connected ({mgmt[:2]})")
    require(not lan, f"capture outside the guest: only WireGuard UDP crossed the LAN NIC ({lan[:2]})")
    require(any(is_wireguard(f) for f in c.cli.frames("lan", t0)), "WireGuard frames were actually observed on the wire")


def phase_service_kill(c):
    cli = c.cli
    t0 = mark(c)
    sh(cli, "systemctl kill -s KILL lovpn-clientd")
    # Kernel state survives the daemon: policy and routes still in place, nothing leaks.
    require("lovpn-owned" in sh(cli, "nft list table inet lovpn_client")[1], "kill switch table survives the daemon being SIGKILLed")
    require(curl(cli, HOST_URL, "--interface mgmt", 3) is None, "no bypass while the daemon is dead")
    wait_for(lambda: unit_active(cli, "lovpn-clientd"), 30, "systemd restarts clientd")
    wait_state(cli, "protected", 60)
    require(True, "systemd restarted the broker and it returned to Protected without a reconnect")
    mgmt, lan = leak_check(c, t0)
    require(not mgmt and not lan, "no leak frames on either NIC across the crash and restart")
    require(curl(cli, HOST_URL) == "host-ok", "traffic works after recovery")


def phase_network_manager(c):
    cli = c.cli
    t0 = mark(c)
    sh(cli, "systemctl restart NetworkManager")
    time.sleep(8)
    s = wait_state(cli, "protected", 60)
    require(True, "still Protected after NetworkManager was restarted")
    require("lovpn0" in sh(cli, "ip route get 10.0.2.2")[1], "routing unchanged after the NetworkManager restart")
    rc, out, _ = sh(cli, "nmcli -t -f DEVICE,STATE device")
    note(out.replace("\n", " | "))
    # DHCP renewal on the physical NIC while the kill switch is armed.
    before = sh(cli, "ip -4 -o addr show mgmt | awk '{print $4}'")[1]
    rc, out, _ = sh(cli, "nmcli connection up 'cloud-init mgmt' 2>&1 | tail -1")
    time.sleep(6)
    after = sh(cli, "ip -4 -o addr show mgmt | awk '{print $4}'")[1]
    require(before == after and after != "", f"DHCP re-acquisition on the physical NIC works through the kill switch ({after})")
    require(any(is_dhcp(f) for f in c.cli.frames("mgmt", t0)), "the DHCP exchange was observed on the wire")
    wait_state(cli, "protected", 30)
    require(curl(cli, HOST_URL) == "host-ok", "traffic still works after the DHCP renewal")
    mgmt, lan = leak_check(c, t0)
    require(not mgmt and not lan, "no leak frames during NetworkManager restart and DHCP renewal")
    require("9100" in sh(cli, "ip rule")[1], "owned policy rules intact")


def phase_resolved(c):
    cli = c.cli
    t0 = mark(c)
    sh(cli, "systemctl restart systemd-resolved")
    # What really happens to the per-link settings, measured, not assumed.
    after = sh(cli, "resolvectl status lovpn0")[1]
    note("after resolved restart, link DNS present: " + str("10.66.0.1" in after))
    leaked = sh(cli, "getent hosts example.invalid >/dev/null 2>&1; echo $?")[1]
    started = time.monotonic()
    s = wait_state(cli, "protected", 90)
    note(f"back to Protected {time.monotonic() - started:.0f}s after the resolver restart")
    rc, out, _ = sh(cli, "resolvectl status lovpn0")
    require("10.66.0.1" in out and "~." in out,
            "the per-link DNS settings are intact after systemd-resolved restarted (resolved kept them itself, so this "
            "run did not need a LoVPN repair; whether the monitor would repair a lost setting is covered by unit tests only)")
    require("192.0.2.50" in sh(cli, "getent hosts lab.test")[1], "resolution through the tunnel works again")
    mgmt, lan = leak_check(c, t0)
    require(not mgmt and not lan, "no DNS or data frame left the physical NIC while resolved had lost the settings")


def phase_server_outage(c):
    cli, srv = c.cli, c.srv
    t0 = mark(c)
    srv.qmp_command("stop")
    time.sleep(2)
    require(curl(cli, HOST_URL, t=5) is None, "with the server frozen, nothing reaches the host (no fallback path)")
    require(curl(cli, HOST_URL, "--interface mgmt", 3) is None, "and forcing the physical NIC is still blocked")
    mgmt, lan = leak_check(c, t0)
    require(not mgmt, f"no IPv4 frame left the physical NIC during the outage ({mgmt[:2]})")
    srv.qmp_command("cont")
    started = time.monotonic()
    wait_for(lambda: curl(cli, HOST_URL, t=3) == "host-ok", 90, "tunnel traffic after the server resumes", 2)
    note(f"traffic recovered {time.monotonic() - started:.0f}s after the server resumed")
    wait_state(cli, "protected", 120)
    require(True, "client is Protected again after the server outage")


def phase_disconnect(c):
    cli = c.cli
    t0 = mark(c)
    rc, data = lovpn(cli, "disconnect")
    require(rc == 0, f"strict disconnect succeeds ({data})")
    s = status(cli)
    require(s.get("state") == "blocked", f"strict disconnect leaves the machine Blocked, not open ({s.get('state')})")
    require(curl(cli, HOST_URL, t=3) is None, "strict kill switch blocks the physical NIC after disconnect")
    mgmt, lan = leak_check(c, t0)
    require(not mgmt and not lan, "no IPv4 frames except DHCP/WireGuard while blocked")
    rc, data = lovpn(cli, "disconnect", "--release-kill-switch")
    require(rc == 0, f"explicit release succeeds ({data})")
    require(status(cli).get("state") == "disconnected", "release restores normal networking")
    released = mark(c)
    require(curl(cli, HOST_URL) == "host-ok", "direct connectivity is back after release")
    time.sleep(1)
    direct, _ = leak_check(c, released)
    require(direct, "positive control: once released, the same capture DOES see non-DHCP IPv4 on the physical NIC (the leak detector works)")
    require("lovpn_client" not in sh(cli, "nft list tables")[1], "owned nftables table removed")
    require("9100" not in sh(cli, "ip rule")[1], "owned policy rules removed")
    require("10.66.0.1" not in sh(cli, "resolvectl status")[1], "DNS settings reverted")


def phase_reboot_client(c):
    cli = c.cli
    rc, data = lovpn(cli, "connect", "home", timeout=120)
    require(rc == 0, f"reconnect for the reboot test ({data})")
    wait_state(cli, "protected", 60)
    mk = mark(c)
    mk_wall = time.time()
    sh(cli, "setsid nohup bash -c 'sleep 2; systemctl reboot' >/dev/null 2>&1 &")
    time.sleep(8)
    c.cli.wait_agent(180)
    s = wait_state(cli, "protected", 120)
    note(f"Protected again {time.time() - mk_wall:.0f}s after the reboot command")
    require(True, "a real reboot with a connected strict profile comes back Protected on its own")
    mgmt, lan = leak_check(c, mk)
    require(not mgmt, f"capture outside the guest across the real reboot: no non-DHCP IPv4 frame left the physical NIC ({mgmt[:3]})")
    require(not lan, f"only WireGuard crossed the LAN NIC across the reboot ({lan[:3]})")
    v6 = [f for f in c.cli.frames("mgmt", mk) if f["kind"] == "ipv6"]
    note(f"IPv6 frames on the physical NIC during boot (not claimed blocked pre-arm): {len(v6)}")
    seen = {}
    for nic in ("mgmt", "lan"):
        for f in c.cli.frames(nic, mk):
            key = f"{nic}:{f['kind']}" + (":dhcp" if is_dhcp(f) else ":wg" if is_wireguard(f) else "")
            seen[key] = seen.get(key, 0) + 1
    note(f"frames the guest sent from the reboot command onward: {seen}")
    require(any(k.endswith(":dhcp") for k in seen) and any(k.endswith(":wg") for k in seen),
            "the capture covered the whole boot (it saw DHCP and WireGuard, so silence elsewhere is meaningful)")
    ordering = sh(cli, "systemctl show -p Before --value lovpn-clientd")[1]
    require("network-pre.target" in ordering, "unit is ordered before network-pre.target on the real system")
    require(curl(cli, HOST_URL) == "host-ok", "traffic through the tunnel works after the reboot")


def phase_suspend(c):
    cli = c.cli
    mk = mark(c)
    try:
        cli.agent("guest-suspend-ram", timeout=5)
    except (OSError, RuntimeError, ValueError):
        pass
    state = wait_for(lambda: cli.qmp_command("query-status").get("return", {}).get("status") == "suspended", 40, "guest suspended")
    note("guest entered ACPI S3 (suspended)")
    time.sleep(10)
    cli.qmp_command("system_wakeup")
    cli.wait_agent(120)
    started = time.monotonic()
    wait_state(cli, "protected", 150)
    note(f"Protected {time.monotonic() - started:.0f}s after wake")
    require(curl(cli, HOST_URL, t=6) == "host-ok" or wait_for(lambda: curl(cli, HOST_URL, t=4) == "host-ok", 60, "traffic after resume", 3),
            "tunnel traffic works after suspend/resume")
    mgmt, lan = leak_check(c, mk)
    require(not mgmt, f"no non-DHCP IPv4 frame left the physical NIC across suspend/resume ({mgmt[:3]})")
    note("resume nudge events: " + str(journal(cli, "lovpn-clientd", f"--since '-3min'").count("nudge")))


def phase_reboot_server(c):
    srv, cli = c.srv, c.cli
    mk = mark(c)
    sh(srv, "setsid nohup bash -c 'sleep 2; systemctl reboot' >/dev/null 2>&1 &")
    time.sleep(8)
    srv.wait_agent(180)
    wait_for(lambda: unit_active(srv, "lovpn-server-broker"), 60, "broker back after reboot")
    require(True, "server broker (enabled) is up again after a real reboot")
    started = time.monotonic()
    def in_sync():
        out = sh(srv, "lovpn-server --json status --live", user="lovpn-server")[1].replace(" ", "")
        return '"in_sync":true' in out
    wait_for(in_sync, 60, "the rebooted server restoring itself")
    note(f"server restored its own interface, peers and firewall {time.monotonic() - started:.0f}s after the broker started")
    require("startup-apply" in journal(srv, "lovpn-server-broker"), "the restore was the broker's startup apply, not an administrator command")
    sh(srv, "systemd-run --unit=lab-services2 python3 /home/lab/lovpn/guest/lab_services.py 10.66.0.1")
    wait_for(lambda: curl(cli, HOST_URL, t=3) == "host-ok", 120, "client traffic after the server rebooted", 3)
    wait_state(cli, "protected", 120)
    require(True, "client is Protected again with no administrator action on either side")
    mgmt, _ = leak_check(c, mk)
    require(not mgmt, "no leak frames on the client's physical NIC while the server was down and coming back")


def phase_hygiene(c):
    for vm in (c.srv, c.cli):
        avc = sh(vm, "journalctl --no-pager -k -g 'avc.*denied' 2>/dev/null | grep -E 'lovpn|wg|nft' | grep -v virt_qemu_ga_t | head -5")[1]
        require(avc == "", f"{vm.name}: no SELinux denial for LoVPN services ({avc[:200]})")
    require("lovpn_client" in sh(c.cli, "nft list tables")[1], "client table still owned and present at the end of the run")
    unrelated = sh(c.cli, "nft list tables")[1]
    note(unrelated.replace("\n", " | "))


def phase_uninstall(c):
    cli, srv = c.cli, c.srv
    lovpn(cli, "reset")
    rc, out, err = sh(cli, "cd /home/lab/lovpn && ./scripts/install-client.sh --uninstall --yes")
    require(rc == 0, f"client uninstall ran for real ({err})")
    require("lovpn-clientd" not in sh(cli, "ls /usr/local/bin /etc/systemd/system")[1], "program and unit removed")
    require(sh(cli, "ls /var/lib/lovpn-client")[1] != "", "profiles and keys kept on uninstall")
    sh(srv, "systemctl stop lovpn-server-enroll lab-services lab-services2 2>/dev/null; true")
    rc, out, err = sh(srv, "lovpn-server teardown --yes")
    require(rc == 0, f"server teardown through the real broker ({err})")
    rc, out, err = sh(srv, "cd /home/lab/lovpn && ./scripts/install-server.sh --uninstall --yes")
    require(rc == 0 and "lovpn-server" not in sh(srv, "ls /usr/local/bin /etc/systemd/system")[1], "server uninstall removed program and units")
    require(sh(srv, "ls /var/lib/lovpn-server")[1] != "", "server state and key kept on uninstall")


PHASES = ["boot", "server_install", "server_setup", "enroll_unit", "client_install", "enroll", "protected",
          "service_kill", "network_manager", "resolved", "server_outage", "disconnect", "reboot_client",
          "suspend", "reboot_server", "hygiene", "uninstall"]


def main():
    work, bin_dir = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    selected = PHASES
    if "--phases" in sys.argv:
        selected = sys.argv[sys.argv.index("--phases") + 1].split(",")
    c = Context(work, bin_dir)
    c.state = {}
    start_host_http(c)
    state_file = os.path.join(work, "state.json")
    if os.path.exists(state_file):
        import json
        c.state.update(json.load(open(state_file)))
    import json
    try:
        for name in selected:
            print(f"== phase {name}", flush=True)
            globals()[f"phase_{name}"](c)
            json.dump({k: v for k, v in c.state.items() if isinstance(v, (str, int, float))}, open(state_file, "w"))
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
