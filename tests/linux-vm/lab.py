"""Two real Fedora virtual machines (KVM, real systemd, real kernel) for host-level tests.

Why VMs and not the namespaces of tests/networking: namespaces cannot show how the
services behave under a real systemd, a real systemd-resolved, a real NetworkManager, a
real reboot or a real suspend. Nothing here touches the host's network: each guest has a
QEMU user-mode NIC (SSH forward and NAT to the outside) and a private point-to-point
"LAN" NIC joined by a localhost TCP netdev between the two guests.

Requirements: qemu-system-x86_64 with KVM, qemu-img, xorriso (or mkisofs), ssh, and a
Fedora Cloud Base image (see run.sh). Everything lives in the working directory given
as the first argument of the scenario script; nothing is installed on the host.
"""
import json
import os
import shutil
import socket
import subprocess
import time

BASE_PORT = 2200
LAN_PORT = 7700


class Vm:
    def __init__(self, work, name, index, base_image, pubkey):
        self.work, self.name, self.index = work, name, index
        self.dir = os.path.join(work, name)
        self.ssh_port = BASE_PORT + index
        self.mgmt_mac = f"52:54:00:00:00:0{index}"
        self.lan_mac = f"52:54:00:aa:00:0{index}"
        self.lan_ip = f"10.99.0.{index}"
        # Unix socket paths are limited to 107 bytes, so sockets live in a short directory.
        self.qmp = os.path.join(socket_dir(work), f"{name}.qmp")
        self.qga = os.path.join(socket_dir(work), f"{name}.qga")
        self.serial = os.path.join(self.dir, "serial.log")
        self.pidfile = os.path.join(self.dir, "qemu.pid")
        self.disk = os.path.join(self.dir, "disk.qcow2")
        self.seed = os.path.join(self.dir, "seed.iso")
        self.key = os.path.join(work, "lab_key")
        os.makedirs(self.dir, exist_ok=True)
        if not os.path.exists(self.disk):
            subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", base_image, "-F", "qcow2",
                            self.disk, "8G"], check=True)
            self._make_seed(pubkey)

    def _make_seed(self, pubkey):
        files = os.path.join(self.dir, "seed")
        os.makedirs(files, exist_ok=True)
        with open(os.path.join(files, "meta-data"), "w") as f:
            f.write(f"instance-id: {self.name}-1\nlocal-hostname: {self.name}\n")
        with open(os.path.join(files, "user-data"), "w") as f:
            f.write(f"""#cloud-config
users:
  - name: lab
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - {pubkey}
ssh_pwauth: false
package_update: false
packages: [wireguard-tools, nftables, python3, tcpdump, bind-utils, qemu-guest-agent, policycoreutils-python-utils]
runcmd:
  # Lab control channel only: the guest agent's own SELinux domain becomes permissive so it can
  # run commands. SELinux stays ENFORCING for every LoVPN service under test.
  - [semanage, permissive, -a, virt_qemu_ga_t]
  - [systemctl, enable, --now, qemu-guest-agent]
""")
        with open(os.path.join(files, "network-config"), "w") as f:
            f.write(f"""version: 2
ethernets:
  mgmt:
    match: {{macaddress: "{self.mgmt_mac}"}}
    set-name: mgmt
    dhcp4: true
  lan:
    match: {{macaddress: "{self.lan_mac}"}}
    set-name: lan
    addresses: ["{self.lan_ip}/24"]
""")
        tool = shutil.which("xorriso")
        cmd = ([tool, "-as", "mkisofs"] if tool else [shutil.which("mkisofs")]) + [
            "-quiet", "-output", self.seed, "-volid", "cidata", "-joliet", "-rock", files]
        subprocess.run(cmd, check=True)

    def start(self, listen_lan):
        lan = f"socket,id=lan,{'listen' if listen_lan else 'connect'}=127.0.0.1:{LAN_PORT}"
        cmd = [
            "qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-machine", "q35", "-smp", "2", "-m", "1536",
            "-display", "none", "-daemonize", "-pidfile", self.pidfile,
            "-serial", f"file:{self.serial}",
            "-qmp", f"unix:{self.qmp},server=on,wait=off",
            "-global", "ICH9-LPC.disable_s3=0",
            # Control channel that survives a strict kill switch (it is not a network).
            "-chardev", f"socket,path={self.qga},server=on,wait=off,id=qga",
            "-device", "virtio-serial", "-device", "virtserialport,chardev=qga,name=org.qemu.guest_agent.0",
            "-drive", f"file={self.disk},if=virtio,format=qcow2",
            "-drive", f"file={self.seed},if=virtio,format=raw,media=cdrom,readonly=on",
            "-netdev", f"user,id=mgmt,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22",
            # Frames the guest puts on each NIC, recorded by QEMU outside the guest. This is
            # what a leak test measures; nothing inside the VM can falsify it.
            "-object", f"filter-dump,id=dump-mgmt,netdev=mgmt,file={self.pcap('mgmt')}",
            "-device", f"virtio-net-pci,netdev=mgmt,mac={self.mgmt_mac}",
            "-netdev", lan,
            "-object", f"filter-dump,id=dump-lan,netdev=lan,file={self.pcap('lan')}",
            "-device", f"virtio-net-pci,netdev=lan,mac={self.lan_mac}",
        ]
        subprocess.run(cmd, check=True)

    def pcap(self, nic):
        return os.path.join(self.dir, f"{nic}.pcap")

    def frames(self, nic, since=0.0, until=1e18):
        """Parse the QEMU capture: frames the GUEST transmitted (it records both ways, so
        keep only frames whose source MAC is this guest's)."""
        return parse_pcap(self.pcap(nic), {"mgmt": self.mgmt_mac, "lan": self.lan_mac}[nic], since, until)

    def latest_ts(self):
        """Newest frame time (in the capture's own clock) on either NIC, any direction.
        QEMU's capture timestamps are not the host's wall clock, so every window in a test is
        bounded by captured timestamps, never by time.time()."""
        newest = 0.0
        for nic in ("mgmt", "lan"):
            for frame in parse_pcap(self.pcap(nic), None):
                newest = max(newest, frame["ts"])
        return newest

    def ssh_cmd(self, command, timeout=120, check=True):
        full = ["ssh", "-i", self.key, "-p", str(self.ssh_port), "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR", "lab@127.0.0.1", command]
        return subprocess.run(full, capture_output=True, text=True, timeout=timeout, check=check)

    def sudo(self, command, **kw):
        return self.ssh_cmd("sudo bash -c " + shell_quote(command), **kw)

    def scp(self, source, dest):
        subprocess.run(["scp", "-q", "-i", self.key, "-P", str(self.ssh_port), "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes", "-o", "LogLevel=ERROR",
                        source, f"lab@127.0.0.1:{dest}"], check=True)

    def wait_ssh(self, seconds=240):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                if self.ssh_cmd("true", timeout=10, check=False).returncode == 0:
                    return True
            except subprocess.TimeoutExpired:
                pass
            time.sleep(2)
        raise RuntimeError(f"{self.name}: ssh did not come up; see {self.serial}")

    def wait_cloud_init(self):
        self.sudo("cloud-init status --wait >/dev/null 2>&1 || true", timeout=600)

    def qmp_command(self, command, **arguments):
        client = socket.socket(socket.AF_UNIX)
        client.connect(self.qmp)
        reader = client.makefile("rw")
        reader.readline()
        reader.write(json.dumps({"execute": "qmp_capabilities"}) + "\n")
        reader.flush()
        reader.readline()
        reader.write(json.dumps({"execute": command, "arguments": arguments}) + "\n")
        reader.flush()
        while True:
            line = json.loads(reader.readline())
            if "return" in line or "error" in line:
                client.close()
                return line

    def agent(self, command, timeout=10, **arguments):
        """One QEMU guest-agent request over virtio-serial (independent of any firewall)."""
        client = socket.socket(socket.AF_UNIX)
        client.settimeout(timeout)
        client.connect(self.qga)
        stream = client.makefile("rwb")
        # Resynchronize the channel (the reply is prefixed with a raw 0xFF byte).
        marker = int(time.time() * 1000) & 0x7FFFFFFF
        stream.write(json.dumps({"execute": "guest-sync-delimited", "arguments": {"id": marker}}).encode() + b"\n")
        stream.flush()
        while True:
            raw = stream.readline()
            if not raw:
                raise RuntimeError("guest agent closed the channel")
            try:
                if json.loads(raw.lstrip(b"\xff")).get("return") == marker:
                    break
            except ValueError:
                continue
        stream.write(json.dumps({"execute": command, "arguments": arguments}).encode() + b"\n")
        stream.flush()
        line = json.loads(stream.readline())
        client.close()
        if "error" in line:
            raise RuntimeError(f"guest agent: {line['error']}")
        return line["return"]

    def wait_agent(self, seconds=240):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                self.agent("guest-ping", timeout=3)
                return True
            except (OSError, RuntimeError, ValueError):
                time.sleep(2)
        raise RuntimeError(f"{self.name}: guest agent did not answer")

    def exec(self, command, timeout=120, check=False):
        """Run a root shell command through the guest agent. Returns (status, stdout, stderr)."""
        import base64
        started = self.agent("guest-exec", path="/bin/bash", arg=["-c", command], **{"capture-output": True})
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            status = self.agent("guest-exec-status", pid=started["pid"])
            if status.get("exited"):
                out = base64.b64decode(status.get("out-data", "")).decode(errors="replace")
                err = base64.b64decode(status.get("err-data", "")).decode(errors="replace")
                if check and status.get("exitcode") != 0:
                    raise RuntimeError(f"{self.name}: `{command}` exited {status.get('exitcode')}: {err or out}")
                return status.get("exitcode"), out, err
            time.sleep(0.3)
        raise TimeoutError(f"{self.name}: `{command}` did not finish in {timeout}s")

    def alive(self):
        try:
            with open(self.pidfile) as handle:
                os.kill(int(handle.read()), 0)
            return True
        except (OSError, ValueError):
            return False

    def kill(self):
        try:
            with open(self.pidfile) as handle:
                os.kill(int(handle.read()), 15)
        except (OSError, ValueError):
            pass


def socket_dir(work):
    import hashlib
    path = os.path.join("/tmp", "lovpn-lab-" + hashlib.sha256(work.encode()).hexdigest()[:8])
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def shell_quote(text):
    return "'" + text.replace("'", "'\\''") + "'"


def parse_pcap(path, source_mac, since=0.0, until=1e18):
    """Minimal classic-pcap reader. Returns dicts: ts, kind (arp/ipv4/ipv6/other), proto,
    sport, dport, dst for frames sent BY source_mac within [since, until]."""
    import struct
    frames = []
    try:
        data = open(path, "rb").read()
    except OSError:
        return frames
    if len(data) < 24:
        return frames
    magic = struct.unpack("<I", data[:4])[0]
    endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
    offset = 24
    want = bytes(int(x, 16) for x in source_mac.split(":")) if source_mac else None
    while offset + 16 <= len(data):
        seconds, fraction, captured, _ = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        packet = data[offset:offset + captured]
        offset += captured
        if len(packet) < 14 or (want is not None and packet[6:12] != want):
            continue
        ts = seconds + fraction / (1e9 if nano else 1e6)
        if not since <= ts <= until:
            continue
        ethertype = struct.unpack(">H", packet[12:14])[0]
        frame = {"ts": ts, "kind": "other", "proto": None, "sport": None, "dport": None, "dst": None}
        if ethertype == 0x0806:
            frame["kind"] = "arp"
        elif ethertype == 0x86DD:
            frame["kind"] = "ipv6"
        elif ethertype == 0x0800 and len(packet) >= 34:
            header = (packet[14] & 0x0F) * 4
            frame["kind"] = "ipv4"
            frame["proto"] = packet[23]
            frame["dst"] = ".".join(str(b) for b in packet[30:34])
            if frame["proto"] in (6, 17) and len(packet) >= 14 + header + 4:
                frame["sport"], frame["dport"] = struct.unpack(">HH", packet[14 + header:14 + header + 4])
        frames.append(frame)
    return frames


def is_dhcp(frame):
    return frame["kind"] == "ipv4" and frame["proto"] == 17 and (frame["sport"], frame["dport"]) in ((68, 67),)


def is_wireguard(frame):
    return frame["kind"] == "ipv4" and frame["proto"] == 17 and 51820 in (frame["sport"], frame["dport"])
