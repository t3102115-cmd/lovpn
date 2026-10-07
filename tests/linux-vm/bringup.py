"""Create and boot the two lab VMs, then print what the guests actually run.

usage: bringup.py WORKDIR BASE_IMAGE.qcow2
"""
import os
import subprocess
import sys

from lab import Vm


def main(work, base):
    os.makedirs(work, exist_ok=True)
    key = os.path.join(work, "lab_key")
    if not os.path.exists(key):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "lovpn-lab", "-f", key], check=True)
    pubkey = open(key + ".pub").read().strip()
    server = Vm(work, "srv", 1, os.path.abspath(base), pubkey)
    client = Vm(work, "cli", 2, os.path.abspath(base), pubkey)
    server.start(listen_lan=True)
    client.start(listen_lan=False)
    for vm in (server, client):
        vm.wait_ssh()
        vm.wait_cloud_init()
        vm.wait_agent()
        print(f"== {vm.name}")
        print(vm.sudo("uname -r; . /etc/os-release; echo $PRETTY_NAME; ip -br addr; "
                      "systemctl is-active NetworkManager systemd-resolved; command -v wg nft python3").stdout)


if __name__ == "__main__":
    main(*sys.argv[1:3])
