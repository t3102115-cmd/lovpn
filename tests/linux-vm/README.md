# Real-host gate (two KVM virtual machines)

`tests/networking/` proves behavior in disposable *namespaces*. This directory proves what
namespaces cannot: the LoVPN services as **real systemd services**, installed by the real
installers, on a real Fedora kernel with **enforcing SELinux**, a real **systemd-resolved**,
a real **NetworkManager**, real **reboots** and a real ACPI **suspend/resume**.

```bash
tests/linux-vm/run.sh --fresh [WORKDIR]    # about 15 minutes; needs KVM, qemu, xorriso, ssh
```

* `srv` runs `lovpn-server-broker` and `lovpn-server-enroll`; `cli` runs `lovpn-clientd`.
  They share a private point-to-point LAN (a localhost TCP netdev between the two QEMU
  processes) and each has a user-mode NIC for NAT to the host.
* Control is the QEMU guest agent over virtio-serial, **not the network**, so it keeps
  working while a strict kill switch blocks every IP path. (The agent's own SELinux domain
  is made permissive in the guest so it can run commands; SELinux stays enforcing for every
  service under test, and the test fails on any AVC denial for LoVPN.)
* Leak claims are measured **outside the guest**: QEMU records every frame on each NIC
  (`filter-dump`), and the test parses the capture. A positive control proves the detector
  would see a leak (after the kill switch is released, plain traffic *is* visible).
* Windows is out of scope here; see `tests/windows/`.

What it does not cover: other distributions (Debian/Ubuntu need their own run), physical
Wi-Fi/Ethernet hardware, several uplinks, IPv6 underlay, rogue DHCP/RA, a NetworkManager
profile that *manages* the tunnel interface, power loss in the middle of a write, and
anything about performance.

Nothing is installed on the host. The work directory holds the image, disks and keys;
delete it to remove everything.
