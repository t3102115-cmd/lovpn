"""Disposable namespace peer. Test traffic only; no application daemon code."""
import json
import os
import selectors
import socket
import subprocess
import sys


def run(*command, **kwargs):
    return subprocess.run(command, check=True, capture_output=True, **kwargs)


def install_key(interface, key):
    # Private test keys live in memory/anonymous fd only, never argv/files/logs.
    fd = os.memfd_create("lovpn-test-key", os.MFD_CLOEXEC)
    try:
        os.write(fd, key.encode())
        os.lseek(fd, 0, os.SEEK_SET)
        run("wg", "set", interface, "private-key", f"/proc/self/fd/{fd}", pass_fds=(fd,))
    finally:
        os.close(fd)


def main():
    print("ready", flush=True)
    config = json.loads(sys.stdin.readline())
    for command in [
        ("ip", "link", "set", "lo", "up"),
        ("ip", "addr", "add", "192.0.2.1/24", "dev", "peer0"),
        ("ip", "-6", "addr", "add", "2001:db8::1/64", "dev", "peer0", "nodad"),
        ("ip", "link", "set", "peer0", "up"),
        ("ip", "link", "add", "lovpn_srv", "type", "wireguard"),
        ("ip", "addr", "add", "10.66.0.1/32", "dev", "lovpn_srv"),
        ("ip", "-6", "addr", "add", "fd66::1/128", "dev", "lovpn_srv", "nodad"),
    ]:
        run(*command)
    install_key("lovpn_srv", config["server_private"])
    config["server_private"] = None
    run("wg", "set", "lovpn_srv", "listen-port", "51820", "peer", config["client_public"],
        "allowed-ips", "10.66.0.2/32,fd66::2/128")
    run("ip", "link", "set", "lovpn_srv", "up")
    run("ip", "route", "add", "10.66.0.2/32", "dev", "lovpn_srv")
    run("ip", "-6", "route", "add", "fd66::2/128", "dev", "lovpn_srv")

    selector = selectors.DefaultSelector()
    selector.register(sys.stdin, selectors.EVENT_READ, "control")
    sockets = []
    for family, address in [(socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1"),
                            (socket.AF_INET, "10.66.0.1"), (socket.AF_INET6, "fd66::1")]:
        for port in [53, 9999]:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((address, port))
            sockets.append(sock)
            selector.register(sock, selectors.EVENT_READ, "udp")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("192.0.2.1", 9998))
    listener.listen(2)
    selector.register(listener, selectors.EVENT_READ, "listener")
    print("configured", flush=True)
    while True:
        for key, _ in selector.select():
            if key.data == "control":
                return  # EOF or a shutdown request from the isolated controller.
            if key.data == "udp":
                packet, sender = key.fileobj.recvfrom(4096)
                key.fileobj.sendto(packet, sender)
            elif key.data == "listener":
                connection, _ = listener.accept()
                selector.register(connection, selectors.EVENT_READ, "tcp")
            else:
                packet = key.fileobj.recv(4096)
                if not packet:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                else:
                    key.fileobj.sendall(packet)


if __name__ == "__main__":
    main()
