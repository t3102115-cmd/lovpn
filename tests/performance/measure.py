"""PERF-01: connect/reconnect time, round-trip time and TCP throughput through a real
LoVPN tunnel, plus the client daemon's CPU time and memory, in disposable namespaces.

It reuses the topology of tests/networking/client_e2e.py (kernel WireGuard, real server and
client brokers). It runs the client and server on ONE machine over veth pairs, so it
measures LoVPN's own software overhead, NOT a real network: no loss, no latency, no radio,
no battery. Run it with release binaries; see docs/performance.md for what the numbers mean.

    scripts/measure-performance.sh
"""
import json
import os
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "networking"))
import client_e2e as lab_module  # noqa: E402
from server_e2e import require  # noqa: E402

SINK = ("import socket,sys;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
        "s.bind(('0.0.0.0',9300));s.listen(4)\n"
        "while True:\n c,_=s.accept()\n n=0\n while True:\n  d=c.recv(1<<20)\n  if not d: break\n  n+=len(d)\n c.sendall(str(n).encode());c.close()")
ECHO_TIME = ("import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',9301))\n"
             "while True:\n d,a=s.recvfrom(64);s.sendto(d,a)")
SENDER = ("import socket,sys,time;n=int(sys.argv[1]);s=socket.socket();s.connect(('198.51.100.2',9300));b=b'x'*(1<<20)\n"
          "t=time.perf_counter();sent=0\n"
          "while sent<n: s.sendall(b);sent+=len(b)\n"
          "s.shutdown(socket.SHUT_WR);got=int(s.recv(32));dt=time.perf_counter()-t\n"
          "print(got,dt)")
RTT = ("import socket,time,statistics;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2)\n"
       "r=[]\n"
       "for i in range(400):\n t=time.perf_counter();s.sendto(b'p',('198.51.100.2',9301));s.recvfrom(64);r.append((time.perf_counter()-t)*1000)\n"
       "r=r[20:];r.sort();print(round(r[len(r)//2],3),round(r[int(len(r)*.95)],3),round(r[-1],3))")


def cpu_seconds(pid):
    fields = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    ticks = int(fields[11]) + int(fields[12])  # utime + stime
    return ticks / os.sysconf("SC_CLK_TCK")


def rss_mib(pid):
    for line in open(f"/proc/{pid}/status"):
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) / 1024
    return float("nan")


def main(host_netns, server_bin, client_bin, clientd_bin, megabytes="1024"):
    lab = lab_module.Lab(host_netns, server_bin, client_bin, clientd_bin)
    result = {}
    try:
        lab_module.make_topology(lab)
        upstream = lab.namespaces[0]
        upstream.popen("python3", "-c", SINK)
        upstream.popen("python3", "-c", ECHO_TIME)
        key_file, public_key, server_public, strict_profile, vpn_only_profile = lab_module.configure_server(lab)
        lab.start_server_broker()
        lab.server("apply")
        lab.start_client_broker()
        lab_module.import_profiles(lab, key_file, public_key, server_public, strict_profile, vpn_only_profile)
        client = lab.client_namespace

        # Connect time: from the command until traffic really flows through the tunnel.
        times = []
        for _ in range(7):
            start = time.perf_counter()
            lab.client("--json", "connect", "strict")
            lab_module.wait_for(lambda: lab_module.probe(client, "198.51.100.2") == "198.51.100.1", "tunnel traffic", 30)
            times.append(time.perf_counter() - start)
            lab.client("--json", "disconnect", "--release-kill-switch", check=False)
        result["connect_seconds"] = {"samples": len(times), "median": round(statistics.median(times), 2), "max": round(max(times), 2)}

        lab.client("--json", "connect", "strict")
        lab_module.wait_for(lambda: lab_module.probe(client, "198.51.100.2") == "198.51.100.1", "tunnel traffic", 30)
        start = time.perf_counter()
        lab.client("--json", "reconnect", check=False)
        lab_module.wait_for(lambda: lab_module.probe(client, "198.51.100.2") == "198.51.100.1", "traffic after reconnect", 30)
        result["reconnect_seconds"] = round(time.perf_counter() - start, 2)

        median, p95, worst = client.run("python3", "-c", RTT).stdout.split()
        result["rtt_ms_through_tunnel"] = {"median": float(median), "p95": float(p95), "max": float(worst)}

        pid = lab.client_broker.pid
        cpu_before, wall = cpu_seconds(pid), time.perf_counter()
        total = int(megabytes) << 20
        out = client.run("python3", "-c", SENDER, str(total)).stdout.split()
        elapsed = float(out[1])
        require(int(out[0]) == total, "every byte reached the far side through the tunnel")
        result["tcp_throughput_mbit_s"] = round(total * 8 / elapsed / 1e6, 1)
        result["transferred_mib"] = total >> 20
        result["clientd_cpu_seconds_during_transfer"] = round(cpu_seconds(pid) - cpu_before, 2)
        result["clientd_rss_mib"] = round(rss_mib(pid), 1)
        result["clientd_cpu_seconds_total"] = round(cpu_seconds(pid), 2)
        require(wall > 0, "measured")
        print(json.dumps(result, indent=1))
    finally:
        lab.close()


if __name__ == "__main__":
    main(*sys.argv[1:6])
