#!/usr/bin/env python3
"""TEST DOUBLE for visual QA of lovpn-ui. It speaks the real broker wire protocol on a
Unix socket but invents its answers; it is never installed or shipped.

    fake_broker.py SOCKET [scenario]      scenarios: disconnected protected degraded
                                           blocked connecting unknown empty
Change the scenario while running by writing its name to SOCKET.scenario.
"""
import json, os, socketserver, sys, threading, time

SOCK = sys.argv[1]
STATE = {"scenario": sys.argv[2] if len(sys.argv) > 2 else "protected", "selected": "home", "profiles": ["home", "work"], "since": time.time()}

def checks(kind):
    def c(n, s, d): return {"name": n, "status": s, "detail": d}
    ok = [c("interface", "ok", "present, owned, up"), c("handshake", "ok", "7s ago"), c("endpoint-route", "ok", "server reached outside the tunnel"),
          c("ipv4", "ok", "unmarked traffic routes into the tunnel"), c("ipv6", "ok", "blocked by firewall policy"),
          c("firewall", "ok", "installed, generation 12"), c("dns", "ok", "tunnel resolvers set; DNS to other servers blocked")]
    if kind == "degraded":
        ok[2] = c("endpoint-route", "fail", "uplink changed; route is stale"); ok[6] = c("dns", "fail", "tunnel resolvers differ from the profile")
    if kind == "unknown":
        ok[3] = c("ipv4", "unknown", "could not inspect")
    return ok

def status():
    s = STATE["scenario"]
    base = {"state": s, "desired": "connected", "profile": STATE["selected"], "kill_switch": "strict", "kill_switch_armed": True,
            "checks": [], "reasons": [], "handshake_age_secs": None, "rx_bytes": 0, "tx_bytes": 0, "generation": 12}
    if s in ("disconnected", "empty"):
        base.update(state="disconnected", desired="disconnected", kill_switch_armed=False, profile=None if s == "empty" else STATE["selected"])
    elif s == "blocked":
        base.update(desired="disconnected")
    elif s in ("protected", "degraded", "unknown", "connecting"):
        base.update(checks=checks(s), handshake_age_secs=7, rx_bytes=48211, tx_bytes=31877)
        base["reasons"] = [c["name"] for c in base["checks"] if c["status"] == "fail"]
        if s == "connecting": base["state"] = "connecting"
    return base

def profiles():
    names = [] if STATE["scenario"] == "empty" else STATE["profiles"]
    return [{"name": n, "endpoint": "203.0.113.9:51820", "server_public_key": "x", "kill_switch": "strict" if n == "home" else "vpn-only", "interface": "lovpn0"} for n in names]

def handle(req):
    op = req.get("op")
    ok = lambda data=None: {"ok": True, "code": "ok", "message": "ok", "data": data or {}}
    if op == "status": return ok(status())
    if op == "list-profiles": return ok({"profiles": profiles(), "selected": STATE["selected"] if STATE["scenario"] != "empty" else None})
    if op == "connect":
        if req.get("profile"): STATE["selected"] = req["profile"]
        STATE["scenario"] = "protected"; return ok({"profile": STATE["selected"], "handshake_seen": True, "kill_switch_armed": True})
    if op == "disconnect":
        STATE["scenario"] = "disconnected" if req.get("release") else "blocked"; return ok()
    if op in ("reconnect", "repair"): STATE["scenario"] = "protected"; return ok({"profile": STATE["selected"], "handshake_seen": True, "kill_switch_armed": True})
    if op == "reset": STATE["scenario"] = "disconnected"; return ok()
    if op == "use-profile": STATE["selected"] = req["name"]; return ok()
    if op == "remove-profile": STATE["profiles"] = [p for p in STATE["profiles"] if p != req["name"]]; return ok()
    if op == "public-key": return ok({"public_key": "4kwDqCWUdejUQ+23TV2jbOm4TKHAHJzW0PjUnDAcmXo="})
    if op == "import-profile":
        STATE["profiles"].append(req["name"]); STATE["scenario"] = "disconnected"; return ok({"profile": {"name": req["name"]}})
    return {"ok": False, "code": "unsupported.platform", "message": "Not supported by the test double.", "data": None}

class H(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            path = SOCK + ".scenario"
            if os.path.exists(path):
                STATE["scenario"] = open(path).read().strip() or STATE["scenario"]
            req = json.loads(self.rfile.readline())
            self.wfile.write((json.dumps(handle(req)) + "\n").encode())
        except Exception:
            pass

if os.path.exists(SOCK): os.unlink(SOCK)
class S(socketserver.ThreadingMixIn, socketserver.UnixStreamServer): daemon_threads = True
srv = S(SOCK, H)
os.chmod(SOCK, 0o600)
print("fake broker on", SOCK, flush=True)
srv.serve_forever()
