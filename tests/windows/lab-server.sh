#!/usr/bin/env bash
# Disposable LoVPN server for Windows VM tests. Everything runs inside an unprivileged
# user+network namespace created by `pasta`; nothing on the host network is changed.
# The namespace listens on UDP $LAB_PORT at $LAB_BIND (the host address the VM can reach)
# and serves, only inside the tunnel:
#   10.66.0.1:53    DNS responder (answers every A query with 192.0.2.50)
#   192.0.2.50:8080 HTTP decoy on an unroutable TEST-NET address: a VM can fetch it only
#                   if its traffic really goes through the tunnel.
# Usage:  LAB_DIR=/tmp/lovpn-lab tests/windows/lab-server.sh
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
: "${LAB_DIR:?set LAB_DIR to a private scratch directory}"
BIN=${CARGO_TARGET_DIR:-target}/debug
BIND=${LAB_BIND:-172.16.8.1}
PORT=${LAB_PORT:-51820}

if [[ ${1:-} != inner ]]; then
  mkdir -p "$LAB_DIR" && chmod 700 "$LAB_DIR"
  rm -f "$LAB_DIR/ready"
  export LAB_DIR LAB_BIND=$BIND LAB_PORT=$PORT CARGO_TARGET_DIR
  exec pasta --config-net -u "$BIND/$PORT" -- bash "$0" inner
fi

# ----- inside the namespace (root-mapped, disposable) -----
S="$BIN/lovpn-server --state-dir $LAB_DIR/state --socket $LAB_DIR/broker.sock"
mkdir -p "$LAB_DIR/broker" && chmod 700 "$LAB_DIR/broker"
WAN=$(ip route show default | awk '{print $5; exit}')
if [[ ! -f "$LAB_DIR/state/state.json" ]]; then
  $S setup --write-state --endpoint "$BIND:$PORT" --pool 10.66.0.0/24 --wan-interface "$WAN" --dns 10.66.0.1 >/dev/null
fi
$BIN/lovpn-server --state-dir "$LAB_DIR/state" --socket "$LAB_DIR/broker.sock" broker --owner-uid 0 --broker-dir "$LAB_DIR/broker" 2>"$LAB_DIR/broker.log" &
for _ in $(seq 50); do [[ -S $LAB_DIR/broker.sock ]] && break; sleep 0.1; done
$S apply >/dev/null
ip link add decoy0 type dummy && ip addr add 192.0.2.50/32 dev decoy0 && ip link set decoy0 up
python3 - "$LAB_DIR" <<'PY' &
import socket, sys, threading, http.server
def dns():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("10.66.0.1", 53))
    while True:
        q, a = s.recvfrom(512)
        i = 12
        while q[i]:
            i += q[i] + 1
        question = q[12:i + 5]
        resp = q[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question
        resp += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04\xc0\x00\x02\x32"
        s.sendto(resp, a)
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"lovpn-decoy via " + self.client_address[0].encode() + b"\n"
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
threading.Thread(target=dns, daemon=True).start()
http.server.ThreadingHTTPServer(("192.0.2.50", 8080), H).serve_forever()
PY
# Command channel for the test driver: `lab-exec.sh '<command>'` runs it in this namespace.
( while true; do
    if [[ -f $LAB_DIR/run.sh ]]; then
      bash "$LAB_DIR/run.sh" >"$LAB_DIR/run.out" 2>&1 || true
      rm -f "$LAB_DIR/run.sh"; : >"$LAB_DIR/run.done"
    fi
    sleep 0.2
  done ) &
sleep 1
echo ready >"$LAB_DIR/ready"
wait
