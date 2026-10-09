import json, socket, sys, time
T = sys.argv[1]
for _ in range(60):
    try:
        s = socket.create_connection(("127.0.0.1", 2828)); break
    except OSError: time.sleep(1)
buf = b""
def read():
    global buf
    while b":" not in buf: buf += s.recv(65536)
    n, rest = buf.split(b":", 1); n = int(n)
    while len(rest) < n: rest += s.recv(65536)
    buf = rest[n:]; return json.loads(rest[:n])
read()
mid = 0
def cmd(name, params=None):
    global mid; mid += 1
    body = json.dumps([0, mid, name, params or {}]).encode()
    s.sendall(str(len(body)).encode() + b":" + body)
    while True:
        m = read()
        if m[0] == 1 and m[1] == mid: return m
cmd("WebDriver:NewSession", {"capabilities": {}})
url = open(T + "/url").read().strip()
cmd("WebDriver:Navigate", {"url": url}); time.sleep(5)
h = cmd("WebDriver:GetWindowHandle")[3]["value"]
cmd("WebDriver:SwitchToWindow", {"handle": h, "focus": True}); time.sleep(1)
cmd("WebDriver:FullscreenWindow"); time.sleep(2)
def js(code): return cmd("WebDriver:ExecuteScript", {"script": code, "args": []})
def focus(sel):
    js(f"var e=document.querySelector({json.dumps(sel)}); if(e) e.focus(); return !!e;"); time.sleep(1.6)
def mark(text):
    open(T + "/marks", "a").write(f"{time.time()} {text}\n")
for name, sel in [("h1", "main h1"), ("nav-servers", "nav a[href='#/servers']"), ("disconnect", "main button")]:
    mark(name); focus(sel)
js("location.hash='#/settings'"); time.sleep(2); mark("settings")
for name, sel in [("h1", "main h1"), ("theme-radio", "input[name=theme]"), ("lang-radio", "input[name=lang]"), ("notify", "#notify")]:
    mark(name); focus(sel)
js("location.hash='#/servers'"); time.sleep(2)
mark("remove-dialog"); js("document.querySelector(\"button[data-fid^='remove:']\").click()"); time.sleep(2.5)
mark("dialog-closed"); js("document.getElementById('dialog').close()"); time.sleep(1.5)
js("location.hash='#/home'"); time.sleep(2)
mark("state-change-degraded"); open(T + "/b.sock.scenario", "w").write("degraded"); time.sleep(12)
mark("end")
r = js("return [document.getElementById('announcer').textContent, document.hidden, document.hasFocus(), document.querySelector('main h1').textContent]")
open(T + "/final.txt", "w").write(json.dumps(r))
