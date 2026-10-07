# The LoVPN window

`lovpn-ui` is the graphical front end on Windows and Linux. It is a small local web app: a
loopback-only server plus a page the program opens in an app-style window (Edge `--app` on
Windows, the default browser elsewhere). It was chosen over a native toolkit to avoid a
large native dependency tree, to get platform accessibility for free, and to keep one UI for
both systems.

## What it is and is not

- It runs as the **normal user** and holds **no secrets**. Every action goes through the same
  authenticated channel as the `lovpn` command, so the window cannot do anything the command
  cannot.
- It makes **no network connection** except its own listener on `127.0.0.1`. The page loads
  nothing from the internet (no fonts, scripts, analytics).
- It exits shortly after the window closes.

Start it from the Start Menu / application menu, or run `lovpn-ui` (`--no-open` prints the
link; `--url-file PATH` writes it to a file).

## Screens

| Screen | What it shows, and where the facts come from |
| --- | --- |
| Home | One sentence of truth ("You're protected", "Not fully protected", "Internet is blocked"...), the **protection ring** and four checks: VPN tunnel, DNS, IPv6, kill switch. Connect / Disconnect / Repair. |
| Servers | Stored profiles; connect, set default, check profile, remove; the add-server wizard. |
| Devices | This device's public key per server. Other devices are managed on the server. |
| Privacy | The four protections with *how* each was verified; what the program does not do. |
| Diagnostics | Every observed check, a refresh, and **Copy sanitized diagnostics**. |
| Settings | Appearance, default server. Only settings that work are listed. |
| Logs | The service's own events (journal on Linux, protected log file on Windows). |
| Advanced | Reconnect, repair, reset networking; an honest list of what is *not available yet*. |

**The ring.** Four arcs, one per check. An arc is solid only when that check was *observed*
passing; failing is a broken red arc; unverified is a thin dotted outline; "off" and
"blocking" are slate. A complete green ring therefore means something. Nothing is green
unless the service observed it, and an unobserved check is never green.

**Onboarding.** With no server stored, Home shows the setup path instead: name the server,
create a device key, give its public half to the administrator, import the profile plus the
server key received separately, check, connect, review Privacy. No account.

## Sanitized diagnostics

Built from an *allowlist*: state, mode, handshake age, the check names/results and their
short engine phrases. Profile names, endpoints, keys, tunnel addresses and paths are never
included, and a detail phrase that looks like an address or key is replaced by `(omitted)`.
Tested with hostile inputs ([`api.rs`](../crates/lovpn-ui/src/api.rs)).

## Security of the local server

A browser can reach any loopback port, so the server defends itself:

- listens on `127.0.0.1` only, random port;
- a random per-launch secret in the first URL is exchanged for an `HttpOnly; SameSite=Strict`
  cookie (named per port) and removed from the address bar; every other request needs it;
- the `Host` header must be the loopback address and port (DNS-rebinding defence);
- state-changing calls must be same-origin `application/json` POSTs (CSRF defence);
- strict HTTP parsing: size and time limits, no chunked bodies, duplicate `Content-Length`
  refused, no keep-alive; max 16 connections;
- every response carries a restrictive CSP (`default-src 'none'`, own script and style
  only), `nosniff`, `no-store`, `no-referrer`, `frame-ancestors 'none'`;
- the page builds its DOM with `textContent` only (no `innerHTML`), so service text can never
  become markup.

## Evidence and limits

Unit-tested: the HTTP parser (smuggling and limit cases), authentication, Host/Origin
checks and the sanitizer. Exercised by hand in a browser against a test double of the
service (all states, wizard, phone width, light/dark) and against the **real Windows
service**: connect, protected state, logs and disconnect from the window. There are no
automated browser tests and no formal accessibility audit (keyboard focus, labels, landmarks,
contrast and reduced-motion were designed in but not audited with a screen reader).
No tray icon yet.
