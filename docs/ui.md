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

## Language, accessibility and notifications

* **Languages:** English and German, as JSON catalogs served from `/i18n/<lang>.json`
  (`ui/i18n/`). The browser language picks one, Settings can override it, and anything
  missing falls back to English; a missing key shows the key, never a blank. Messages written
  by the service and the technical codes stay English on purpose, so a report and a bug
  match. A unit test fails when the two catalogs differ in keys or `{placeholders}`, or when
  `app.js` asks for a key that does not exist.
* **Accessibility:** one skip link, landmarks, one `h1` per view that receives focus on
  navigation, native `<dialog>` modals named by their heading with focus returned to the
  opener, a polite status region for state changes (the content area itself is not a live
  region, so a poll never re-reads the page), focus kept across the polling re-render,
  `aria-invalid`/`role=alert` on wizard errors, visible focus, reduced motion and
  forced-colors/high-contrast support, and the status colors chosen for AA contrast in both
  themes. Light-theme green was darkened after the first audit found it under 4.5:1.
* **Notifications (window):** off by default. Turning them on asks the browser for permission
  from that click. They fire only while the window is open and unfocused or hidden, only for
  a lasting change (the same state on two refreshes in a row) into degraded, blocked, unknown
  or service-down, or back to protected, and the text never contains a name, address or key.
* **Tray (`lovpn-tray`):** on Linux a StatusNotifierItem (any desktop that hosts one; only KDE Plasma was tested) with a standard theme icon per state, the state in
  the tooltip, and a menu: Open LoVPN, Connect (the default server), Disconnect, Quit tray.
  It polls the service like the `lovpn` command and sends freedesktop notifications under the
  same rules as the window, so it also covers the time the window is closed. Disconnect never
  releases the kill switch; "Restore normal internet" stays in the window. It is not started
  automatically. On Windows it is a notification-area icon (Win32 `Shell_NotifyIcon`, a hidden
  window, one instance per session) with an icon drawn in code: each state has its own *shape*
  (check, exclamation mark, cross, dash, dots, slash) inside a coloured disc, so colour is never
  the only signal. The same menu, polling and notification rules apply; a click or Enter on the
  icon opens the window. It is installed by the MSI but not started or added to start-up
  automatically. Tray text is English only.

## Evidence and limits

* Unit tests: 12 in `lovpn-ui` (HTTP parser limits and smuggling, session secret, Host/Origin,
  sanitizer, catalog parity, key coverage, route auth) and 6 in `lovpn-tray` (state mapping,
  debouncing, no-identifier messages, menu rules).
* Browser tests (`scripts/test-ui.sh`, [tests/ui/README.md](../tests/ui/README.md)): a real
  `lovpn-ui` in headless Chromium against the test double, 93 checks: all views and six
  scenarios without console or CSP errors, no inline script or style, keyboard and focus
  behaviour, dialogs, the wizard end to end, language selection and fallback, notification
  gating, 360 px layout, forced colors.
* Accessibility audit: axe-core 4.14.0 (WCAG 2.0/2.1/2.2 A and AA plus best practice) over
  light and dark, 1100 and 360 px, six scenarios, eight views: **0 violations** (the first run
  on the previous UI found only the contrast problem noted above).
* Tray (Linux): the model is unit-tested; the binary was run once against the KDE Plasma
  session of the development machine with the test double: it registered with the
  StatusNotifierWatcher, its icon and title followed the state, and one notification was
  delivered.
* Tray (Windows): built natively and run in the interactive desktop session of the Windows 11
  test VM (`tests/windows/tray-e2e.ps1`, with the real `LoVPNClient` service): Windows
  registered the icon, the icon changed shape and colour when the service stopped and started
  (screenshots read by hand), the notification "The LoVPN service isn't running." appeared, a
  second instance exited at once. **Not exercised:** the right-click menu, Connect/Disconnect
  from it, an Explorer restart, high-contrast icons, and the MSI build itself.
* Screen reader: Orca 50.3 with Firefox 157 on Linux in an isolated session, speech captured
  from Orca's own log (`tests/ui/screenreader/`). It reads the page as 2 landmarks, 1 heading
  and the navigation list, each view heading, buttons, radios, the checkbox with its hint, and
  the remove dialog with its text. **It found two real problems, now fixed:** Orca treats
  `role="status"` as UI text and never speaks it as a live region, so the announcer is a plain
  `aria-live` region; and a refresh could drop focus from the heading the user was on.
  **Whether Orca then spoke the state-change announcement is not confirmed**: its log showed it
  handling the live-region message but the capture ended before the speech line. The run is
  also flaky (about one in three runs, Firefox on Wayland was never activated and Orca stayed
  silent), so it is a manual aid, not a CI test.
* Earlier: used by hand against the **real Windows service** (connect, protected, logs,
  disconnect).

Not done, and what that means: **NVDA, JAWS and VoiceOver were not run** and Orca only
partly (above); automated checks find only part of the real problems; Chromium is the only
browser in the automated tests (Firefox only under Orca); the Linux tray was seen on one
desktop (KDE), not GNOME, Xfce or Cinnamon; no further languages were added; German text
was written by the author, not by a native reviewer; right-to-left languages are untested;
the notification wording and permission flow depend on the browser.
