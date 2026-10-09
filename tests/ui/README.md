# Browser tests for the window (`lovpn-ui`)

These drive a **real `lovpn-ui` binary** in a **real Chromium** against `fake_broker.py`, a test
double that speaks the real service protocol. Nothing here is installed or shipped, and the
packages below are test-only (the product has no JavaScript dependencies).

```bash
python3 -m venv .venv && .venv/bin/pip install playwright==1.63.0
.venv/bin/playwright install chromium-headless-shell
npm install --prefix .axe axe-core@4.14.0
cargo build -p lovpn-ui
scripts/test-ui.sh        # uses .venv and .axe if present
```

* `browser/test_window.py`: every view in every state with no console error or CSP violation,
  no inline script or style, the launch-token check, headline per state, German/English and
  fallback, skip link, focus on navigation, dialog labelling and focus return, the add-server
  wizard, notification gating (opt-in, unfocused, two sightings, no identifiers), no horizontal
  scrolling at 360 px, forced colors.
* `browser/axe_audit.py`: axe-core (WCAG 2.0/2.1/2.2 A and AA, best-practice) over light and
  dark, 1100 and 360 px wide, six scenarios and all eight views. Any violation fails.

Limits: axe finds roughly a third of accessibility problems and no screen reader is run.
Chromium by default; `LOVPN_BROWSER=firefox scripts/test-ui.sh` runs Firefox (also passes with
`playwright install firefox`). WebKit needs system libraries (`playwright install --with-deps`).
