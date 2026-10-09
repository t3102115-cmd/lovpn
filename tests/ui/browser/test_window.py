"""Browser tests for the LoVPN window: a real `lovpn-ui` binary, a real Chromium, the TEST
DOUBLE broker. Usage: test_window.py PATH/TO/lovpn-ui   (needs the optional packages in
tests/ui/README.md). Nothing here ships."""
import sys
import urllib.error
import urllib.request
import os
from playwright.sync_api import sync_playwright
from harness import Window, require

ui = sys.argv[1]
SECTIONS = ["home", "servers", "devices", "privacy", "diagnostics", "settings", "logs", "advanced"]
H1 = {"protected": "You’re protected", "disconnected": None}
win = Window(ui, "protected")
base = win.url.split("?")[0]


def open_page(browser, **ctx_args):
    ctx = browser.new_context(**ctx_args)
    page = ctx.new_page()
    page.problems = []
    page.on("console", lambda m: page.problems.append(m.text) if m.type in ("error", "warning") else None)
    page.on("pageerror", lambda e: page.problems.append(str(e)))
    page.goto(win.url)
    page.wait_for_selector("main h1")
    return ctx, page


def goto(page, section):
    page.goto(base + "#/" + section)
    page.wait_for_selector("main h1")
    page.wait_for_timeout(150)


try:
    with sync_playwright() as p:
        browser = getattr(p, os.environ.get('LOVPN_BROWSER', 'chromium')).launch()

        # --- every view renders in every scenario, with no console error or CSP violation
        ctx, page = open_page(browser)
        page.evaluate("document.addEventListener('securitypolicyviolation', e => console.error('CSP ' + e.violatedDirective))")
        for scenario in ("protected", "degraded", "blocked", "unknown", "disconnected", "empty"):
            win.set_scenario(scenario)
            for section in SECTIONS:
                goto(page, section)
                page.evaluate("refresh().then(render)")
                page.wait_for_timeout(100)
                require(page.inner_text("main h1").strip() != "", f"{scenario}/{section}: has a heading")
        require(page.problems == [], f"no console errors or CSP violations ({page.problems})")
        require(page.evaluate("document.querySelectorAll('[style]').length") == 0, "no inline style attributes")
        require(page.evaluate("document.querySelectorAll('script:not([src])').length") == 0, "no inline scripts")
        ctx.close()

        # --- the page carries a strict CSP and local-only resources
        ctx, page = open_page(browser)
        csp = page.goto(base).headers.get("content-security-policy", "")
        ctx.close()
        with_no_cookie = None
        try:
            urllib.request.urlopen(base)
        except urllib.error.HTTPError as error:
            with_no_cookie = error.code
        require(with_no_cookie == 403, "a request without the launch token is refused")
        require("default-src 'none'" in csp, "CSP starts from default-src 'none'")

        # --- headline per state (English)
        ctx, page = open_page(browser)
        expected = {"protected": "You’re protected"}
        for scenario in ("protected", "degraded", "blocked", "unknown", "disconnected"):
            win.set_scenario(scenario)
            goto(page, "home")
            page.evaluate("refresh().then(render)")
            page.wait_for_timeout(300)
            heading = page.inner_text("main h1")
            require(bool(heading), f"home heading for {scenario}: {heading!r}")
            if scenario in expected:
                require(heading == expected[scenario], f"{scenario} headline is {heading!r}")
        headings = set()
        for scenario in ("protected", "degraded", "blocked", "unknown", "disconnected"):
            win.set_scenario(scenario); goto(page, "home"); page.evaluate("refresh().then(render)"); page.wait_for_timeout(300)
            headings.add(page.inner_text("main h1"))
        require(len(headings) == 5, "each state has its own headline")
        ctx.close()

        # --- German, fallback, and persistence
        win.set_scenario("protected")
        ctx, page = open_page(browser, locale="de-DE")
        require(page.evaluate("document.documentElement.lang") == "de", "browser language de selects German")
        german = page.inner_text("main h1")
        require(german != "You’re protected", f"German headline ({german!r})")
        goto(page, "settings")
        page.get_by_label("English").check()
        page.wait_for_timeout(300)
        require(page.evaluate("document.documentElement.lang") == "en", "choosing English switches the language")
        require(page.inner_text("main h1") == "Settings", "settings heading in English")
        page.reload(); page.wait_for_selector("main h1")
        require(page.evaluate("document.documentElement.lang") == "en", "the choice survives a reload")
        page.evaluate("localStorage.setItem('lovpn-lang','xx')"); page.reload(); page.wait_for_selector("main h1")
        require(page.evaluate("document.documentElement.lang") in ("de", "en"), "an unknown stored language is ignored")
        ctx.close()
        ctx, page = open_page(browser, locale="it-IT")
        require(page.evaluate("document.documentElement.lang") == "en", "unsupported language falls back to English")
        ctx.close()
        for code, word in (("fr-FR", "protégé"), ("es-ES", "protegido")):
            ctx, page = open_page(browser, locale=code)
            require(page.evaluate("document.documentElement.lang") == code[:2], f"browser language {code} selects its language")
            require(word in page.inner_text("main h1").lower(), f"{code} headline is translated ({page.inner_text('main h1')!r})")
            ctx.close()

        # --- keyboard: skip link, focus on navigation, dialog focus
        ctx, page = open_page(browser)
        page.keyboard.press("Tab")
        require(page.evaluate("document.activeElement.id") == "skip-link", "the first Tab stops on the skip link")
        page.keyboard.press("Enter")
        require(page.evaluate("document.activeElement.id") == "main", "the skip link moves focus to the content")
        page.goto(base + "#/servers"); page.wait_for_selector("main h1")
        page.evaluate("location.hash = '#/privacy'"); page.wait_for_timeout(300)
        require(page.evaluate("document.activeElement.tagName") == "H1", "navigating moves focus to the new heading")
        goto(page, "servers")
        opener = page.locator("button[data-fid^='remove:']").first
        opener.focus(); opener.press("Enter")
        page.wait_for_selector("dialog[open]")
        require(page.evaluate("document.querySelector('dialog').getAttribute('aria-labelledby')") == "dialog-title", "the dialog is named by its heading")
        require(page.evaluate("document.querySelector('dialog').contains(document.activeElement)"), "focus is inside the open dialog")
        page.keyboard.press("Escape")
        page.wait_for_timeout(200)
        require(page.evaluate("document.activeElement.getAttribute('data-fid')") == "remove:home", "Escape returns focus to the button that opened the dialog")
        require(page.evaluate("document.getElementById('announcer').getAttribute('aria-live')") == "polite", "a polite live region exists")
        require(page.evaluate("document.getElementById('announcer').hasAttribute('role')") is False, "the live region has no role=status (Orca ignores it as UI text)")
        require(page.evaluate("document.getElementById('main').getAttribute('aria-live')") is None, "the content area is not a live region")
        ctx.close()

        # --- the add-a-server wizard
        win.set_scenario("empty")
        ctx, page = open_page(browser)
        goto(page, "servers")
        page.get_by_role("button", name="Add a server").first.click()
        page.wait_for_selector("dialog[open] #srvname")
        require(page.evaluate("document.activeElement.id") == "srvname", "the wizard focuses the name field")
        page.fill("#srvname", "Bad Name")
        page.get_by_role("button", name="Continue").click()
        require(page.locator("#wiz-err[role=alert]").count() == 1, "a bad name is announced as an alert")
        page.fill("#srvname", "lab")
        page.get_by_role("button", name="Continue").click()
        page.wait_for_selector("dialog[open] h2")
        require(page.evaluate("document.activeElement.tagName") == "H2", "each step moves focus to its heading")
        page.get_by_role("button", name="Create a key on this device").click() if page.get_by_role("button", name="Create a key on this device").count() else page.locator("dialog button.primary").click()
        page.wait_for_selector("dialog .keybox")
        require(page.inner_text("dialog .keybox").endswith("="), "the public key is shown, never a private key")
        page.locator("dialog button.primary").last.click()
        page.wait_for_selector("dialog textarea")
        page.fill("dialog textarea", "[Interface]\nAddress = 10.0.0.2/32\n")
        page.fill("#sk", "4kwDqCWUdejUQ+23TV2jbOm4TKHAHJzW0PjUnDAcmXo=")
        page.locator("dialog button.primary").click()
        page.wait_for_selector("dialog button.go")
        win.set_scenario("disconnected")  # the double re-reads the scenario file on every request
        page.get_by_role("button", name="Not now").click()
        page.wait_for_timeout(400)
        page.evaluate("refresh().then(render)"); page.wait_for_timeout(300)
        require("lab" in page.inner_text("main"), "the new server appears in the list")
        ctx.close()

        # --- notifications: opt-in, only when unfocused, only after two sightings, no identifiers
        win.set_scenario("protected")
        stub = """
        window.__notes = [];
        class FakeNotification { constructor(title, opts) { window.__notes.push([title, (opts||{}).body||'']); } static requestPermission() { return Promise.resolve('granted'); } }
        FakeNotification.permission = 'granted';
        window.Notification = FakeNotification;
        """
        for opted_in, focused, label in ((True, False, "opted in and unfocused"), (False, False, "not opted in"), (True, True, "focused window")):
            win.set_scenario("protected")
            ctx = browser.new_context()
            ctx.add_init_script(stub + f"localStorage.setItem('lovpn-notify','{1 if opted_in else 0}');" +
                                ("Document.prototype.hasFocus = () => false;" if not focused else "Document.prototype.hasFocus = () => true;"))
            page = ctx.new_page(); page.goto(win.url); page.wait_for_selector("main h1")
            page.wait_for_timeout(3000)
            win.set_scenario("degraded")
            page.wait_for_timeout(3000)  # one refresh: a single sighting is not enough
            before = page.evaluate("window.__notes.length")
            page.wait_for_timeout(6000)
            notes = page.evaluate("window.__notes")
            if opted_in and not focused:
                require(before == 0 and len(notes) == 1, f"{label}: exactly one notification, after a repeated sighting ({before} then {len(notes)})")
                body = " ".join(notes[0])
                require("home" not in body and "203.0.113" not in body and "=" not in body, "the notification carries no name, address or key")
            else:
                require(len(notes) == 0, f"{label}: no notification")
            ctx.close()
        win.set_scenario("protected")

        # --- narrow screens: no horizontal scrolling in any view
        ctx, page = open_page(browser, viewport={"width": 360, "height": 740})
        for section in SECTIONS:
            goto(page, section)
            wide = page.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth")
            require(not wide, f"360px {section}: no horizontal scroll")
        ctx.close()

        # --- forced colors keeps controls visible
        ctx, page = open_page(browser, forced_colors="active")
        require(page.locator("button").first.is_visible(), "forced-colors: buttons are visible")
        ctx.close()
        browser.close()
finally:
    win.close()
print("ALL BROWSER TESTS PASSED")
