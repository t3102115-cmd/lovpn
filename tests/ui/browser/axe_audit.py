import json, os, sys
import os
from playwright.sync_api import sync_playwright
from harness import Window, require
ui, axe = sys.argv[1], sys.argv[2]
SECTIONS = ["home","servers","devices","privacy","diagnostics","settings","logs","advanced"]
win = Window(ui, "protected")
found = {}
try:
    with sync_playwright() as p:
        browser = getattr(p, os.environ.get('LOVPN_BROWSER', 'chromium')).launch()
        for scheme in ("light", "dark"):
            for width in (1100, 360):
                ctx = browser.new_context(viewport={"width": width, "height": 800}, color_scheme=scheme, bypass_csp=True)
                page = ctx.new_page()
                page.goto(win.url)
                page.wait_for_selector("main h1")
                for scenario in ("protected", "degraded", "blocked", "unknown", "disconnected", "empty"):
                    win.set_scenario(scenario)
                    for sec in SECTIONS:
                        page.goto(win.url.split("?")[0] + "#/" + sec)
                        page.wait_for_timeout(300)
                        page.evaluate("render()")
                        page.wait_for_timeout(200)
                        page.add_script_tag(path=axe)
                        res = page.evaluate("axe.run(document, {runOnly:['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa','best-practice']})")
                        for v in res["violations"]:
                            key = (v["id"], v["impact"])
                            found.setdefault(key, {"help": v["help"], "where": set(), "nodes": set()})
                            found[key]["where"].add(f"{scheme}/{width}/{scenario}/{sec}")
                            for n in v["nodes"][:3]:
                                found[key]["nodes"].add(n["target"][0] if n["target"] else "?")
                ctx.close()
        browser.close()
finally:
    win.close()
for (rid, impact), info in sorted(found.items()):
    print(f"{impact:9} {rid}: {info['help']}  [{len(info['where'])} views]  e.g. {sorted(info['nodes'])[:3]}")
print("TOTAL rule violations:", len(found))
sys.exit(1 if found else 0)
