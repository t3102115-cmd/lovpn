#!/usr/bin/env python3
"""Check required architecture documents and repository-local Markdown links."""
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
errors = []
for name in ["architecture", "threat-model", "security-model", "networking", "development", "roadmap", "feature-matrix", "server", "enrollment"]:
    path = ROOT / "docs" / f"{name}.md"
    if not path.is_file() or path.stat().st_size == 0:
        errors.append(f"Missing or empty document: docs/{name}.md")
files = list(ROOT.glob("*.md")) + list((ROOT / "docs").rglob("*.md"))
for file in files:
    for link in re.findall(r"\[[^\]]*\]\(([^)\s]+)\)", file.read_text(encoding="utf-8")):
        parsed = urlsplit(link)
        if parsed.scheme or not parsed.path:
            continue  # Deliberately no outbound link checks.
        target = (file.parent / unquote(parsed.path)).resolve()
        if not target.is_relative_to(ROOT) or not target.exists():
            errors.append(f"Broken local link in {file.relative_to(ROOT)}: {link}")
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print(f"Documentation checks passed: {len(files)} Markdown files; no network requests")
