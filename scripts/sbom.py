#!/usr/bin/env python3
"""Write a CycloneDX 1.5 SBOM (JSON) of everything Cargo.lock pins, for one target.

No network, no third-party tool: it reads `cargo metadata --locked` (versions, licences,
repository, registry checksums). It lists dependencies; it does NOT cover the WireGuard-NT
driver (a separate download with its own licence, see docs/windows.md) and is not a
statement about vulnerabilities (`cargo audit` does that).

    scripts/sbom.py [--target TRIPLE] [-o FILE]
"""
import argparse
import json
import subprocess
import sys
import tomllib
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=None)
    parser.add_argument("-o", "--output", default="-")
    args = parser.parse_args()
    cmd = ["cargo", "metadata", "--locked", "--format-version", "1"]
    if args.target:
        cmd += ["--filter-platform", args.target]
    meta = json.loads(subprocess.check_output(cmd))
    with open("Cargo.lock", "rb") as handle:
        sums = {(p["name"], p["version"]): p.get("checksum") for p in tomllib.load(handle)["package"]}
    members = set(meta["workspace_members"])
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    components, depends = [], []
    for pkg in sorted(meta["packages"], key=lambda p: (p["name"], p["version"])):
        if pkg["id"] not in nodes:
            continue  # not used on this target
        ref = f'{pkg["name"]}@{pkg["version"]}'
        component = {
            "type": "application" if pkg["id"] in members else "library",
            "bom-ref": ref,
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": f'pkg:cargo/{pkg["name"]}@{pkg["version"]}',
        }
        if pkg.get("license"):
            component["licenses"] = [{"expression": pkg["license"]}]
        elif pkg["id"] not in members:
            component["licenses"] = [{"license": {"name": "NOASSERTION"}}]
        if pkg.get("repository"):
            component["externalReferences"] = [{"type": "vcs", "url": pkg["repository"]}]
        if pkg["id"] not in members and (pkg.get("source") or "").startswith("registry+"):
            lock = sums.get((pkg["name"], pkg["version"]))
            if lock:
                component["hashes"] = [{"alg": "SHA-256", "content": lock}]
        components.append(component)
        deps = sorted(
            f'{d["name"]}@{d["version"]}'
            for dep in nodes[pkg["id"]]["deps"]
            for d in [next(p for p in meta["packages"] if p["id"] == dep["pkg"])]
        )
        depends.append({"ref": ref, "dependsOn": deps})
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(components, sort_keys=True))),
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "lovpn", "version": next(
            p["version"] for p in meta["packages"] if p["id"] in members)}},
        "components": components,
        "dependencies": depends,
    }
    text = json.dumps(bom, indent=1, sort_keys=True) + "\n"
    if args.output == "-":
        sys.stdout.write(text)
    else:
        open(args.output, "w").write(text)
        print(f"{len(components)} components -> {args.output}", file=sys.stderr)


main()
