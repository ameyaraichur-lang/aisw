"""Lockfile-based SBOM (CycloneDX 1.5) and licence gate for the backend and web workspaces.

NOT Syft/ScanCode (neither is installed here): components come from `uv.lock` and
`package-lock.json`; Python licences come from installed package metadata, npm licences from the
lockfile. Native libraries bundled inside wheels (libpq, OpenSSL, ...) are NOT inventoried.

Usage: python tools/sbom.py [--check]    (--check: fail if the committed SBOM/report drifted or the
licence gate fails; without it the files are (re)written)
"""

from __future__ import annotations

import base64
import importlib.metadata as md
import json
import re
import sys
import tomllib
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "implementation" / "sbom"
POLICY = json.loads((OUT / "licence-policy.json").read_text())

_ALIASES = {
    "apache 2.0": "Apache-2.0", "apache license 2.0": "Apache-2.0", "apache-2.0": "Apache-2.0",
    "psfl": "PSF-2.0", "psf-2.0": "PSF-2.0", "mit": "MIT", "mit license": "MIT",
    "bsd": "BSD-3-Clause", "bsd license": "BSD-3-Clause",
}  # fmt: skip
_CLASSIFIERS = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
}


def norm_name(n: str) -> str:
    return re.sub(r"[-_.]+", "-", n).lower()


def py_licence(name: str) -> str:
    try:
        meta = md.distribution(name).metadata
    except md.PackageNotFoundError:
        return "UNKNOWN"
    expr = (meta.get("License-Expression") or "").strip()
    if expr:
        return expr
    raw = " ".join((meta.get("License") or "").split())
    if raw and len(raw) <= 40:
        return _ALIASES.get(raw.lower(), raw)
    if raw.lower().startswith("apache license"):
        return "Apache-2.0"
    for c in meta.get_all("Classifier") or []:
        if c in _CLASSIFIERS:
            return _CLASSIFIERS[c]
    return "UNKNOWN"


def python_components() -> list[dict[str, Any]]:
    lock = tomllib.loads((ROOT / "backend" / "uv.lock").read_text())
    pk = {norm_name(p["name"]): p for p in lock["package"]}
    root = pk["aisw"]
    runtime: set[str] = set()

    def edges(pkg: dict[str, Any]) -> list[str]:
        # Windows-only edges are not part of any supported deployment (Linux containers/macOS dev)
        return [
            norm_name(d["name"]) for d in pkg.get("dependencies", [])
            if "win32" not in d.get("marker", "") and "Windows" not in d.get("marker", "")
        ]  # fmt: skip

    stack = edges(root)
    while stack:
        n = stack.pop()
        if n in runtime:
            continue
        runtime.add(n)
        stack += edges(pk[n])
    comps = []
    for n, p in sorted(pk.items()):
        if n == "aisw":
            continue
        comps.append(
            {
                "type": "library", "name": p["name"], "version": p["version"],
                "purl": f"pkg:pypi/{n}@{p['version']}", "ecosystem": "pypi",
                "scope": "required" if n in runtime else "excluded",
                "licence": py_licence(p["name"]),
            }
        )  # fmt: skip
    return comps


def npm_components() -> list[dict[str, Any]]:
    lock = json.loads((ROOT / "web" / "package-lock.json").read_text())
    comps = []
    for path, p in sorted(lock["packages"].items()):
        if not path:
            continue
        name = path.split("node_modules/")[-1]
        c: dict[str, Any] = {
            "type": "library", "name": name, "version": p["version"],
            "purl": f"pkg:npm/{name.replace('@', '%40', 1)}@{p['version']}", "ecosystem": "npm",
            "scope": "excluded" if p.get("dev") else "required",
            "licence": p.get("license") or "UNKNOWN",
        }  # fmt: skip
        if isinstance(c["licence"], dict):
            c["licence"] = c["licence"].get("type", "UNKNOWN")
        integ = p.get("integrity", "")
        if integ.startswith("sha512-"):
            c["sha512"] = base64.b64decode(integ[7:]).hex()
        comps.append(c)
    return comps


def classify(c: dict[str, Any]) -> tuple[str, str | None]:
    lic = c["licence"]
    parts = (
        [x.strip("() ") for x in re.split(r"\s+(?:OR|AND)\s+", lic)]
        if lic != "UNKNOWN"
        else ["UNKNOWN"]
    )
    if any(p in POLICY["deny"] for p in parts) and not (
        " OR " in lic and any(p in POLICY["allow"] for p in parts)
    ):
        status = "deny"
    elif all(p in POLICY["allow"] for p in parts) or (
        " OR " in lic and any(p in POLICY["allow"] for p in parts)
    ):
        status = "allow"
    elif all(p in POLICY["allow"] + POLICY["review"] for p in parts):
        status = "review"
    else:
        status = "deny"
    accepted = POLICY["acceptances"].get(c["name"])
    if accepted is None:
        for pre, why in POLICY["acceptance_prefixes"].items():
            if c["name"].startswith(pre):
                accepted = why
    return status, accepted


def build() -> tuple[dict[str, Any], str, list[str]]:
    comps = python_components() + npm_components()
    failures: list[str] = []
    rows: dict[str, list[str]] = {"review": [], "unknown_or_denied": []}
    for c in comps:
        status, accepted = classify(c)
        c["licence_status"] = status
        if status != "allow":
            line = f"| {c['name']} | {c['version']} | {c['ecosystem']} | {c['scope']} | {c['licence']} | {accepted or '**NO ACCEPTANCE RECORDED**'} |"
            rows["review" if status == "review" else "unknown_or_denied"].append(line)
            if accepted is None:
                failures.append(
                    f"{c['ecosystem']}:{c['name']}@{c['version']} licence {c['licence']} ({status}) has no recorded acceptance"
                )
            elif status == "deny" and c["scope"] == "required":
                failures.append(f"{c['name']} is denied/unknown and ships at runtime")
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps([(c["purl"], c["licence"]) for c in comps]))),
        "metadata": {
            "component": {"type": "application", "name": "aisw", "version": "0.0.1"},
            "tools": [{"name": "aisw tools/sbom.py", "version": "1", "description": "lockfile + metadata based; not Syft/ScanCode"}],
        },
        "components": [
            {
                "type": "library", "name": c["name"], "version": c["version"], "purl": c["purl"],
                "scope": c["scope"],
                "licenses": [{"license": {"id": c["licence"]}}] if c["licence"] != "UNKNOWN" and " " not in c["licence"] else [{"license": {"name": c["licence"]}}],
                **({"hashes": [{"alg": "SHA-512", "content": c["sha512"]}]} if "sha512" in c else {}),
                "properties": [{"name": "aisw:licence-status", "value": c["licence_status"]}],
            }
            for c in comps
        ],
    }  # fmt: skip
    counts = {e: sum(1 for c in comps if c["ecosystem"] == e) for e in ("pypi", "npm")}
    shipped = sum(1 for c in comps if c["scope"] == "required")
    report = (
        "# Licence report (generated by tools/sbom.py; do not edit)\n\n"
        "Engineering gate, not legal advice. Source: `backend/uv.lock` + installed Python metadata, "
        "`web/package-lock.json`. **Not Syft/ScanCode**; native libraries inside wheels are not inventoried.\n\n"
        f"Components: {counts['pypi']} Python, {counts['npm']} npm; {shipped} are runtime (shipped) dependencies, the rest are build/test tooling.\n\n"
        "## Needs review (recorded acceptance required)\n\n| Component | Version | Eco | Scope | Licence | Acceptance |\n|---|---|---|---|---|---|\n"
        + "\n".join(rows["review"] or ["| none | | | | | |"])
        + "\n\n## Unknown or denied\n\n| Component | Version | Eco | Scope | Licence | Acceptance |\n|---|---|---|---|---|---|\n"
        + "\n".join(rows["unknown_or_denied"] or ["| none | | | | | |"])
        + f"\n\n## Gate\n\n{'**FAIL**' if failures else '**PASS**'}: " + (f"{len(failures)} problem(s)." if failures else "every non-allow-listed component has a recorded acceptance and nothing denied ships at runtime.")
        + "\n"
    )  # fmt: skip
    return bom, report, failures


def main() -> int:
    bom, report, failures = build()
    text = json.dumps(bom, indent=1, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        drift = [
            n for n, t in (("aisw.cdx.json", text), ("licence-report.md", report))
            if not (OUT / n).exists() or (OUT / n).read_text() != t
        ]  # fmt: skip
        for f in failures:
            print("LICENCE GATE:", f)
        if drift:
            print("SBOM drift (run python tools/sbom.py):", ", ".join(drift))
        return 1 if failures or drift else 0
    (OUT / "aisw.cdx.json").write_text(text)
    (OUT / "licence-report.md").write_text(report)
    for f in failures:
        print("LICENCE GATE:", f)
    print(f"wrote SBOM with {len(bom['components'])} components")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
