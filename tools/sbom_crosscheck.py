"""Cross-check the lockfile SBOM against Syft and ScanCode output (ADR-043).

  python tools/sbom_crosscheck.py stage OUT_DIR
      copy the licence files of every runtime (`required`) component into OUT_DIR/<eco>/<name>@<version>/
      for ScanCode; run with the backend virtualenv's Python after `npm ci` in web/
  python tools/sbom_crosscheck.py check [--syft A.cdx.json ...] [--scancode S.json] [--summary OUT.md]
      at least one of --syft and --scancode

`check` fails when a runtime component of docs/implementation/sbom/aisw.cdx.json is missing from the
Syft output for its ecosystem or present only at another version, when no ecosystem could be
checked at all, or when ScanCode finds a denied licence in a runtime component's files without a
recorded acceptance. Components only Syft sees (OS packages, bundled binaries) are reported, not
failed: the lockfile SBOM does not claim to list them.
"""

from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import re
import shutil
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SBOM = ROOT / "docs" / "implementation" / "sbom" / "aisw.cdx.json"
POLICY = json.loads((ROOT / "docs" / "implementation" / "sbom" / "licence-policy.json").read_text())
ECOSYSTEMS = ("pypi", "npm")
LICENCE_FILE = re.compile(r"(licen[cs]e|copying|notice|copyright)", re.IGNORECASE)


def norm(eco: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "pypi" else name


def eco_of(component: dict[str, Any]) -> str | None:
    m = re.match(r"pkg:([a-z]+)/", component.get("purl", ""))
    return m.group(1) if m else None


def runtime_components(sbom: dict[str, Any]) -> list[tuple[str, str, str]]:
    return sorted(
        (eco, norm(eco, c["name"]), c["version"]) for c in sbom["components"]
        if c.get("scope") == "required" and (eco := eco_of(c)) in ECOSYSTEMS
    )  # fmt: skip


def accepted(name: str) -> bool:
    if name in POLICY["acceptances"]:
        return True
    return any(name.startswith(p) for p in POLICY["acceptance_prefixes"])


def licence_ids(expression: str) -> set[str]:
    return {t for t in re.split(r"[\s()]+", expression) if t and t not in {"AND", "OR", "WITH"}}


def scancode_findings(doc: dict[str, Any]) -> dict[tuple[str, str], set[str]]:
    """{(eco, name@version): licence ids} from a ScanCode JSON scan of a `stage` directory."""
    out: dict[tuple[str, str], set[str]] = defaultdict(set)
    for f in doc.get("files", []):
        parts = Path(f.get("path", "")).parts
        idx = next((i for i, p in enumerate(parts) if p in ECOSYSTEMS), None)
        if idx is None or len(parts) < idx + 3:
            continue
        exprs = [f.get("detected_license_expression_spdx") or ""]
        exprs += [d.get("license_expression_spdx") or "" for d in f.get("license_detections", [])]
        for e in exprs:
            out[(parts[idx], parts[idx + 1])] |= licence_ids(e)
    return out


def check(
    sbom: dict[str, Any], syft_docs: list[dict[str, Any]] | None, scancode: dict[str, Any] | None
) -> tuple[list[str], list[str]]:
    """(failures, report lines). None means that tool was not run in this job."""
    runtime = runtime_components(sbom)
    failures: list[str] = []
    report: list[str] = []
    if syft_docs is None and scancode is None:
        return ["nothing to check: pass Syft and/or ScanCode output"], report
    if syft_docs is None:
        report.append("- components: Syft not run in this job")
    else:
        failures += _check_syft(runtime, syft_docs, report)
    if scancode is None:
        report.append("- licences: ScanCode not run in this job")
    else:
        failures += _check_scancode(runtime, scancode, report)
    return failures, report


def _check_syft(
    runtime: list[tuple[str, str, str]], syft_docs: list[dict[str, Any]], report: list[str]
) -> list[str]:
    found: dict[str, dict[str, set[str]]] = {e: defaultdict(set) for e in ECOSYSTEMS}
    extras: dict[str, set[str]] = defaultdict(set)
    for doc in syft_docs:
        for c in doc.get("components", []):
            eco = eco_of(c)
            if eco in ECOSYSTEMS:
                found[eco][norm(eco, c["name"])].add(c.get("version", ""))
            elif c.get("type") != "file":
                extras[eco or c.get("type", "other")].add(f"{c['name']} {c.get('version', '')}".strip())
    failures: list[str] = []
    checked = [e for e in ECOSYSTEMS if found[e]]
    for eco in ECOSYSTEMS:
        mine = [(n, v) for e, n, v in runtime if e == eco]
        if eco not in checked:
            report.append(f"- {eco}: NOT CHECKED (no {eco} components in the Syft input)")
            continue
        missing = [f"{n}@{v}" for n, v in mine if n not in found[eco]]
        other = [f"{n}@{v} at another version (Syft: {', '.join(sorted(found[eco][n]))})" for n, v in mine
                 if n in found[eco] and v not in found[eco][n]]  # fmt: skip
        failures += [f"{eco}: runtime component {m} not found by Syft" for m in missing]
        failures += [f"{eco}: runtime component {m}" for m in other]
        report.append(f"- {eco}: {len(mine) - len(missing) - len(other)} of {len(mine)} runtime components confirmed by Syft")
    if not checked:
        failures.append("no ecosystem could be checked: the Syft input has no pypi or npm components")
    for kind in sorted(extras):
        items = sorted(extras[kind])
        report.append(f"- found only by Syft ({kind}, {len(items)}): {', '.join(items[:25])}{' ...' if len(items) > 25 else ''}")
    return failures


def _check_scancode(
    runtime: list[tuple[str, str, str]], scancode: dict[str, Any], report: list[str]
) -> list[str]:
    failures: list[str] = []
    seen = scancode_findings(scancode)
    silent = []
    for eco, name, version in runtime:
        ids = seen.get((eco, f"{name.replace('/', '__')}@{version}"))
        if not ids:
            silent.append(f"{name}@{version}")
            continue
        denied = sorted(i for i in ids if i in POLICY["deny"] and i != "UNKNOWN")
        if denied and not accepted(name):
            failures.append(f"{eco}: ScanCode found {', '.join(denied)} in {name}@{version}")
    report.append(f"- licences: ScanCode read {len(runtime) - len(silent)} of {len(runtime)} runtime components; no licence text detected in: {', '.join(silent) or 'none'}")
    return failures


def stage(out: Path) -> int:
    sbom = json.loads(SBOM.read_text())
    missing = []
    for eco, name, version in runtime_components(sbom):
        dest = out / eco / f"{name.replace('/', '__')}@{version}"
        files: list[Path] = []
        if eco == "pypi":
            try:
                dist = md.distribution(name)
            except md.PackageNotFoundError:
                missing.append(name)
                continue
            files = [Path(str(dist.locate_file(f))) for f in dist.files or []
                     if ".dist-info" in str(f) and (LICENCE_FILE.search(f.name) or f.name == "METADATA")]  # fmt: skip
        else:
            pkg = ROOT / "web" / "node_modules" / name
            if not pkg.is_dir():
                missing.append(name)
                continue
            files = [p for p in pkg.iterdir() if p.is_file() and (LICENCE_FILE.search(p.name) or p.name == "package.json")]  # fmt: skip
        dest.mkdir(parents=True, exist_ok=True)
        for f in files:
            shutil.copy2(f, dest / f.name)
    if missing:
        print("not installed, cannot stage: " + ", ".join(missing), file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sbom_crosscheck")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("stage")
    s.add_argument("out", type=Path)
    c = sub.add_parser("check")
    c.add_argument("--syft", type=Path, action="append")
    c.add_argument("--scancode", type=Path)
    c.add_argument("--summary", type=Path)
    args = ap.parse_args(argv)
    if args.cmd == "stage":
        return stage(args.out)
    failures, report = check(
        json.loads(SBOM.read_text()), [json.loads(p.read_text()) for p in args.syft] if args.syft else None,
        json.loads(args.scancode.read_text()) if args.scancode else None,
    )  # fmt: skip
    text = "\n".join(["## SBOM cross-check", *report, *(f"- FAIL: {f}" for f in failures)]) + "\n"
    print(text, end="")
    if args.summary:
        with args.summary.open("a") as fh:
            fh.write(text)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
