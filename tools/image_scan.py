"""Gate the built container images on Trivy reports (ADR-048).

  python tools/image_scan.py REPORT.json [REPORT.json ...] [--exceptions FILE] [--summary OUT.md]

Fails when an image has a CRITICAL or HIGH vulnerability that has a fixed version and no live
exception, or when Trivy did not detect the image's OS (its OS packages were then not scanned).
Unfixed CRITICAL and HIGH vulnerabilities are reported, not failed: nothing can be patched yet,
and whether they should fail is the pending image-baseline decision. An exception names the image,
the vulnerability and the package, with an owner, a reason and an expiry at most 90 days ahead;
an expired exception no longer applies.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import date, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
GATED = ("CRITICAL", "HIGH")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
MAX_EXCEPTION_DAYS = 90


def image_name(report: dict[str, Any]) -> str:
    return str(report.get("ArtifactName", "?")).rsplit(":", 1)[0]


def vulnerabilities(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [v for r in report.get("Results") or [] for v in r.get("Vulnerabilities") or []]


def load_exceptions(
    data: dict[str, Any], today: date
) -> tuple[dict[tuple[str, str, str], dict[str, Any]], list[str]]:
    live: dict[tuple[str, str, str], dict[str, Any]] = {}
    failures: list[str] = []
    for e in data.get("exceptions", []):
        key = (e["image"], e["vulnerability"], e["package"])
        missing = [f for f in ("owner", "reason", "expires") if not e.get(f)]
        if missing:
            failures.append(f"exception {'/'.join(key)} lacks {', '.join(missing)}")
            continue
        expires = date.fromisoformat(e["expires"])
        if expires > today + timedelta(days=MAX_EXCEPTION_DAYS):
            failures.append(
                f"exception {'/'.join(key)} expires {expires}, more than {MAX_EXCEPTION_DAYS} days ahead"
            )
        elif expires >= today:
            live[key] = e
    return live, failures


def check(
    reports: list[dict[str, Any]], exceptions: dict[str, Any], today: date
) -> tuple[list[str], list[str]]:
    live, failures = load_exceptions(exceptions, today)
    report: list[str] = []
    used: set[tuple[str, str, str]] = set()
    if not reports:
        failures.append("no Trivy reports given")
    for r in reports:
        name = image_name(r)
        os_ = (r.get("Metadata") or {}).get("OS") or {}
        if not os_.get("Family"):
            failures.append(
                f"{name}: Trivy did not detect the OS, so its packages were not scanned"
            )
        vulns = vulnerabilities(r)
        counts = Counter(v.get("Severity", "UNKNOWN") for v in vulns)
        base = f"{os_.get('Family', '?')} {os_.get('Name', '?')}"
        report.append(
            f"- {name} ({base}): " + ", ".join(f"{counts[s]} {s.lower()}" for s in SEVERITIES)
        )
        unfixed = []
        for v in vulns:
            if v.get("Severity") not in GATED:
                continue
            key = (name, v["VulnerabilityID"], v["PkgName"])
            what = (
                f"{v['VulnerabilityID']} in {v['PkgName']} {v.get('InstalledVersion', '')}".rstrip()
            )
            if not v.get("FixedVersion"):
                unfixed.append(what)
            elif key in live:
                used.add(key)
                report.append(
                    f"  - excepted until {live[key]['expires']} ({live[key]['owner']}): {what}, fixed in {v['FixedVersion']}"
                )
            else:
                failures.append(f"{name}: {v['Severity']} {what} is fixed in {v['FixedVersion']}")
        if unfixed:
            shown = sorted(set(unfixed))
            report.append(
                f"  - unfixed critical or high, reported only ({len(shown)}): {', '.join(shown[:15])}{' ...' if len(shown) > 15 else ''}"
            )
    for key in sorted(set(live) - used):
        report.append(f"- exception {'/'.join(key)} matched nothing and can be removed")
    return failures, report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="image_scan")
    ap.add_argument("reports", type=Path, nargs="+")
    ap.add_argument(
        "--exceptions", type=Path, default=ROOT / "deploy" / "image-scan-exceptions.json"
    )
    ap.add_argument("--summary", type=Path)
    ap.add_argument("--today", type=date.fromisoformat, default=date.today())
    args = ap.parse_args(argv)
    exceptions = json.loads(args.exceptions.read_text()) if args.exceptions.is_file() else {}
    failures, report = check(
        [json.loads(p.read_text()) for p in args.reports], exceptions, args.today
    )
    text = (
        "\n".join(
            ["## Image vulnerability scan (Trivy)", *report, *(f"- FAIL: {f}" for f in failures)]
        )
        + "\n"
    )
    print(text, end="")
    if args.summary:
        with args.summary.open("a") as fh:
            fh.write(text)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
