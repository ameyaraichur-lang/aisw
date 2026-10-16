"""Build docs/implementation/scorecard.md from ACTUAL result files (never hand-typed numbers).

Usage (from backend/, after running the suites with machine-readable reporters):
  uv run pytest --junitxml=/tmp/backend.xml
  (cd ../web && npx vitest run src --reporter=json --outputFile=/tmp/vitest.json
               && PLAYWRIGHT_JSON_OUTPUT_NAME=/tmp/playwright.json npx playwright test --reporter=json)
  python ../tools/scorecard.py --junit /tmp/backend.xml --vitest /tmp/vitest.json --playwright /tmp/playwright.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import xml.etree.ElementTree as ET  # noqa: S405 - our own pytest output, not untrusted input
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AREAS: list[tuple[str, tuple[str, ...]]] = [
    ("Contracts and schemas", ("tests.contract.",)),
    ("Scope gate, signing, permits and renewal", ("test_agent0_gate", "test_signing", "test_scope_rules", "test_manifest_db", "test_permit_renewal")),
    ("Tool gateway and SSRF/URL safety", ("test_tool_gateway", "test_net_guard", "test_url_smoke")),
    ("Tenant isolation, RBAC, audit, idempotency", ("test_tenant_isolation", "test_api_authz", "test_audit_chain", "test_analysis_security", "test_config_fail_closed")),
    ("Pipeline, evidence and assurance", ("test_pipeline_security", "test_vertical_slice", "test_evidence", "test_policy_engine", "test_coverage_report", "test_console_api", "test_migrations")),
    ("Import adapters and reconciliation", ("test_import", "test_discovery", "test_adapter_contract")),
    ("Risk, correlation, recommendations, assurance (M7)", ("test_rubric", "test_correlation", "test_architecture", "test_assurance_m7", "test_analysis_pipeline", "test_analysis_api")),
    ("LLM controls (stub model only)", ("tests.evaluation.", "test_config_ai")),
    ("Hardening: retention, export, retries, cancellation", ("test_retention", "test_hardening")),
    ("Supply chain and secrets", ("test_sbom_gate", "test_secret_scan", "test_redaction")),
]
NOT_MEASURED = [
    "Any real scanner, real Prowler/Greenbone/Wazuh/OpenSCAP/Nmap/ZAP output or live URL (M9 needs your explicit authorisation)",
    "Any real language model: quality, latency, licence review of weights",
    "Production sign-in (OIDC), key custody/rotation (OpenBao), egress firewall enforcement",
    "Docker/compose deployment, OPA, object-lock evidence storage, multi-node worker soak",
    "CI workflow has never run on a CI runner",
    "Screen-reader/manual accessibility testing (automated axe only)",
    "Syft/ScanCode scan (a lockfile-based SBOM is used); legal review of LGPL (psycopg)",
]


def area(key: str) -> str:
    for name, needles in AREAS:
        if any(n in key for n in needles):
            return name
    return "Other"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--junit", required=True)
    ap.add_argument("--vitest", required=True)
    ap.add_argument("--playwright", required=True)
    a = ap.parse_args()
    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])  # passed, failed, skipped
    for tc in ET.parse(a.junit).getroot().iter("testcase"):  # noqa: S314
        key = f"{tc.get('classname')}::{tc.get('name')}"
        bad = tc.find("failure") is not None or tc.find("error") is not None
        skip = tc.find("skipped") is not None
        counts[area(key)][1 if bad else 2 if skip else 0] += 1
    v = json.loads(Path(a.vitest).read_text())
    p = json.loads(Path(a.playwright).read_text())["stats"]
    head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout.strip())
    mut = json.loads((ROOT / "docs/implementation/mutation-log.json").read_text())
    rows = "\n".join(f"| {n} | {c[0]} | {c[1]} | {c[2]} |" for n, c in sorted(counts.items(), key=lambda kv: kv[0]))
    total = [sum(c[i] for c in counts.values()) for i in range(3)]
    mrows = "\n".join(
        f"| {k} | {len(v_)} | {sum(1 for m in v_ if m['final'] == 'CAUGHT')} | {sum(1 for m in v_ if m['first_run'] == 'SURVIVED')} |"
        for k, v_ in mut.items() if k.startswith("M")
    )  # fmt: skip
    out = f"""# Scorecard (generated from actual results: do not edit by hand)

Based on commit `{head}`{" **plus uncommitted changes**" if dirty else ""}. Regenerate with `tools/scorecard.py` (see its docstring). A pass here means an automated test passed in this repository's environment; it is not evidence about any customer environment.

## Backend (pytest)
| Area | Passed | Failed | Skipped |
|---|---|---|---|
{rows}
| **Total** | **{total[0]}** | **{total[1]}** | **{total[2]}** |

## Web
| Suite | Passed | Failed | Skipped |
|---|---|---|---|
| Unit (vitest) | {v["numPassedTests"]} | {v["numFailedTests"]} | {v.get("numPendingTests", 0)} |
| End-to-end + axe WCAG 2.2 AA (Playwright, system Chrome) | {p["expected"]} | {p["unexpected"]} | {p["skipped"]} (flaky: {p["flaky"]}) |

## Mutation checks (one-line breaks of a control; tests must fail)
| Milestone | Mutations | Caught at the end | Survived on first run (test strengthened) |
|---|---|---|---|
{mrows}

## Not measured / unverified
""" + "\n".join(f"- {x}" for x in NOT_MEASURED) + "\n"
    (ROOT / "docs/implementation/scorecard.md").write_text(out)
    print(out)


if __name__ == "__main__":
    main()
