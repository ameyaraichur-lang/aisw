"""Report assembly. Counts come from the same records the report lists (reconcile by construction).

Only assurance-ACCEPTed findings appear as findings. Rejected and needs-review items are NOT
silently dropped: their counts and (for needs-review) ids/severities are disclosed so a reviewer
can see what the authoritative dataset excludes. A partial run carries a prominent banner.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from aisw.contracts.assurance import ReportBundle
from aisw.contracts.base import canonical_hash
from aisw.contracts.domain import CoverageLedger

DISCLAIMER = (
    "Assessment report generated from recorded evidence. It is not a certification and does not "
    "prove the assessed estate is secure. Unknown and unassessed items are listed, never passed."
)
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass(frozen=True)
class ReportInputs:
    tenant_id: str
    project_id: str
    run_id: str
    manifest_hash: str
    manifest_version: int
    policy_version: str
    pack_hash: str
    tasks: list[dict[str, Any]]
    ledgers: list[CoverageLedger]
    controls: list[dict[str, Any]]
    accepted: list[dict[str, Any]]
    needs_review: list[dict[str, Any]]
    rejected_count: int
    evidence: list[dict[str, str]]  # [{ref, hash}]
    run_partial: bool
    generated_at: datetime


def build_report(inp: ReportInputs) -> tuple[ReportBundle, dict[str, Any], str]:
    coverage_complete = all(L.is_complete for L in inp.ledgers) and bool(inp.ledgers)
    limitations: list[str] = []
    for L in inp.ledgers:
        if not L.is_complete:
            limitations.append(
                f"Segment {L.segment}: coverage incomplete (expected {L.expected_count}, "
                f"reconciled {L.reconciled_count}, unknown {L.unknown_count}, "
                f"unsupported {L.unsupported_count})."
            )
    for t in inp.tasks:
        if t["status"] not in {"SUCCEEDED"}:
            limitations.append(f"Task {t['adapter_id']} on {t['target']}: {t['status']}.")
    if inp.rejected_count:
        limitations.append(
            f"{inp.rejected_count} candidate finding(s) failed independent assurance "
            "and are excluded."
        )
    if inp.needs_review:
        limitations.append(
            f"{len(inp.needs_review)} candidate finding(s) await review and are not authoritative."
        )
    if not inp.ledgers:
        limitations.append("No coverage information was produced.")

    by_sev = {s: 0 for s in SEVERITY_ORDER}
    for f in inp.accepted:
        by_sev[f["severity"]] += 1
    counts: dict[str, int] = {"total": len(inp.accepted), **{k: v for k, v in by_sev.items() if v}}

    partial = inp.run_partial or not coverage_complete
    banner = (
        "PARTIAL ASSESSMENT: coverage is incomplete or some tasks did not finish. "
        "Findings below reflect only what was assessed."
        if partial
        else None
    )
    tools = sorted({t["tool_version"] for t in inp.tasks if t.get("tool_version")})
    manifest = sorted(inp.evidence, key=lambda e: e["ref"])
    body: dict[str, Any] = {
        "title": "AISW assessment report",
        "run_id": inp.run_id, "project_id": inp.project_id,
        "scope_manifest_hash": inp.manifest_hash, "scope_manifest_version": inp.manifest_version,
        "policy_versions": [inp.policy_version], "policy_pack_hash": inp.pack_hash,
        "tool_versions": tools, "model_versions": [],
        "generated_at": inp.generated_at.isoformat(),
        "banner": banner, "disclaimer": DISCLAIMER, "limitations": limitations,
        "coverage_complete": coverage_complete,
        "coverage": [L.model_dump(mode="json") for L in inp.ledgers],
        "controls": inp.controls, "findings": inp.accepted,
        "finding_counts": counts,
        "assurance": {
            "accepted": len(inp.accepted), "needs_review": len(inp.needs_review),
            "rejected": inp.rejected_count,
        },
        "pending_review": inp.needs_review, "tasks": inp.tasks, "evidence_manifest": manifest,
    }  # fmt: skip
    bundle = ReportBundle(
        report_id=f"rep-{inp.run_id}", tenant_id=inp.tenant_id, project_id=inp.project_id,
        run_id=inp.run_id, scope_manifest_hash=inp.manifest_hash,
        policy_versions=[inp.policy_version], tool_versions=tools, model_versions=[],
        coverage_complete=coverage_complete, limitations=limitations, finding_counts=counts,
        evidence_manifest_hash=canonical_hash(manifest), report_hash=canonical_hash(body),
        generated_at=inp.generated_at,
    )  # fmt: skip
    return bundle, body, render_html(body)


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_html(body: dict[str, Any]) -> str:
    """Static HTML; every value is escaped (evidence-derived strings are untrusted)."""
    rows = "".join(
        f"<tr><td>{_e(f['severity'])}</td><td>{_e(f['title'])}</td>"
        f"<td>{_e(', '.join(f['affected_assets']))}</td>"
        f"<td>{_e(', '.join(f['evidence_refs']))}</td></tr>"
        for f in body["findings"]
    )
    cov = "".join(
        f"<tr><td>{_e(c['segment'])}</td><td>{c['expected_count']}</td>"
        f"<td>{c['reconciled_count']}</td><td>{c['unknown_count']}</td>"
        f"<td>{c['unsupported_count']}</td><td>{_e(', '.join(c['reasons']) or '-')}</td></tr>"
        for c in body["coverage"]
    )
    limits = "".join(f"<li>{_e(x)}</li>" for x in body["limitations"]) or "<li>None recorded</li>"
    banner = f'<p role="alert"><strong>{_e(body["banner"])}</strong></p>' if body["banner"] else ""
    counts = ", ".join(f"{_e(k)}: {v}" for k, v in body["finding_counts"].items())
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>{_e(body['title'])}</title></head><body><main>"
        f"<h1>{_e(body['title'])}</h1>{banner}<p>{_e(body['disclaimer'])}</p>"
        f"<p>Run {_e(body['run_id'])} | scope hash {_e(body['scope_manifest_hash'])} | "
        f"policy {_e(', '.join(body['policy_versions']))} | "
        f"report generated {_e(body['generated_at'])}</p>"
        f"<h2>Findings ({counts})</h2><table><thead><tr><th>Severity</th><th>Title</th>"
        f"<th>Assets</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table>"
        "<h2>Coverage</h2><table><thead><tr><th>Segment</th><th>Expected</th><th>Reconciled</th>"
        f"<th>Unknown</th><th>Unsupported</th><th>Reasons</th></tr></thead><tbody>{cov}</tbody></table>"
        f"<h2>Limitations</h2><ul>{limits}</ul></main></body></html>"
    )
