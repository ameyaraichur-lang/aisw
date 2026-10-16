"""Report assembly. Counts come from the same records the report lists (reconcile by construction).

Only assurance-ACCEPTed findings appear as findings. Rejected and needs-review items are NOT
silently dropped: their counts and (for needs-review) ids/severities are disclosed so a reviewer
can see what the authoritative dataset excludes. A partial run carries a prominent banner.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from aisw.contracts.assurance import ReportBundle
from aisw.contracts.base import canonical_hash
from aisw.contracts.domain import CoverageLedger
from aisw.policy import signoffs

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
    notice: str | None = None
    # M7 analysis layer. Everything here is already assurance-ACCEPTed (or counted, never listed).
    risks: dict[str, dict[str, Any]] = field(default_factory=dict)  # finding_id -> risk assessment
    scenarios: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[dict[str, Any]] = field(default_factory=list)
    analysis_excluded: dict[str, int] = field(default_factory=dict)  # e.g. scenarios_rejected: 2
    ai: dict[str, Any] = field(default_factory=lambda: {"mode": "disabled"})
    model_versions: list[str] = field(default_factory=list)
    revision: int = 1  # > 1 after a human overruled an AI dissent and assurance re-ran (ADR-022)
    supersedes: str | None = None
    # Agent 8 / Agent 4 AI-written text that passed grounding, assurance and the validator.
    executive_summary: dict[str, Any] | None = None
    verification_questions: dict[str, dict[str, Any]] = field(default_factory=dict)


def _pending_signoffs(inp: ReportInputs) -> list[str]:
    """The sample/provisional label of every policy artefact this report actually relies on."""
    used = {f"risk-rubric-{r['rubric_version']}" for r in inp.risks.values()}
    used |= {
        f"architecture-catalog-{r['catalog_ref'].rpartition('@')[2]}" for r in inp.recommendations
    }
    register = signoffs.builtin()
    pack_signoff = inp.policy_version.replace(":", "-")
    if register.get(pack_signoff) is not None:
        used.add(pack_signoff)  # packs without a sign-off record carry their own report notice
    out = []
    for signoff_id in sorted(used):
        entry = register.get(signoff_id)
        if entry is None:
            out.append(f"{signoff_id} has no sign-off record; treat its results as unapproved.")
        elif entry.status != "APPROVED":
            out.append(f"{entry.label_while_pending} ({signoff_id}: {entry.status})")
    return out


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
    phrases = {
        "failed": "failed independent assurance and are excluded",
        "needs_review": "await review and are not authoritative",
    }
    for key, n in sorted(inp.analysis_excluded.items()):
        kind, _, status = key.partition("_")
        if n and status in phrases:
            limitations.append(f"{n} candidate {kind}(s) {phrases[status]}.")
    if inp.ai.get("mode") == "enabled" and inp.ai.get("not_shown"):
        limitations.append(
            f"AI-written summaries were unavailable or not accepted for {inp.ai['not_shown']} item(s); "
            "the deterministic description is shown instead."
        )
    validation = inp.ai.get("validation") or {}
    if validation.get("held_for_review"):
        limitations.append(
            f"The AI validator dissented on {validation['held_for_review']} item(s); accepted items "
            "among them are held for human review and are not authoritative until resolved."
        )
    if validation.get("overruled") or validation.get("upheld"):
        limitations.append(
            f"A reviewer overruled {validation.get('overruled', 0)} and upheld "
            f"{validation.get('upheld', 0)} AI validator dissent(s); each decision is recorded "
            "with its reason."
        )
    if validation.get("unavailable"):
        limitations.append(
            f"AI validation was unavailable or invalid for {validation['unavailable']} item(s); "
            "their deterministic results stand unreviewed by the model."
        )
    usage = inp.ai.get("usage") or {}
    if usage.get("budget_refused"):
        limitations.append(
            f"The run's AI token budget was exhausted: {usage['budget_refused']} model call(s) "
            "were not made and their deterministic results stand."
        )
    if usage.get("replayed"):
        limitations.append(
            f"{usage['replayed']} AI reply(ies) were replayed from a recording, not produced live."
        )
    if not inp.ledgers:
        limitations.append("No coverage information was produced.")
    limitations.extend(_pending_signoffs(inp))

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
        "tool_versions": tools, "model_versions": inp.model_versions,
        "generated_at": inp.generated_at.isoformat(),
        "banner": banner, "notice": inp.notice, "disclaimer": DISCLAIMER, "limitations": limitations,
        "coverage_complete": coverage_complete,
        "coverage": [L.model_dump(mode="json") for L in inp.ledgers],
        "controls": inp.controls,
        "findings": [
            {**f,
             **({"risk": inp.risks[f["finding_id"]]} if f["finding_id"] in inp.risks else {}),
             **({"verification_questions": inp.verification_questions[f["finding_id"]]}
                if f["finding_id"] in inp.verification_questions else {})}
            for f in inp.accepted
        ],
        "scenarios": inp.scenarios, "recommendations": inp.recommendations, "ai": inp.ai,
        "finding_counts": counts,
        "assurance": {
            "accepted": len(inp.accepted), "needs_review": len(inp.needs_review),
            "rejected": inp.rejected_count,
        },
        "pending_review": inp.needs_review, "tasks": inp.tasks, "evidence_manifest": manifest,
    }  # fmt: skip
    if inp.revision > 1:
        body["revision"] = {"number": inp.revision, "supersedes": inp.supersedes}
    if inp.executive_summary:
        body["executive_summary"] = {**inp.executive_summary, "ai_generated": True}
    suffix = f"-r{inp.revision}" if inp.revision > 1 else ""
    bundle = ReportBundle(
        report_id=f"rep-{inp.run_id}{suffix}", tenant_id=inp.tenant_id, project_id=inp.project_id,
        run_id=inp.run_id, scope_manifest_hash=inp.manifest_hash,
        policy_versions=[inp.policy_version], tool_versions=tools, model_versions=inp.model_versions,
        coverage_complete=coverage_complete, limitations=limitations, finding_counts=counts,
        evidence_manifest_hash=canonical_hash(manifest), report_hash=canonical_hash(body),
        generated_at=inp.generated_at,
    )  # fmt: skip
    return bundle, body, render_html(body)


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _risk_cell(risk: dict[str, Any] | None) -> str:
    if not risk:
        return "-"
    if risk.get("tier"):
        return _e(f"{risk['tier']} (rubric {risk['rubric_version']})")
    return _e(
        f"Not rated: criticality unknown (severity-only indication {risk['provisional_tier']})"
    )


def _narrative_html(n: dict[str, Any] | None) -> str:
    if not n:
        return ""
    claims = "".join(f"<li>{_e(c['text'])}</li>" for c in n["claims"])
    return (
        f"<p><em>AI-written summary, checked against recorded evidence (model {_e(n['model_id'])}, "
        f"prompt {_e(n['prompt_version'])}).</em> {_e(n['summary'])}</p><ul>{claims}</ul>"
    )


def _analysis_html(body: dict[str, Any]) -> str:
    out = ""
    if body.get("scenarios"):
        out += "<h2>Correlated scenarios</h2>"
        for s in body["scenarios"]:
            tier = _e(s["tier"]) if s.get("tier") else "not rated (inputs incomplete)"
            out += (
                f"<h3>{_e(s['title'])}</h3><p>Asset {_e(s['asset_id'])} | risk tier {tier} | "
                f"findings {_e(', '.join(s['finding_ids']))}</p>"
                f"<p>Assumptions: {_e('; '.join(s['assumptions']) or 'none')}</p>"
                f"<p>Validation steps: {_e('; '.join(s['validation_steps']))}</p>"
                f"{_narrative_html(s.get('narrative'))}"
            )
    if body.get("recommendations"):
        out += "<h2>Recommendations (draft, for planning only)</h2>"
        for r in body["recommendations"]:
            tier = _e(r["risk_tier"]) if r.get("risk_tier") else "not rated"
            questions = "".join(f"<li>{_e(q)}</li>" for q in r["owner_questions"])
            out += (
                f"<h3>{_e(r['title'])}</h3><p>Pattern {_e(r['catalog_ref'])} | risk tier {tier} | "
                f"findings {_e(', '.join(r['finding_refs']))} | effort: unknown</p>"
                f"<p>Target: {_e(r['target_pattern'])}</p><p>Action: {_e(r['action'])}</p>"
                f"<p>Rollback: {_e(r['rollback'])}</p><p>Acceptance test: {_e(r['acceptance_test'])}</p>"
                f"<p>Owner questions:</p><ul>{questions or '<li>None</li>'}</ul>"
                f"{_narrative_html(r.get('narrative'))}"
            )
    v = (body.get("ai") or {}).get("validation")
    if v:
        verdicts = ", ".join(f"{_e(k)}: {n}" for k, n in sorted(v["by_verdict"].items()))
        out += (
            "<h2>AI validation of agent outcomes</h2>"
            f"<p><em>An AI reviewer (model {_e(', '.join(v['models']) or 'unknown')}) checked "
            f"{v['total']} agent outcome(s). It can only add caution: a dissent holds an item for "
            f"human review, and nothing is ever marked as passing by it.</em></p><p>{verdicts}</p>"
        )
    return out


def render_html(body: dict[str, Any]) -> str:
    """Static HTML; every value is escaped (evidence-derived strings are untrusted)."""
    rows = "".join(
        f"<tr><td>{_e(f['severity'])}</td><td>{_risk_cell(f.get('risk'))}</td><td>{_e(f['title'])}</td>"
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
    if body.get("notice"):
        banner = f'<p role="note"><strong>{_e(body["notice"])}</strong></p>' + banner
    if rev := body.get("revision"):
        banner += (
            f'<p role="note">Revision {int(rev["number"])}; supersedes report '
            f"{_e(rev['supersedes'] or '')} after a human review of AI validator dissent.</p>"
        )
    counts = ", ".join(f"{_e(k)}: {v}" for k, v in body["finding_counts"].items())
    executive = ""
    if ex := body.get("executive_summary"):
        executive = (
            '<section aria-labelledby="exec-h"><h2 id="exec-h">Executive summary (AI-written)</h2>'
            f"<p>{_e(ex['summary'])}</p><p><em>Written by model {_e(ex.get('model_id') or 'unknown')}"
            "; every claim was checked against the accepted findings. The findings table below is "
            "authoritative.</em></p></section>"
        )
    questions = "".join(
        f"<li>{_e(f['title'])}<ul>"
        + "".join(f"<li>{_e(q)}</li>" for q in f["verification_questions"]["questions"])
        + "</ul></li>"
        for f in body["findings"] if f.get("verification_questions")
    )  # fmt: skip
    if questions:
        questions = (
            "<h2>Questions for asset owners (AI-written)</h2><p><em>Answering these confirms or "
            f"refutes the recorded exposure. Nothing was tested to produce them.</em></p><ul>{questions}</ul>"
        )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>{_e(body['title'])}</title></head><body><main>"
        f"<h1>{_e(body['title'])}</h1>{banner}<p>{_e(body['disclaimer'])}</p>"
        f"<p>Run {_e(body['run_id'])} | scope hash {_e(body['scope_manifest_hash'])} | "
        f"policy {_e(', '.join(body['policy_versions']))} | "
        f"report generated {_e(body['generated_at'])}</p>{executive}"
        f"<h2>Findings ({counts})</h2><table><thead><tr><th>Severity</th><th>Risk tier</th><th>Title</th>"
        f"<th>Assets</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table>"
        "<h2>Coverage</h2><table><thead><tr><th>Segment</th><th>Expected</th><th>Reconciled</th>"
        f"<th>Unknown</th><th>Unsupported</th><th>Reasons</th></tr></thead><tbody>{cov}</tbody></table>"
        f"{questions}{_analysis_html(body)}"
        f"<h2>Limitations</h2><ul>{limits}</ul></main></body></html>"
    )
