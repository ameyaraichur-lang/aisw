"""Validation packets: what each agent's reviewer sees (ADR-021). Pure functions over stored records.

Targets carry deterministic fields plus, for findings, the observed and expected values the rule
compared (truncated; the whole packet is redacted again before it is sent). Raw evidence blobs are
never included.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from aisw.agents.registry import AGENTS
from aisw.contracts.analysis import CorrelationScenario, RiskAssessment
from aisw.contracts.domain import CoverageLedger, Finding, Recommendation
from aisw.llm.schema import NarrativeOutput, NarrativeSubject
from aisw.llm.validation import ValidationPacket, ValidationTarget

MAX_VALUE_CHARS = 300

FOCUS: dict[int, str] = {
    0: "Scope and authorisation. Check that the approved scope is no broader than the tasks that "
    "ran need, that every task's adapter and type is inside the manifest and the permit, that "
    "only read-only profiles were used, and that the approval was separate from the author.",
    1: "Coverage and reconciliation. Check that the counts are internally consistent, that gaps "
    "(unknown, unsupported, failed sources) are explained by the stated reasons, and flag "
    "anomalies such as a successful source that discovered nothing.",
    2: "Host and OS configuration findings. Check that the observed value really contradicts the "
    "expected value, that severity fits the weakness, and that the control mapping is plausible.",
    3: "Cloud posture findings. Check that the observed configuration supports the failure, that "
    "public exposure is actually evidenced, and that severity and control mapping fit.",
    4: "Network, perimeter and web findings. Check that the observed exposure supports the "
    "failure, that ports and services are consistent, and that severity fits.",
    5: "Correlated scenarios. Check each chain link is supported by its finding, that "
    "exploitability is not overstated, that the tier follows from the stated rubric factors, and "
    "whether compensating controls are missing from the reasoning.",
    6: "Draft recommendations. Check traceability to the cited findings, feasibility against the "
    "stated current state, and that rollback and acceptance test are meaningful.",
    7: "AI-written summaries and verification questions. Check every claim against the facts "
    "given for it; flag claims that are unsupported or overstated, and questions that presume "
    "an answer or that the owner could not answer.",
    8: "The AI-written executive summary of the report. Check that it reflects the facts and the "
    "coverage stated for the whole run without overstating or understating severity, and that "
    "it does not hide incomplete coverage.",
}


def _name(agent_id: int) -> str:
    return next(a.name for a in AGENTS if a.agent_id == agent_id)


def _clip(value: Any) -> str | None:
    if value is None:
        return None
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    return text if len(text) <= MAX_VALUE_CHARS else text[:MAX_VALUE_CHARS] + "...[truncated]"


def _fact(f: Finding) -> dict[str, Any]:
    return {
        "finding_id": f.finding_id, "title": f.title, "outcome": f.outcome.value,
        "severity": f.severity.value,
        "category": f.category, "asset_ids": f.affected_assets, "evidence_refs": f.evidence_refs,
    }  # fmt: skip


def chunk(
    agent_id: int, targets: Sequence[ValidationTarget], *, batch: int, max_items: int
) -> list[ValidationPacket]:
    kept = list(targets)[:max_items]
    return [
        ValidationPacket(
            packet_id=f"a{agent_id}-b{n}",
            agent_id=agent_id,
            agent_name=_name(agent_id),
            focus=FOCUS[agent_id],
            targets=kept[i : i + batch],
        )  # fmt: skip
        for n, i in enumerate(range(0, len(kept), batch), start=1)
    ]


def scope_target(
    manifest_id: str, manifest: Mapping[str, Any], *, author: str, approvers: Sequence[str],
    permit: Mapping[str, Any] | None, tasks: Sequence[Mapping[str, Any]], expected_assets: int,
) -> ValidationTarget:  # fmt: skip
    """Agent 0: the authorised scope against what actually ran. Values are clipped like evidence."""
    data = {
        "manifest_targets": [_clip(t) for t in manifest.get("targets", [])],
        "exclusions": [_clip(x) for x in manifest.get("exclusions", [])],
        "domains": manifest.get("domains", []),
        "allowed_adapters": manifest.get("allowed_adapters", []),
        "profiles": _clip(manifest.get("profiles", {})),
        "expires_at": manifest.get("expires_at"),
        "expected_assets": expected_assets,
        "approval_separate_from_author": bool(approvers) and author not in approvers,
        "approver_count": len(approvers),
        "permit_task_types": list((permit or {}).get("allowed_task_types", [])),
        "tasks": [{"adapter_id": t["adapter_id"], "task_type": t["task_type"],
                   "status": t["status"]} for t in tasks],
    }  # fmt: skip
    return ValidationTarget(target_ref=f"scope:{manifest_id}", kind="scope", data=data)


def coverage_targets(ledgers: Iterable[CoverageLedger]) -> list[ValidationTarget]:
    out = []
    for n, L in enumerate(sorted(ledgers, key=lambda x: x.segment), start=1):
        data = L.model_dump(mode="json", exclude={"tenant_id", "run_id", "last_success_at"})
        out.append(ValidationTarget(target_ref=f"coverage:{n}", kind="coverage", data=data))
    return out


def finding_targets(
    findings: Iterable[Finding],
    observations: Mapping[str, tuple[Any, Any]],
) -> list[ValidationTarget]:
    """``observations`` maps finding_id -> (observed_value, expected_value) of its own rule."""
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    out = []
    for f in sorted(findings, key=lambda x: (order.get(x.severity.value, 9), x.finding_id)):
        observed, expected = observations.get(f.finding_id, (None, None))
        data = {
            **_fact(f), "outcome": f.outcome.value, "confidence": f.confidence,
            "controls": [f"{m.framework} {m.control_id}" for m in f.control_mappings],
            "assumptions": f.assumptions, "observed_value": _clip(observed),
            "expected_value": _clip(expected),
        }  # fmt: skip
        out.append(
            ValidationTarget(
                target_ref=f"finding:{f.finding_id}",
                kind="finding",
                data=data,
                evidence_refs=f.evidence_refs,
            )  # fmt: skip
        )
    return out


def scenario_targets(
    scenarios: Iterable[CorrelationScenario],
    findings: Mapping[str, Finding],
    risks: Mapping[str, RiskAssessment],
) -> list[ValidationTarget]:
    out = []
    for s in scenarios:
        facts = [findings[i] for i in s.finding_ids if i in findings]
        data = {
            "title": s.title, "asset_id": s.asset_id, "tier": s.tier, "basis": s.basis,
            "confidence": s.confidence, "chain": [c.model_dump(mode="json") for c in s.chain],
            "assumptions": s.assumptions, "missing_evidence": s.missing_evidence,
            "findings": [_fact(f) for f in facts],
            "risk_factors": {i: risks[i].factors.model_dump(mode="json")
                             for i in s.finding_ids if i in risks},
        }  # fmt: skip
        refs = sorted({r for f in facts for r in f.evidence_refs})
        out.append(
            ValidationTarget(
                target_ref=f"scenario:{s.scenario_id}",
                kind="scenario",
                data=data,
                evidence_refs=refs,
            )  # fmt: skip
        )
    return out


def recommendation_targets(
    recs: Iterable[Recommendation], findings: Mapping[str, Finding]
) -> list[ValidationTarget]:
    out = []
    for r in recs:
        facts = [findings[i] for i in r.finding_refs if i in findings]
        data = {
            "title": r.title, "action": r.action, "target_pattern": r.target_pattern,
            "current_state": r.current_state, "rollback": r.rollback,
            "acceptance_test": r.acceptance_test, "risk_tier": r.risk_tier,
            "owner_questions": r.owner_questions, "assumptions": r.assumptions,
            "validation_steps": r.validation_steps, "findings": [_fact(f) for f in facts],
        }  # fmt: skip
        refs = sorted({x for f in facts for x in f.evidence_refs})
        out.append(
            ValidationTarget(
                target_ref=f"recommendation:{r.recommendation_id}",
                kind="recommendation",
                data=data,
                evidence_refs=refs,
            )  # fmt: skip
        )
    return out


def narrative_targets(
    items: Iterable[tuple[str, NarrativeSubject, NarrativeOutput]],
) -> list[ValidationTarget]:
    """``items`` are (narrative_id, subject, validated output)."""
    out = []
    for narrative_id, subject, output in items:
        data = {
            "about": f"{subject.purpose} {subject.subject_ref}: {subject.title}",
            "tier": subject.tier, "summary": output.summary,
            "claims": [c.model_dump(mode="json") for c in output.claims],
            "open_questions": output.open_questions,
            "facts_are": "recorded weaknesses: each title states a requirement that was NOT met",
            "facts": [f.model_dump(mode="json") for f in subject.facts],
            "context": subject.context,
        }  # fmt: skip
        refs = sorted({r for f in subject.facts for r in f.evidence_refs})
        out.append(
            ValidationTarget(
                target_ref=f"narrative:{narrative_id}",
                kind="narrative",
                data=data,
                evidence_refs=refs,
            )  # fmt: skip
        )
    return out
