"""Build the model's input from validated deterministic objects only (never from raw evidence)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from aisw.contracts.analysis import CorrelationScenario
from aisw.contracts.domain import Finding, Recommendation
from aisw.llm.schema import Fact, NarrativeSubject


def _fact(f: Finding) -> Fact:
    return Fact(
        finding_id=f.finding_id, title=f.title, severity=f.severity.value, category=f.category,
        asset_ids=f.affected_assets, evidence_refs=f.evidence_refs,
        control_ids=[f"{m.framework} {m.control_id}" for m in f.control_mappings],
    )  # fmt: skip


def scenario_subject(s: CorrelationScenario, findings: Mapping[str, Finding]) -> NarrativeSubject:
    return NarrativeSubject(
        purpose="scenario", subject_ref=s.scenario_id, title=s.title, tier=s.tier,
        facts=[_fact(findings[i]) for i in s.finding_ids],
        context=[*s.assumptions, *s.missing_evidence],
    )  # fmt: skip


def recommendation_subject(r: Recommendation, findings: Mapping[str, Finding]) -> NarrativeSubject:
    ctx: Sequence[str] = [
        x for x in (r.target_pattern, r.current_state, r.action, *r.assumptions) if x
    ]
    return NarrativeSubject(
        purpose="recommendation", subject_ref=r.recommendation_id,
        title=r.title or r.action, tier=r.risk_tier,
        facts=[_fact(findings[i]) for i in r.finding_refs], context=list(ctx),
    )  # fmt: skip
