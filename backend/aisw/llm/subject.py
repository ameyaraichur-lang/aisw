"""Build the model's input from validated deterministic objects only (never from raw evidence)."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from aisw.contracts.analysis import CorrelationScenario
from aisw.contracts.domain import CoverageLedger, Finding, Recommendation
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


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
EXECUTIVE_MAX_FACTS = 12


def _by_severity(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity.value, 9), f.finding_id))


def verification_subject(f: Finding, observed: tuple[Any, Any] | None) -> NarrativeSubject:
    """Agent 4: questions an owner can answer to confirm one exposure finding."""
    obs, exp = observed or (None, None)
    context = [f"Observed: {_short(obs)}", f"Expected: {_short(exp)}"] if observed else []
    if ports := _ports(obs):
        context.append("Observed open ports: " + ", ".join(f"port {p}" for p in ports))
    if ports := _ports(exp):
        context.append("Ports named in the requirement: " + ", ".join(f"port {p}" for p in ports))
    return NarrativeSubject(
        purpose="verification", subject_ref=f.finding_id, title=f.title, tier=None,
        facts=[_fact(f)], context=context,
    )  # fmt: skip


def executive_subject(
    findings: Iterable[Finding], ledgers: Sequence[CoverageLedger]
) -> NarrativeSubject | None:
    """Agent 8: one summary of the run, over its most severe findings and its coverage."""
    ranked = _by_severity(findings)
    if not ranked:
        return None
    counts: dict[str, int] = {}
    for f in ranked:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    ordered = sorted(counts.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))
    tally = ", ".join(f"{n} {s.lower()}" for s, n in ordered)
    assets = {a for f in ranked for a in f.affected_assets}
    context = [f"{len(ranked)} failed check(s) on {len(assets)} asset(s): {tally}."]
    for led in ledgers:
        context.append(
            f"Coverage {led.segment}: {led.reconciled_count} of {led.expected_count} expected "
            f"asset(s) reconciled; {'complete' if led.is_complete else 'incomplete'}."
        )
    return NarrativeSubject(
        purpose="executive", subject_ref="executive", title="Executive summary", tier=None,
        facts=[_fact(f) for f in ranked[:EXECUTIVE_MAX_FACTS]], context=context,
    )  # fmt: skip


def _ports(value: Any) -> list[int]:
    """A list of port numbers, stated so the grounding check can see them (it reads "port N")."""
    if (
        isinstance(value, list)
        and value
        and all(isinstance(p, int) and not isinstance(p, bool) and 0 < p < 65536 for p in value)
    ):
        return sorted(set(value))[:20]
    return []


def _short(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    return text if len(text) <= 200 else text[:200] + "...[truncated]"


def recommendation_subject(r: Recommendation, findings: Mapping[str, Finding]) -> NarrativeSubject:
    ctx: Sequence[str] = [
        x for x in (r.target_pattern, r.current_state, r.action, *r.assumptions) if x
    ]
    return NarrativeSubject(
        purpose="recommendation", subject_ref=r.recommendation_id,
        title=r.title or r.action, tier=r.risk_tier,
        facts=[_fact(findings[i]) for i in r.finding_refs], context=list(ctx),
    )  # fmt: skip
