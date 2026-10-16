"""Agent 5 - Exposure, Vulnerability & Threat Correlation (deterministic core).

Builds evidence-backed scenarios from findings that are ALREADY recorded: every chain link cites a
finding and its evidence reference and is labelled OBSERVED. Nothing is inferred: assumptions and
missing evidence are listed instead, and a scenario's risk is complete only if every constituent
finding's risk is complete. Model-written narrative, when enabled, is a separate, validated layer.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Mapping, Sequence

from aisw.contracts.analysis import ChainLink, CorrelationScenario, RiskAssessment
from aisw.contracts.domain import Finding
from aisw.contracts.enums import Confidence, EdgeBasis
from aisw.policy.rubric import TierOrder

ASSUMPTIONS = (
    "Exploitability of the listed weaknesses was not tested",
    "Whether the asset is reachable from an untrusted network was not verified",
)
VALIDATION_STEPS = (
    "Confirm each finding against the cited evidence with the asset owner",
    "Re-collect the evidence after any change and compare with the original observation",
)


def scenario_id(finding_ids: Sequence[str]) -> str:
    return "sc-" + hashlib.sha256("|".join(sorted(finding_ids)).encode()).hexdigest()[:16]


def build_scenarios(
    findings: Sequence[Finding], risks: Mapping[str, RiskAssessment]
) -> list[CorrelationScenario]:
    by_asset: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        for a in f.affected_assets:
            by_asset[a].append(f)
    out: list[CorrelationScenario] = []
    for asset, fs in sorted(by_asset.items()):
        uniq = {f.finding_id: f for f in fs}
        if len(uniq) < 2:
            continue  # one weakness is a finding, not a scenario
        ordered = [uniq[i] for i in sorted(uniq)]
        rs = [risks[f.finding_id] for f in ordered]
        complete = all(r.basis == "COMPLETE" for r in rs)
        tiers = [r.tier for r in rs if r.tier is not None]
        missing = sorted({m for r in rs for m in r.missing_evidence})
        fresh = all(r.factors.evidence_fresh for r in rs)
        sources = min(r.factors.corroborating_sources for r in rs)
        confidence = (
            Confidence.HIGH
            if fresh and sources >= 2
            else Confidence.MEDIUM
            if fresh
            else Confidence.LOW
        )
        out.append(
            CorrelationScenario(
                scenario_id=scenario_id(list(uniq)), asset_id=asset,
                title=f"{len(ordered)} weaknesses recorded on {asset}",
                finding_ids=[f.finding_id for f in ordered],
                chain=[ChainLink(finding_id=f.finding_id, evidence_ref=f.evidence_refs[0], basis=EdgeBasis.OBSERVED) for f in ordered],
                tier=TierOrder.worst(tiers) if complete else None,  # type: ignore[arg-type]
                basis="COMPLETE" if complete else "NEEDS_POLICY_REVIEW",
                confidence=confidence, assumptions=list(ASSUMPTIONS), missing_evidence=missing,
                validation_steps=list(VALIDATION_STEPS),
            )
        )  # fmt: skip
    return out
