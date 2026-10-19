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

from aisw.agents.reachability import describe_ports
from aisw.contracts.analysis import ChainLink, CorrelationScenario, ReachEdge, RiskAssessment
from aisw.contracts.domain import Finding
from aisw.contracts.enums import Confidence, EdgeBasis
from aisw.policy.rubric import TierOrder

ASSUMPTIONS = (
    "Exploitability of the listed weaknesses was not tested",
    "Whether the asset is reachable from an untrusted network was not verified",
)
REACHABLE = {
    "VERIFIED": "A scan declared as run from an untrusted network reached this asset",
    "CONFIGURED": "Firewall configuration admits traffic from untrusted networks; filtering upstream was not evaluated",
}
PATH_ASSUMPTIONS = (
    "Exploitability of the listed weaknesses was not tested",
    "Each hop is read from recorded configuration or a declared-vantage scan; no traffic was sent along the path",
)
UPSTREAM = "Filtering upstream of each host (perimeter, NAT, cloud network rules) was not evaluated"
VALIDATION_STEPS = (
    "Confirm each finding against the cited evidence with the asset owner",
    "Re-collect the evidence after any change and compare with the original observation",
)


def scenario_id(finding_ids: Sequence[str]) -> str:
    return "sc-" + hashlib.sha256("|".join(sorted(finding_ids)).encode()).hexdigest()[:16]


def _confidence(rs: Sequence[RiskAssessment]) -> Confidence:
    fresh = all(r.factors.evidence_fresh for r in rs)
    sources = min(r.factors.corroborating_sources for r in rs)
    return (
        Confidence.HIGH
        if fresh and sources >= 2
        else Confidence.MEDIUM
        if fresh
        else Confidence.LOW
    )


def build_scenarios(
    findings: Sequence[Finding],
    risks: Mapping[str, RiskAssessment],
    exposure: Mapping[str, str] | None = None,
) -> list[CorrelationScenario]:
    exposure = exposure or {}
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
        confidence = _confidence(rs)
        reach = REACHABLE.get(exposure.get(asset, ""))
        assumptions = [ASSUMPTIONS[0], reach] if reach else list(ASSUMPTIONS)
        out.append(
            CorrelationScenario(
                scenario_id=scenario_id(list(uniq)), asset_id=asset,
                title=f"{len(ordered)} weaknesses recorded on {asset}",
                finding_ids=[f.finding_id for f in ordered],
                chain=[ChainLink(finding_id=f.finding_id, evidence_ref=f.evidence_refs[0], basis=EdgeBasis.OBSERVED) for f in ordered],
                tier=TierOrder.worst(tiers) if complete else None,  # type: ignore[arg-type]
                basis="COMPLETE" if complete else "NEEDS_POLICY_REVIEW",
                confidence=confidence, assumptions=assumptions, missing_evidence=missing,
                validation_steps=list(VALIDATION_STEPS),
            )
        )  # fmt: skip
    return out


def path_scenario_id(path: Sequence[ReachEdge], finding_ids: Sequence[str]) -> str:
    key = "path|" + "|".join(e.edge_id for e in path) + "|" + "|".join(sorted(finding_ids))
    return "sc-" + hashlib.sha256(key.encode()).hexdigest()[:16]


def build_path_scenarios(
    findings: Sequence[Finding],
    risks: Mapping[str, RiskAssessment],
    paths: Mapping[str, Sequence[ReachEdge]],
) -> list[CorrelationScenario]:
    """One scenario per asset with findings that a recorded path reaches from the internet."""
    by_asset: dict[str, dict[str, Finding]] = defaultdict(dict)
    for f in findings:
        for a in f.affected_assets:
            by_asset[a][f.finding_id] = f
    out: list[CorrelationScenario] = []
    for asset, path in sorted(paths.items()):
        if asset not in by_asset or not path:
            continue
        ordered = [by_asset[asset][i] for i in sorted(by_asset[asset])]
        rs = [risks[f.finding_id] for f in ordered]
        complete = all(r.basis == "COMPLETE" for r in rs)
        tiers = [r.tier for r in rs if r.tier is not None]
        configured = any(e.basis is EdgeBasis.CONFIGURED for e in path)
        confidence = Confidence.LOW if configured else _confidence(rs)
        route = " → ".join([*(e.src for e in path), asset])
        hops = f"{len(path)} hop{'s' if len(path) > 1 else ''}"
        weak = f"{len(ordered)} recorded weakness{'es' if len(ordered) > 1 else ''}"
        steps = [f"Confirm with the network owner that {e.src} reaches {e.dst} on {describe_ports(e.ports)} "
                 f"(evidence {e.evidence_ref})" for e in path]  # fmt: skip
        out.append(
            CorrelationScenario(
                scenario_id=path_scenario_id(path, [f.finding_id for f in ordered]), asset_id=asset,
                title=f"{asset} is reachable from the internet in {hops} ({route}) with {weak}",
                finding_ids=[f.finding_id for f in ordered],
                chain=[ChainLink(finding_id=f.finding_id, evidence_ref=f.evidence_refs[0], basis=EdgeBasis.OBSERVED) for f in ordered],
                tier=TierOrder.worst(tiers) if complete else None,  # type: ignore[arg-type]
                basis="COMPLETE" if complete else "NEEDS_POLICY_REVIEW",
                confidence=confidence,
                assumptions=[*PATH_ASSUMPTIONS, *([UPSTREAM] if configured else [])],
                missing_evidence=sorted({m for r in rs for m in r.missing_evidence}),
                validation_steps=[*steps, VALIDATION_STEPS[1]], path=list(path),
            )
        )  # fmt: skip
    return out
