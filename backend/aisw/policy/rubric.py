"""Versioned, deterministic risk rubric (blueprint section 10). No model, no hidden weights.

* score = severity + owner criticality + exposure; tiers come from fixed thresholds
* if criticality is not known the tier is NOT produced: basis NEEDS_POLICY_REVIEW, with a clearly
  separate severity-only ``provisional_tier`` that is never presented as business risk
* ``assess`` is pure, so Agent 7 can recompute it from the stored factors and compare
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Literal

from pydantic import Field

from aisw.contracts.analysis import RiskAssessment, RiskFactors, Tier
from aisw.contracts.base import NonEmpty, StrictModel


class Rubric(StrictModel):
    version: NonEmpty
    description: str = ""
    severity: dict[str, int]
    criticality: dict[str, int]
    exposure: dict[str, int]
    thresholds: dict[str, int]
    provisional_by_severity: dict[str, Tier]
    exposure_by_category: dict[str, Literal["VERIFIED", "CONFIGURED"]] = Field(default_factory=dict)


def builtin(version: str = "1.0.0") -> Rubric:
    text = (resources.files("aisw.policy") / "rubrics" / f"risk-rubric-{version}.json").read_text(
        encoding="utf-8"
    )
    return Rubric.model_validate(json.loads(text))


def normalize_criticality(raw: str | None, rubric: Rubric) -> str | None:
    """Only the rubric's own labels count; free text such as "tier-1" is UNKNOWN, not guessed."""
    if raw is None:
        return None
    v = raw.strip().lower()
    return v if v in rubric.criticality else None


def exposure_for(category: str, rubric: Rubric) -> Literal["VERIFIED", "CONFIGURED", "UNKNOWN"]:
    return rubric.exposure_by_category.get(category, "UNKNOWN")


def _tier(score: int, rubric: Rubric) -> Tier:
    t = rubric.thresholds
    return (
        "P0"
        if score >= t["P0"]
        else "P1"
        if score >= t["P1"]
        else "P2"
        if score >= t["P2"]
        else "P3"
    )


def assess(finding_id: str, factors: RiskFactors, rubric: Rubric) -> RiskAssessment:
    sev = factors.severity.upper()
    if sev not in rubric.severity:
        raise ValueError(f"severity {sev!r} is not in rubric {rubric.version}")
    provisional = rubric.provisional_by_severity[sev]
    missing: list[str] = []
    if factors.exposure == "UNKNOWN":
        missing.append(
            "Exposure to untrusted networks was not verified; it is scored as 0, not assumed"
        )
    elif factors.exposure == "CONFIGURED" and factors.exposure_basis:
        missing.append(
            "Exposure is read from firewall configuration; filtering upstream was not evaluated"
        )
    if not factors.evidence_fresh:
        missing.append("Supporting evidence is older than the freshness window")
    if factors.criticality is None:
        missing.append(
            "Owner-supplied asset criticality is unknown; no business-risk tier is produced"
        )
        return RiskAssessment(
            finding_id=finding_id, rubric_version=rubric.version, tier=None, provisional_tier=provisional,
            basis="NEEDS_POLICY_REVIEW", factors=factors, missing_evidence=missing,
            rationale=f"Severity {sev} only indicates {provisional}; business risk needs asset criticality (policy review).",
        )  # fmt: skip
    score = (
        rubric.severity[sev]
        + rubric.criticality[factors.criticality]
        + rubric.exposure[factors.exposure]
    )
    tier = _tier(score, rubric)
    return RiskAssessment(
        finding_id=finding_id, rubric_version=rubric.version, tier=tier, provisional_tier=provisional,
        basis="COMPLETE", factors=factors, missing_evidence=missing,
        rationale=(f"severity {sev} ({rubric.severity[sev]}) + criticality {factors.criticality} "
                   f"({rubric.criticality[factors.criticality]}) + exposure {factors.exposure} "
                   f"({rubric.exposure[factors.exposure]}) = {score} -> {tier}"),
    )  # fmt: skip


@dataclass(frozen=True)
class TierOrder:
    ORDER = ("P0", "P1", "P2", "P3")

    @classmethod
    def worst(cls, tiers: list[str]) -> str:
        return min(tiers, key=cls.ORDER.index)
