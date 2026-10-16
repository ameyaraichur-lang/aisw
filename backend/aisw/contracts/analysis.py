"""Contracts for Agent 5 (risk and correlation)."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from aisw.contracts.base import NonEmpty, Slug, StrictModel
from aisw.contracts.enums import Confidence, EdgeBasis

Tier = Literal["P0", "P1", "P2", "P3"]


class RiskFactors(StrictModel):
    severity: NonEmpty
    criticality: str | None  # owner-supplied; None means UNKNOWN, never inferred
    exposure: Literal["VERIFIED", "CONFIGURED", "UNKNOWN"]
    evidence_fresh: bool
    corroborating_sources: int = Field(ge=1)


class RiskAssessment(StrictModel):
    finding_id: Slug
    rubric_version: NonEmpty
    tier: Tier | None  # a business-risk tier exists ONLY when basis is COMPLETE
    provisional_tier: Tier  # severity-only indication, never presented as business risk
    basis: Literal["COMPLETE", "NEEDS_POLICY_REVIEW"]
    factors: RiskFactors
    missing_evidence: list[NonEmpty] = Field(default_factory=list)
    rationale: NonEmpty

    @model_validator(mode="after")
    def _no_fabricated_score(self) -> Self:
        if (self.basis == "COMPLETE") != (self.tier is not None):
            raise ValueError("tier must be present exactly when basis is COMPLETE")
        if self.basis == "COMPLETE" and self.factors.criticality is None:
            raise ValueError("a COMPLETE assessment requires owner-supplied criticality")
        return self


class ChainLink(StrictModel):
    finding_id: Slug
    evidence_ref: NonEmpty
    basis: EdgeBasis
    note: NonEmpty | None = None

    @model_validator(mode="after")
    def _inferred_is_flagged(self) -> Self:
        if self.basis is EdgeBasis.INFERRED and not self.note:
            raise ValueError("an INFERRED link must state what is assumed")
        return self


class CorrelationScenario(StrictModel):
    scenario_id: Slug
    asset_id: Slug
    title: NonEmpty
    finding_ids: list[Slug] = Field(min_length=2)
    chain: list[ChainLink] = Field(min_length=2)
    tier: Tier | None
    basis: Literal["COMPLETE", "NEEDS_POLICY_REVIEW"]
    confidence: Confidence
    assumptions: list[NonEmpty] = Field(default_factory=list)
    missing_evidence: list[NonEmpty] = Field(default_factory=list)
    validation_steps: list[NonEmpty] = Field(min_length=1)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if (self.basis == "COMPLETE") != (self.tier is not None):
            raise ValueError("tier must be present exactly when basis is COMPLETE")
        if {c.finding_id for c in self.chain} != set(self.finding_ids):
            raise ValueError("every finding must appear in the evidence chain, and only those")
        return self
