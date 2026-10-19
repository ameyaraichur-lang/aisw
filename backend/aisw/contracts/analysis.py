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
    # Reachability edges (ADR-041) that raise exposure above the finding category's own level.
    exposure_basis: list[Slug] = Field(default_factory=list)


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


INTERNET = "internet"


class ReachEdge(StrictModel):
    """One way traffic can reach a host: from the internet or from another host (ADR-041)."""

    edge_id: Slug
    src: Slug  # INTERNET or an asset id
    dst: Slug
    basis: Literal[EdgeBasis.OBSERVED, EdgeBasis.CONFIGURED]
    ports: list[tuple[int, int]] | None  # None: every port
    via: Slug  # the firewall rule/policy asset, or the scanning adapter
    evidence_ref: NonEmpty
    note: NonEmpty | None = None


class CorrelationScenario(StrictModel):
    scenario_id: Slug
    asset_id: Slug
    title: NonEmpty
    finding_ids: list[Slug] = Field(min_length=1)
    chain: list[ChainLink] = Field(min_length=1)
    tier: Tier | None
    basis: Literal["COMPLETE", "NEEDS_POLICY_REVIEW"]
    confidence: Confidence
    assumptions: list[NonEmpty] = Field(default_factory=list)
    missing_evidence: list[NonEmpty] = Field(default_factory=list)
    validation_steps: list[NonEmpty] = Field(min_length=1)
    path: list[ReachEdge] = Field(default_factory=list)  # internet -> ... -> asset_id

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if (self.basis == "COMPLETE") != (self.tier is not None):
            raise ValueError("tier must be present exactly when basis is COMPLETE")
        if not self.path and len(self.finding_ids) < 2:
            raise ValueError(
                "a scenario needs two findings, or one finding and a reachability path"
            )
        if self.path and (
            self.path[0].src != INTERNET
            or self.path[-1].dst != self.asset_id
            or any(a.dst != b.src for a, b in zip(self.path, self.path[1:], strict=False))
        ):
            raise ValueError(
                "a path must run from the internet to the scenario's asset, hop by hop"
            )
        if {c.finding_id for c in self.chain} != set(self.finding_ids):
            raise ValueError("every finding must appear in the evidence chain, and only those")
        return self
