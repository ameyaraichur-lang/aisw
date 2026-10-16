"""Canonical domain entities (blueprint section 8). Facts, reasoning and status stay separate."""

from __future__ import annotations

from typing import Any, Self

from pydantic import Field, model_validator

from aisw.contracts.base import NonEmpty, Sha256, Slug, StrictModel, Timestamp
from aisw.contracts.enums import (
    Confidence,
    EdgeBasis,
    FindingLifecycle,
    PolicyOutcome,
    RecommendationStatus,
    Severity,
)


class EvidenceArtifact(StrictModel):
    evidence_ref: NonEmpty
    tenant_id: Slug
    project_id: Slug
    run_id: Slug
    content_hash: Sha256
    size_bytes: int = Field(ge=0)
    media_type: NonEmpty
    source: NonEmpty
    tool_version: NonEmpty
    collected_at: Timestamp
    redacted: bool


class Asset(StrictModel):
    asset_id: Slug
    tenant_id: Slug
    project_id: Slug
    asset_type: NonEmpty
    native_ids: dict[NonEmpty, NonEmpty] = Field(min_length=1)
    environment: str | None = None
    owner: str | None = None  # None means UNKNOWN; never inferred
    owner_source: str | None = None
    criticality: str | None = None
    criticality_source: str | None = None
    technology: str | None = None
    first_seen: Timestamp
    last_seen: Timestamp
    match_confidence: Confidence

    @model_validator(mode="after")
    def _provenance(self) -> Self:
        if self.owner and not self.owner_source:
            raise ValueError("owner requires owner_source")
        if self.criticality and not self.criticality_source:
            raise ValueError("criticality requires criticality_source")
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen precedes first_seen")
        return self


class Relationship(StrictModel):
    relationship_id: Slug
    tenant_id: Slug
    source_asset_id: Slug
    target_asset_id: Slug
    relationship_type: NonEmpty
    basis: EdgeBasis
    confidence: Confidence
    evidence_ref: NonEmpty | None = None
    observed_at: Timestamp
    validation_steps: list[NonEmpty] = Field(default_factory=list)

    @model_validator(mode="after")
    def _basis_rules(self) -> Self:
        if self.basis is not EdgeBasis.INFERRED and not self.evidence_ref:
            raise ValueError("OBSERVED/CONFIGURED edges require evidence_ref")
        if self.basis is EdgeBasis.INFERRED and not self.validation_steps:
            raise ValueError("INFERRED edges require validation_steps")
        return self


class Observation(StrictModel):
    observation_id: Slug
    tenant_id: Slug
    asset_id: Slug
    source: NonEmpty
    rule_id: NonEmpty
    observed_value: Any = None
    expected_value: Any = None
    outcome: PolicyOutcome
    observed_at: Timestamp
    evidence_ref: NonEmpty
    tool_version: NonEmpty


class ControlMapping(StrictModel):
    framework: NonEmpty
    version: NonEmpty
    control_id: NonEmpty
    mapping_status: str = "NEEDS_REVIEW"


class Finding(StrictModel):
    """severity (source), business_risk, confidence, outcome and lifecycle are distinct fields."""

    finding_id: Slug
    stable_dedupe_key: NonEmpty
    tenant_id: Slug
    project_id: Slug
    run_id: Slug
    title: NonEmpty
    category: NonEmpty
    severity: Severity
    severity_source: NonEmpty
    business_risk: str | None = None  # None until an approved rubric produces it
    confidence: Confidence
    outcome: PolicyOutcome
    lifecycle: FindingLifecycle = FindingLifecycle.NEW
    affected_assets: list[Slug] = Field(min_length=1)
    evidence_refs: list[NonEmpty] = Field(min_length=1)
    control_mappings: list[ControlMapping] = Field(default_factory=list)
    assumptions: list[NonEmpty] = Field(default_factory=list)
    policy_version: NonEmpty
    first_observed: Timestamp
    last_observed: Timestamp

    @model_validator(mode="after")
    def _rules(self) -> Self:
        if self.outcome is PolicyOutcome.PASS:
            raise ValueError("a PASS outcome is not a finding")
        if self.last_observed < self.first_observed:
            raise ValueError("last_observed precedes first_observed")
        return self


class ControlAssessment(StrictModel):
    tenant_id: Slug
    run_id: Slug
    framework: NonEmpty
    version: NonEmpty
    control_id: NonEmpty
    applicability: str
    outcome: PolicyOutcome
    evidence_refs: list[NonEmpty] = Field(default_factory=list)
    policy_version: NonEmpty

    @model_validator(mode="after")
    def _pass_needs_evidence(self) -> Self:
        if self.outcome is PolicyOutcome.PASS and not self.evidence_refs:
            raise ValueError("PASS requires evidence (missing evidence is UNKNOWN, never PASS)")
        return self


class EffortEstimate(StrictModel):
    value: str | None = None  # None means UNKNOWN
    basis: str | None = None
    is_estimate: bool = True

    @model_validator(mode="after")
    def _basis(self) -> Self:
        if self.value is not None and not self.basis:
            raise ValueError("an effort estimate requires a stated basis")
        return self


class Recommendation(StrictModel):
    recommendation_id: Slug
    tenant_id: Slug
    finding_refs: list[Slug] = Field(min_length=1)  # traceability is mandatory
    target_pattern: NonEmpty | None = None
    action: NonEmpty
    alternatives: list[NonEmpty] = Field(default_factory=list)
    dependencies: list[NonEmpty] = Field(default_factory=list)
    effort: EffortEstimate = Field(default_factory=EffortEstimate)
    owner_questions: list[NonEmpty] = Field(default_factory=list)
    rollback: NonEmpty | None = None
    acceptance_test: NonEmpty | None = None
    assumptions: list[NonEmpty] = Field(default_factory=list)
    status: RecommendationStatus = RecommendationStatus.DRAFT
    # Traceability and reviewer context (all derived deterministically from validated findings)
    title: NonEmpty | None = None
    catalog_ref: NonEmpty | None = None  # the approved target-pattern entry this was built from
    current_state: NonEmpty | None = None
    affected_assets: list[Slug] = Field(default_factory=list)
    risk_tier: str | None = None  # None until the rubric had complete inputs
    validation_steps: list[NonEmpty] = Field(default_factory=list)


class Validation(StrictModel):
    validation_id: Slug
    tenant_id: Slug
    target: NonEmpty
    expected_state: NonEmpty
    test_method: NonEmpty
    actual_state: NonEmpty
    result: PolicyOutcome
    verifier: NonEmpty
    verified_at: Timestamp
    evidence_ref: NonEmpty


class RiskException(StrictModel):
    exception_id: Slug
    tenant_id: Slug
    finding_ref: Slug
    rationale: NonEmpty
    compensating_controls: list[NonEmpty] = Field(default_factory=list)
    owner: Slug
    approver: Slug
    approved_at: Timestamp
    expires_at: Timestamp

    @model_validator(mode="after")
    def _rules(self) -> Self:
        if self.expires_at <= self.approved_at:
            raise ValueError("exceptions must expire after approval")
        if self.owner == self.approver:
            raise ValueError("owner and approver must differ")
        return self


class CoverageLedger(StrictModel):
    """Counts per scope segment. Completeness is derived, never asserted."""

    tenant_id: Slug
    run_id: Slug
    segment: NonEmpty
    expected_count: int = Field(ge=0)
    discovered_count: int = Field(ge=0)
    reconciled_count: int = Field(ge=0)
    excluded_count: int = Field(ge=0)
    unsupported_count: int = Field(ge=0)
    unknown_count: int = Field(ge=0)
    assessed_by_outcome: dict[PolicyOutcome, int] = Field(default_factory=dict)
    source_ok: bool
    last_success_at: Timestamp | None = None
    reasons: list[NonEmpty] = Field(default_factory=list)

    @model_validator(mode="after")
    def _bounds(self) -> Self:
        if self.reconciled_count > self.discovered_count:
            raise ValueError("reconciled_count exceeds discovered_count")
        if any(v < 0 for v in self.assessed_by_outcome.values()):
            raise ValueError("negative outcome count")
        if not self.source_ok and not self.reasons:
            raise ValueError("a failed source must state its reasons")
        return self

    @property
    def is_complete(self) -> bool:
        return (
            self.source_ok
            and self.unknown_count == 0
            and self.unsupported_count == 0
            and self.reconciled_count + self.excluded_count >= self.expected_count
        )
