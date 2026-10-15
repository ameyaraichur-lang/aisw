"""Assurance verdicts and report bundle (Agents 7 and 8)."""

from __future__ import annotations

from typing import Self

from pydantic import Field, model_validator

from aisw.contracts.base import NonEmpty, Semver, Sha256, Slug, StrictModel, Timestamp
from aisw.contracts.enums import AssuranceVerdict


class AssuranceResult(StrictModel):
    tenant_id: Slug
    run_id: Slug
    item_ref: NonEmpty
    verdict: AssuranceVerdict
    defect_codes: list[NonEmpty] = Field(default_factory=list)
    missing_refs: list[NonEmpty] = Field(default_factory=list)
    stale_refs: list[NonEmpty] = Field(default_factory=list)
    validation_version: Semver
    validated_at: Timestamp

    @model_validator(mode="after")
    def _verdict_consistent(self) -> Self:
        blocking = bool(self.defect_codes or self.missing_refs or self.stale_refs)
        if self.verdict is AssuranceVerdict.ACCEPT and blocking:
            raise ValueError("ACCEPT cannot carry defects, missing or stale references")
        if self.verdict is AssuranceVerdict.REJECT and not self.defect_codes:
            raise ValueError("REJECT requires at least one defect code")
        return self


class ReportBundle(StrictModel):
    report_id: Slug
    tenant_id: Slug
    project_id: Slug
    run_id: Slug
    scope_manifest_hash: Sha256
    policy_versions: list[NonEmpty] = Field(min_length=1)
    tool_versions: list[NonEmpty] = Field(default_factory=list)
    model_versions: list[NonEmpty] = Field(default_factory=list)
    coverage_complete: bool
    limitations: list[NonEmpty] = Field(default_factory=list)
    finding_counts: dict[str, int]
    evidence_manifest_hash: Sha256
    report_hash: Sha256
    approval_state: str = "PENDING"
    generated_at: Timestamp

    @model_validator(mode="after")
    def _partial_banner(self) -> Self:
        if not self.coverage_complete and not self.limitations:
            raise ValueError("partial coverage must be disclosed in limitations")
        return self
