"""Scope manifest, authorization decision and execution permit (Agent 0 contracts)."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from aisw.contracts.base import (
    NonEmpty,
    Sha256,
    Slug,
    StrictModel,
    Timestamp,
    canonical_hash,
)
from aisw.contracts.enums import Decision, ManifestStatus, ProfileClass


class ScopeTarget(StrictModel):
    kind: Literal["cloud_account", "region", "asset_group", "cidr", "host", "url"]
    selector: NonEmpty
    resolved_asset_id: Slug | None = None  # set once resolved against inventory


class MaintenanceWindow(StrictModel):
    start: Timestamp
    end: Timestamp

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.end <= self.start:
            raise ValueError("window end must follow start")
        return self


class Quotas(StrictModel):
    max_concurrency: int = Field(default=1, ge=1, le=32)
    max_requests: int = Field(default=100, ge=1, le=1_000_000)
    max_duration_seconds: int = Field(default=3600, ge=1, le=86_400)


class ScopeManifestBody(StrictModel):
    """The hashed/signed content. Edits create a new version (blueprint section 8)."""

    tenant_id: Slug
    project_id: Slug
    targets: list[ScopeTarget] = Field(min_length=1)
    exclusions: list[ScopeTarget] = Field(default_factory=list)
    domains: list[Slug] = Field(min_length=1)
    allowed_adapters: list[Slug] = Field(min_length=1)
    profiles: dict[Slug, ProfileClass] = Field(min_length=1)
    allowed_ports: list[int] = Field(default_factory=list)
    internal_range_authorization: list[NonEmpty] = Field(default_factory=list)  # gap G9
    windows: list[MaintenanceWindow] = Field(default_factory=list)
    quotas: Quotas = Field(default_factory=Quotas)
    evidence_retention_days: int = Field(ge=1)
    policy_version: NonEmpty
    expires_at: Timestamp

    @model_validator(mode="after")
    def _checks(self) -> Self:
        if any(not 1 <= p <= 65535 for p in self.allowed_ports):
            raise ValueError("allowed_ports must be within 1-65535")
        if len(set(self.allowed_ports)) != len(self.allowed_ports):
            raise ValueError("duplicate allowed_ports")
        if len({t.selector for t in self.targets}) != len(self.targets):
            raise ValueError("duplicate target selectors")
        unknown = set(self.profiles) - set(self.allowed_adapters)
        if unknown:
            raise ValueError(
                f"profiles reference adapters not in allowed_adapters: {sorted(unknown)}"
            )
        return self

    def has_active_profile(self) -> bool:
        return any(p is ProfileClass.ACTIVE for p in self.profiles.values())

    def hash(self) -> str:
        return canonical_hash(self.model_dump(mode="json"))


class ScopeManifest(StrictModel):
    manifest_id: Slug
    version: int = Field(ge=1)
    status: ManifestStatus
    body: ScopeManifestBody
    canonical_hash: Sha256
    signature: NonEmpty | None = None
    key_id: Slug | None = None
    created_by: Slug
    approved_by: tuple[Slug, ...] = ()

    @model_validator(mode="after")
    def _integrity(self) -> Self:
        if self.canonical_hash != self.body.hash():
            raise ValueError("canonical_hash does not match manifest body")
        if self.status is ManifestStatus.APPROVED:
            if not (self.signature and self.key_id):
                raise ValueError("APPROVED manifest requires signature and key_id")
            if not self.approved_by:
                raise ValueError("APPROVED manifest requires approver(s)")
            if self.created_by in self.approved_by:
                raise ValueError("requester cannot approve their own manifest")
        return self


class AuthorizationDecision(StrictModel):
    decision: Decision
    reason_codes: list[NonEmpty] = Field(min_length=1)
    manifest_hash: Sha256 | None = None

    @model_validator(mode="after")
    def _deny_has_reason(self) -> Self:
        if self.decision is Decision.ALLOW and self.manifest_hash is None:
            raise ValueError("ALLOW must be bound to a manifest hash")
        return self


class ExecutionPermit(StrictModel):
    permit_id: Slug
    tenant_id: Slug
    project_id: Slug
    run_id: Slug
    manifest_hash: Sha256
    allowed_task_types: list[Slug] = Field(min_length=1)
    issued_at: Timestamp
    expires_at: Timestamp
    policy_version: NonEmpty

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("permit expires_at must follow issued_at")
        return self

    def is_valid_at(self, now: Timestamp, *, manifest_hash: str, task_type: str) -> bool:
        return (
            self.issued_at <= now < self.expires_at
            and self.manifest_hash == manifest_hash
            and task_type in self.allowed_task_types
        )
