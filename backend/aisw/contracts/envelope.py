"""Shared agent/task envelope (Appendix G.11, contract_version 1.1) and trusted binding."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from aisw.contracts.base import (
    CONTRACT_VERSION,
    NonEmpty,
    Semver,
    Sha256,
    Slug,
    StrictModel,
    Timestamp,
)
from aisw.contracts.enums import TaskStatus
from aisw.contracts.refs import RefError, require_in_scope


class Provenance(StrictModel):
    tool_versions: list[NonEmpty] = Field(default_factory=list)
    model_id: str | None = None
    prompt_version: str | None = None
    source_hashes: list[Sha256] = Field(default_factory=list)
    input_canonical_hash: Sha256 | None = None

    @model_validator(mode="after")
    def _model_needs_prompt(self) -> Self:
        if (self.model_id is None) != (self.prompt_version is None):
            raise ValueError("model_id and prompt_version must be recorded together")
        return self


class TaskEnvelope(StrictModel):
    contract_version: Literal["1.1"] = CONTRACT_VERSION  # type: ignore[assignment]
    tenant_id: Slug
    project_id: Slug
    run_id: Slug
    task_id: Slug
    agent_id: Slug
    agent_version: Semver
    scope_manifest_id: Slug
    scope_manifest_hash: Sha256
    authorization_permit_id: Slug
    input_refs: list[NonEmpty] = Field(default_factory=list)
    policy_pack_versions: list[NonEmpty] = Field(default_factory=list)
    idempotency_key: NonEmpty
    status: TaskStatus
    started_at: Timestamp
    completed_at: Timestamp | None = None
    output_refs: list[NonEmpty] = Field(default_factory=list)
    warnings: list[NonEmpty] = Field(default_factory=list)
    errors: list[NonEmpty] = Field(default_factory=list)
    provenance: Provenance = Field(default_factory=Provenance)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.completed_at is not None and self.completed_at < self.started_at:
            raise ValueError("completed_at precedes started_at")
        if self.status in {TaskStatus.FAILED, TaskStatus.TIMED_OUT} and not self.errors:
            raise ValueError("FAILED/TIMED_OUT requires at least one error")
        if self.status is TaskStatus.PARTIAL and not (self.warnings or self.errors):
            raise ValueError("PARTIAL must name its gaps in warnings/errors")
        return self


class BindingError(ValueError):
    """Envelope claims disagree with trusted server state: reject, never reconcile."""


class TrustedContext(StrictModel):
    """Derived from server state only (never from model output or request bodies)."""

    tenant_id: Slug
    project_id: Slug
    run_id: Slug
    scope_manifest_id: Slug
    scope_manifest_hash: Sha256
    authorization_permit_id: Slug


def bind_envelope(env: TaskEnvelope, trusted: TrustedContext) -> TaskEnvelope:
    """Reject an envelope whose identity/scope claims differ from trusted state."""
    for name in type(trusted).model_fields:
        if getattr(env, name) != getattr(trusted, name):
            raise BindingError(f"envelope field {name!r} does not match trusted context")
    try:
        require_in_scope(env.input_refs, tenant_id=trusted.tenant_id, project_id=trusted.project_id)
        require_in_scope(
            env.output_refs, tenant_id=trusted.tenant_id, project_id=trusted.project_id
        )
    except RefError as exc:
        raise BindingError(str(exc)) from exc
    return env
