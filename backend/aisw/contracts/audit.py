"""Tamper-evident audit event (hash-chained per tenant)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from aisw.contracts.base import NonEmpty, Sha256, Slug, StrictModel, Timestamp

GENESIS_HASH = "sha256:" + "0" * 64


class AuditEventRecord(StrictModel):
    event_id: Slug
    tenant_id: Slug
    seq: int = Field(ge=1)
    actor: NonEmpty
    action: NonEmpty
    resource: NonEmpty
    before_hash: Sha256 | None = None
    after_hash: Sha256 | None = None
    correlation_id: NonEmpty
    result: Literal["SUCCESS", "DENIED", "FAILURE"]
    occurred_at: Timestamp
    prev_hash: Sha256
    event_hash: Sha256
