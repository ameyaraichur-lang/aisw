"""Gate policy (hard caps) and the inventory used to resolve targets (Agent 0 inputs)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Protocol

from pydantic import BaseModel, ConfigDict


class GatePolicy(BaseModel):
    """Hard caps. Requested values may be lower, never higher (wizard step 4)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_manifest_validity: timedelta = timedelta(days=7)
    permit_ttl: timedelta = timedelta(minutes=15)
    max_concurrency: int = 4
    max_requests: int = 10_000
    max_duration_seconds: int = 7200
    max_retention_days: int = 3650
    allow_wildcards: bool = False  # stricter than the blueprint allows; opt-in only
    min_cidr_prefix_v4: int = 16
    min_cidr_prefix_v6: int = 48
    max_urls_per_manifest: int = 50


class Inventory(Protocol):
    """Resolves selectors against the project's registered inventory/sources."""

    def resolve(self, tenant_id: str, project_id: str, kind: str, selector: str) -> str | None: ...


@dataclass
class StaticInventory:
    """In-memory inventory for tests and fixture-backed runs."""

    entries: dict[tuple[str, str, str, str], str]

    def resolve(self, tenant_id: str, project_id: str, kind: str, selector: str) -> str | None:
        return self.entries.get((tenant_id, project_id, kind, selector))
