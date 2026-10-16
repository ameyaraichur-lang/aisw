"""Adapter capability declarations and the allowlisted registry (blueprint section 5.1).

The registry is the only way an adapter becomes callable. It refuses any capability that could
mutate infrastructure (N5: no remediation path exists in the MVP) and any adapter whose
declared profile classes are inconsistent with its read-only guarantees.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict

from aisw.contracts.enums import ProfileClass

if TYPE_CHECKING:
    from aisw.authz.net_guard import CanonicalURL, VettedTarget


class RegistryError(ValueError):
    pass


@dataclass(frozen=True)
class AdapterCapability:
    adapter_id: str
    version: str
    domains: frozenset[str]
    profiles: dict[str, ProfileClass]  # profile id -> read-only vs active class
    target_kinds: frozenset[str]  # which ScopeTarget kinds this adapter may touch
    mutates_infrastructure: bool = False  # must remain False in the MVP
    enabled: bool = True
    permission_ok: bool = True  # result of the last connector permission validation
    param_model: type[BaseModel] | None = None
    notes: tuple[str, ...] = field(default=())


class AssessmentAdapter(Protocol):
    """Versioned adapter interface; vendor quirks live inside, normalisation lives outside."""

    capability: AdapterCapability

    def execute(self, job: AdapterJob) -> Any: ...


@dataclass(frozen=True)
class AdapterJob:
    tenant_id: str
    project_id: str
    run_id: str
    task_id: str
    profile: str
    target_kind: str
    target_selector: str
    params: dict[str, Any]
    pinned_addresses: tuple[str, ...] = ()  # URL/host targets: connect ONLY to these
    request_budget: int = 0
    # Built by the gateway from the SIGNED scope: re-validates a redirect target (scope, ports,
    # egress policy, DNS) and returns the addresses to pin. Adapters must call it for every hop.
    vet_redirect: Callable[[CanonicalURL, str, int], VettedTarget] | None = None


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, AssessmentAdapter] = {}

    def register(self, adapter: AssessmentAdapter) -> None:
        cap = adapter.capability
        if cap.mutates_infrastructure:
            raise RegistryError("adapters that mutate infrastructure cannot be registered (MVP)")
        if not cap.profiles:
            raise RegistryError("adapter must declare at least one profile")
        if cap.adapter_id in self._adapters:
            raise RegistryError(f"adapter {cap.adapter_id!r} already registered")
        self._adapters[cap.adapter_id] = adapter

    def get(self, adapter_id: str) -> AssessmentAdapter | None:
        return self._adapters.get(adapter_id)

    def capability(self, adapter_id: str) -> AdapterCapability | None:
        a = self._adapters.get(adapter_id)
        return a.capability if a else None

    def ids(self) -> list[str]:
        return sorted(self._adapters)


class AdapterOutput(BaseModel):
    """What every adapter returns. ``raw`` is untrusted tool output and is never interpreted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["SUCCEEDED", "PARTIAL", "FAILED"]
    tool: str
    tool_version: str
    collected_at: datetime
    raw: dict[str, Any]
    warnings: list[str] = []
    errors: list[str] = []
