"""Adapter capability declarations and the allowlisted registry (blueprint section 5.1).

The registry is the only way an adapter becomes callable. It refuses any capability that could
mutate infrastructure (N5: no remediation path exists in the MVP) and any adapter whose
declared profile classes are inconsistent with its read-only guarantees.
"""

from __future__ import annotations

import re
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


class ImportReadError(Exception):
    """An uploaded file could not be used (missing, wrong kind, other project, corrupted)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


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
    # "import" adapters parse a file the operator uploaded; they never touch a network or host.
    kind: Literal["live", "import"] = "live"
    import_kinds: frozenset[str] = frozenset()  # upload kinds this adapter may read
    formats: tuple[str, ...] = ()  # documented input formats / tool versions it understands


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
    # Import adapters: tenant/project-scoped, hash-verified reader for an uploaded file, and a
    # predicate over the SIGNED scope for records the file claims to describe.
    read_import: Callable[[str, frozenset[str]], bytes] | None = None
    in_scope: Callable[[str, str], bool] | None = None


_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
ALLOWED_TARGET_KINDS = frozenset({"cloud_account", "region", "asset_group", "cidr", "host", "url"})


def validate_capability(cap: AdapterCapability) -> None:
    """Registration-time contract: anything unsafe or ambiguous is refused, not warned about."""
    if cap.mutates_infrastructure:
        raise RegistryError("adapters that mutate infrastructure cannot be registered (MVP)")
    if not _SLUG.match(cap.adapter_id) or not _SEMVER.match(cap.version):
        raise RegistryError("adapter id must be a slug and version semver")
    if not cap.profiles or not all(_SLUG.match(p) for p in cap.profiles):
        raise RegistryError("adapter must declare at least one valid profile id")
    if not cap.target_kinds or not cap.target_kinds <= ALLOWED_TARGET_KINDS:
        raise RegistryError("target kinds must be a non-empty subset of the known kinds")
    if not cap.domains:
        raise RegistryError("adapter must declare its domains")
    model = cap.param_model
    if model is not None and model.model_config.get("extra") != "forbid":
        raise RegistryError("parameter models must forbid unknown fields")
    if cap.kind == "import":
        if not cap.import_kinds or not cap.formats:
            raise RegistryError("import adapters must declare import kinds and supported formats")
        if model is None or "import_id" not in model.model_fields:
            raise RegistryError("import adapters take their input only via an import_id parameter")
    elif cap.import_kinds:
        raise RegistryError("only import adapters may declare import kinds")


@dataclass(frozen=True)
class AdapterHealth:
    adapter_id: str
    version: str
    kind: str
    status: Literal["HEALTHY", "DEGRADED", "DISABLED"]
    reasons: tuple[str, ...]


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, AssessmentAdapter] = {}

    def register(self, adapter: AssessmentAdapter) -> None:
        cap = adapter.capability
        validate_capability(cap)
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

    def health(self) -> list[AdapterHealth]:
        """Capability-level health. Live collector heartbeats are not modelled yet (see status.md)."""
        out = []
        for aid in self.ids():
            cap = self._adapters[aid].capability
            reasons = []
            if not cap.enabled:
                reasons.append("DISABLED")
            if not cap.permission_ok:
                reasons.append("PERMISSION_CHECK_FAILED")
            status: Literal["HEALTHY", "DEGRADED", "DISABLED"] = (
                "DISABLED" if not cap.enabled else "DEGRADED" if reasons else "HEALTHY"
            )
            out.append(AdapterHealth(aid, cap.version, cap.kind, status, tuple(reasons)))
        return out


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
