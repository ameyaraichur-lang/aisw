"""Common normalized shapes every adapter's ``normalize`` returns (adapter-specific parsing stays
inside the adapter; everything after this point is vendor-neutral)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass(frozen=True)
class NormalizedAsset:
    asset_id: str
    hostname: str
    attrs: dict[str, str]  # drives policy applicability (e.g. os_family, scheme)
    status: Literal["SCANNED", "UNREACHABLE", "UNSUPPORTED"]
    reason: str | None
    asset_type: str = "host"
    native_ids: dict[str, str] | None = None


@dataclass(frozen=True)
class NormalizedObservation:
    observation_id: str
    asset_id: str
    rule_id: str
    value: Any


@dataclass
class NormalizedBatch:
    assets: list[NormalizedAsset] = field(default_factory=list)
    observations: list[NormalizedObservation] = field(default_factory=list)
