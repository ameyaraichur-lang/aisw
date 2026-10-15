"""Fixture adapter: replays synthetic scanner output from packaged files. No network, no sockets.

It exists to prove the full pipeline (scope -> gateway -> evidence -> policy -> coverage -> report)
without any scanner or credentials. It is NOT evidence that any real tool integration works.
The fixture set is a closed enum, so a caller can never make it read an arbitrary path.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import resources
from typing import Any, Literal

from aisw.contracts.base import StrictModel
from aisw.contracts.enums import ProfileClass
from aisw.gateway.registry import AdapterCapability, AdapterJob, AdapterOutput

FixtureSet = Literal["baseline-ok", "baseline-partial", "baseline-zero", "baseline-injection"]
ADAPTER_ID = "fixture"
PROFILE_ID = "FIXTURE_BASELINE"


class FixtureParams(StrictModel):
    fixture_set: FixtureSet = "baseline-ok"


@dataclass(frozen=True)
class NormalizedAsset:
    asset_id: str
    hostname: str
    attrs: dict[str, str]
    status: Literal["SCANNED", "UNREACHABLE", "UNSUPPORTED"]
    reason: str | None


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


class FixtureAdapter:
    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self.capability = AdapterCapability(
            adapter_id=ADAPTER_ID, version="0.1.0", domains=frozenset({"host"}),
            profiles={PROFILE_ID: ProfileClass.READ_ONLY}, target_kinds=frozenset({"asset_group"}),
            param_model=FixtureParams,
        )  # fmt: skip

    def estimate_requests(self, params: dict[str, Any]) -> int:
        return 1

    def execute(self, job: AdapterJob) -> AdapterOutput:
        params = FixtureParams.model_validate(job.params)
        raw = json.loads(
            (resources.files("aisw.adapters") / "fixture_data" / f"{params.fixture_set}.json")
            .read_text(encoding="utf-8")
        )  # fmt: skip
        hosts: list[dict[str, Any]] = raw.get("hosts", [])
        warnings = [
            f"{h['id']}: {h['state']} ({h.get('reason', 'no reason given')})"
            for h in hosts
            if h.get("state") != "scanned"
        ]
        return AdapterOutput(
            status="PARTIAL" if warnings else "SUCCEEDED",
            tool=raw["scanner"], tool_version=raw["version"], collected_at=self._clock(),
            raw=raw, warnings=warnings,
        )  # fmt: skip

    def normalize(self, output: AdapterOutput, *, run_id: str, task_id: str) -> NormalizedBatch:
        batch = NormalizedBatch()
        for h in output.raw.get("hosts", []):
            status = {"scanned": "SCANNED", "unreachable": "UNREACHABLE"}.get(
                str(h.get("state")), "UNSUPPORTED"
            )
            asset_id = str(h["id"])
            batch.assets.append(
                NormalizedAsset(
                    asset_id=asset_id,
                    hostname=str(h.get("hostname", asset_id)),
                    attrs={"os_family": str(h.get("os_family", "unknown"))},
                    status=status,  # type: ignore[arg-type]
                    reason=h.get("reason"),
                )  # fmt: skip
            )
            if status != "SCANNED":
                continue
            for rule_id, value in sorted((h.get("checks") or {}).items()):
                oid = hashlib.sha256(
                    f"{run_id}|{task_id}|{asset_id}|{rule_id}".encode()
                ).hexdigest()
                batch.observations.append(
                    NormalizedObservation(f"o-{oid[:24]}", asset_id, str(rule_id), value)
                )
        return batch
