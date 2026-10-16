"""Curated mappings from pack controls to external frameworks.

Every mapping ships as a proposal (NEEDS_REVIEW). A tenant's policy owner approves or rejects it;
those decisions are append-only rows and the latest one wins. Nothing here asserts compliance.
"""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path
from typing import Any, Literal

from pydantic import model_validator
from sqlalchemy import text

from aisw.contracts.base import NonEmpty, StrictModel

MappingStatus = Literal["NEEDS_REVIEW", "APPROVED", "REJECTED"]
CATALOG_PATH = Path(__file__).parent / "mappings" / "framework-mappings-1.0.0.json"


class Framework(StrictModel):
    framework: NonEmpty
    version: NonEmpty
    name: NonEmpty
    id_pattern: NonEmpty


class Mapping(StrictModel):
    pack_control: NonEmpty
    framework: NonEmpty
    control_id: NonEmpty

    @property
    def key(self) -> str:
        return f"{self.pack_control}|{self.framework}|{self.control_id}"


class Catalog(StrictModel):
    catalog_id: NonEmpty
    version: NonEmpty
    notice: NonEmpty
    frameworks: list[Framework]
    controls: dict[str, dict[str, NonEmpty]]
    mappings: list[Mapping]

    @model_validator(mode="after")
    def _consistent(self) -> Catalog:
        fws = {f.framework: f for f in self.frameworks}
        if len(fws) != len(self.frameworks) or set(self.controls) != set(fws):
            raise ValueError("frameworks and control titles must name the same unique frameworks")
        for fw, titles in self.controls.items():
            bad = [c for c in titles if not re.fullmatch(fws[fw].id_pattern, c)]
            if bad:
                raise ValueError(f"{fw} control ids do not match the framework's format: {bad}")
        keys = [m.key for m in self.mappings]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate mapping")
        for m in self.mappings:
            if m.control_id not in self.controls.get(m.framework, {}):
                raise ValueError(f"mapping {m.key} names an unknown framework control")
        return self

    def framework(self, name: str) -> Framework:
        return next(f for f in self.frameworks if f.framework == name)

    def title(self, m: Mapping) -> str:
        return self.controls[m.framework][m.control_id]

    def for_control(self, pack_control: str) -> list[Mapping]:
        return [m for m in self.mappings if m.pack_control == pack_control]

    def get(self, key: str) -> Mapping | None:
        return next((m for m in self.mappings if m.key == key), None)


@cache
def builtin() -> Catalog:
    return Catalog.model_validate(json.loads(CATALOG_PATH.read_text(encoding="utf-8")))


def latest_reviews(conn: Any, catalog: Catalog) -> dict[str, dict[str, Any]]:
    rows = conn.execute(
        text(
            "SELECT DISTINCT ON (mapping_key) mapping_key, decision, reason, decided_by, decided_at "
            "FROM framework_mapping_reviews WHERE catalog_version=:v "
            "ORDER BY mapping_key, seq DESC"
        ),
        {"v": catalog.version},
    ).all()
    return {
        r[0]: {"status": r[1], "reason": r[2], "reviewed_by": r[3],
               "reviewed_at": r[4].isoformat()}
        for r in rows
    }  # fmt: skip


__all__ = [
    "CATALOG_PATH",
    "Catalog",
    "Framework",
    "Mapping",
    "MappingStatus",
    "builtin",
    "latest_reviews",
]
