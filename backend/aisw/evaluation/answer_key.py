"""Answer keys: ground truth for a fixture estate, packaged and closed (no caller-supplied paths).

A key says what is really true of the estate, including issues the collector cannot see (an
unreachable host, a value the tool did not return). That is the point: recall measures the whole
system, collection gaps included, not just the policy engine.
"""

from __future__ import annotations

import json
from functools import cache
from importlib import resources
from typing import Literal

from pydantic import Field, model_validator

from aisw.contracts.base import NonEmpty, Slug, StrictModel

Reconciliation = Literal["MATCHED", "ABSENT", "UNEXPECTED"]
AssetStatus = Literal["SCANNED", "UNREACHABLE", "UNSUPPORTED"]
KEY_IDS = ("maple-trust-1.0.0",)


class Check(StrictModel):
    rule_id: NonEmpty
    asset_id: Slug


class AnswerKey(StrictModel):
    key_id: Slug
    fixture_set: Slug
    policy_version: NonEmpty
    note: NonEmpty
    cmdb_expected_assets: list[Slug] = Field(min_length=1)
    reconciliation: dict[Slug, Reconciliation]
    asset_status: dict[Slug, AssetStatus]
    known_issues: list[Check]
    known_clean: list[Check]

    @model_validator(mode="after")
    def _consistent(self) -> AnswerKey:
        issues = {(c.rule_id, c.asset_id) for c in self.known_issues}
        if issues & {(c.rule_id, c.asset_id) for c in self.known_clean}:
            raise ValueError("a check cannot be both a known issue and known clean")
        absent = {a for a, s in self.reconciliation.items() if s == "ABSENT"}
        if absent - set(self.cmdb_expected_assets):
            raise ValueError("an ABSENT asset must be in the CMDB list")
        return self

    @property
    def pack_id(self) -> str:
        return self.policy_version.split(":", 1)[0]


@cache
def load(key_id: str) -> AnswerKey:
    if key_id not in KEY_IDS:
        raise KeyError(key_id)
    path = resources.files("aisw.evaluation") / "answer_keys" / f"{key_id}.json"
    return AnswerKey.model_validate(json.loads(path.read_text(encoding="utf-8")))


def for_fixture(fixture_set: str | None, policy_version: str) -> AnswerKey | None:
    for key_id in KEY_IDS:
        key = load(key_id)
        if key.fixture_set == fixture_set and key.policy_version == policy_version:
            return key
    return None
