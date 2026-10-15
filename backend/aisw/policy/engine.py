"""Deterministic policy evaluation. No model, no network, no clock: same input, same outcome.

Packs are versioned JSON, hashed when loaded, and pinned per run as ``<pack_id>:<version>``.
Production policy engine is OPA (ADR-003); this evaluator is the interim implementation behind the
same ``PolicyEvaluator`` interface and must pass the same tests when OPA is introduced.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from importlib import resources
from typing import Any, Literal, Protocol

from pydantic import Field

from aisw.contracts.base import NonEmpty, Slug, StrictModel, canonical_hash
from aisw.contracts.domain import ControlMapping
from aisw.contracts.enums import PolicyOutcome, Severity


class Check(StrictModel):
    op: Literal["equals", "gte", "lte", "in"]
    value: Any


class PackRule(StrictModel):
    rule_id: NonEmpty
    control_id: NonEmpty
    title: NonEmpty
    category: NonEmpty
    severity: Severity
    applies_to: dict[str, list[str]] = Field(default_factory=dict)  # attr -> allowed values
    check: Check
    mappings: list[ControlMapping] = Field(default_factory=list)

    def applies(self, attrs: Mapping[str, Any]) -> bool:
        """A rule with an attribute condition applies only if the asset PROVES that attribute."""
        return all(str(attrs.get(k)) in allowed for k, allowed in self.applies_to.items())

    def evaluate_value(self, observed: Any) -> PolicyOutcome:
        if observed is None:
            return PolicyOutcome.UNKNOWN  # evidence insufficient: never pass, never fail
        op, expected = self.check.op, self.check.value
        try:
            if op == "equals":
                return PolicyOutcome.PASS if observed == expected else PolicyOutcome.FAIL
            if op == "in":
                return PolicyOutcome.PASS if observed in expected else PolicyOutcome.FAIL
            if isinstance(observed, bool) or not isinstance(observed, int | float):
                return PolicyOutcome.ERROR  # check could not execute on this value type
            ok = observed >= expected if op == "gte" else observed <= expected
            return PolicyOutcome.PASS if ok else PolicyOutcome.FAIL
        except TypeError:
            return PolicyOutcome.ERROR


class Framework(StrictModel):
    name: NonEmpty
    version: NonEmpty


class PolicyPack(StrictModel):
    pack_id: Slug
    version: NonEmpty
    description: str = ""
    framework: Framework
    rules: list[PackRule] = Field(min_length=1)

    @property
    def key(self) -> str:
        return f"{self.pack_id}:{self.version}"

    @property
    def pack_hash(self) -> str:
        return canonical_hash(self.model_dump(mode="json"))

    def rule(self, rule_id: str) -> PackRule | None:
        return next((r for r in self.rules if r.rule_id == rule_id), None)

    def control_ids(self) -> set[str]:
        return {r.control_id for r in self.rules}


class PolicyEvaluator(Protocol):
    def applicable_rules(self, pack: PolicyPack, attrs: Mapping[str, Any]) -> list[PackRule]: ...

    def evaluate_observation(
        self, pack: PolicyPack, *, rule_id: str, value: Any, attrs: Mapping[str, Any]
    ) -> PolicyOutcome | None: ...


class PythonRuleEvaluator:
    def applicable_rules(self, pack: PolicyPack, attrs: Mapping[str, Any]) -> list[PackRule]:
        return [r for r in pack.rules if r.applies(attrs)]

    def evaluate_observation(
        self, pack: PolicyPack, *, rule_id: str, value: Any, attrs: Mapping[str, Any]
    ) -> PolicyOutcome | None:
        rule = pack.rule(rule_id)
        if rule is None or not rule.applies(attrs):
            return None  # unknown or inapplicable: recorded by the caller, never silently passed
        return rule.evaluate_value(value)


class PackRegistry:
    """Only packs registered here can be pinned by a manifest."""

    def __init__(self, packs: list[PolicyPack] | None = None) -> None:
        self._packs: dict[str, PolicyPack] = {}
        for p in packs or []:
            self.add(p)

    def add(self, pack: PolicyPack) -> None:
        self._packs[pack.key] = pack

    def get(self, key: str) -> PolicyPack | None:
        return self._packs.get(key)

    def keys(self) -> list[str]:
        return sorted(self._packs)

    @classmethod
    def builtin(cls) -> PackRegistry:
        reg = cls()
        root = resources.files("aisw.policy") / "packs"
        for entry in sorted(root.iterdir(), key=lambda e: e.name):
            if entry.name.endswith(".json"):
                reg.add(PolicyPack.model_validate(json.loads(entry.read_text(encoding="utf-8"))))
        return reg
