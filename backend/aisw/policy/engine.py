"""Deterministic policy evaluation. No model, no network, no clock: same input, same outcome.

Packs are versioned JSON, hashed when loaded, and pinned per run as ``<pack_id>:<version>``.
Production policy engine is OPA (ADR-003); this evaluator is the interim implementation behind the
same ``PolicyEvaluator`` interface and must pass the same tests when OPA is introduced.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from importlib import resources
from typing import Any, Literal, Protocol

from pydantic import Field, model_validator

from aisw.contracts.base import NonEmpty, Slug, StrictModel, canonical_hash
from aisw.contracts.domain import ControlMapping
from aisw.contracts.enums import PolicyOutcome, Severity


def _is_number(v: Any) -> bool:
    return isinstance(v, int | float) and not isinstance(v, bool)


def json_equal(a: Any, b: Any) -> bool:
    """Equality as JSON (and Rego) define it: true is not 1, numbers compare by value."""
    if _is_number(a) and _is_number(b):
        return bool(a == b)
    if type(a) is not type(b):
        return False
    if isinstance(a, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b, strict=True))
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    return bool(a == b)


RULE_NAME = re.compile(r"[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*")


class Check(StrictModel):
    """``rego`` names a domain rule (``<domain>.<rule>``) that only the OPA engine can run."""

    op: Literal["equals", "gte", "lte", "in", "disjoint", "rego"]
    value: Any

    @model_validator(mode="after")
    def _typed(self) -> Check:
        if self.op in {"gte", "lte"} and not _is_number(self.value):
            raise ValueError(f"{self.op} needs a numeric value")
        if self.op in {"in", "disjoint"} and not isinstance(self.value, list):
            raise ValueError(f"{self.op} needs a list value")
        if self.op == "rego":
            v = self.value
            if not (
                isinstance(v, dict) and set(v) <= {"rule", "params"}
                and isinstance(v.get("rule"), str) and RULE_NAME.fullmatch(v["rule"])
                and isinstance(v.get("params", {}), dict)
            ):  # fmt: skip
                raise ValueError('rego needs {"rule": "<domain>.<rule>", "params": {...}}')
        return self


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
        if op == "rego":
            return PolicyOutcome.ERROR  # a domain rule needs the OPA engine (ADR-031)
        if op == "equals":
            return PolicyOutcome.PASS if json_equal(observed, expected) else PolicyOutcome.FAIL
        if op == "in":
            hit = any(json_equal(observed, e) for e in expected)
            return PolicyOutcome.PASS if hit else PolicyOutcome.FAIL
        if op == "disjoint":  # observed list shares nothing with the pack's list
            if not isinstance(observed, list):
                return PolicyOutcome.ERROR
            shared = any(json_equal(o, e) for o in observed for e in expected)
            return PolicyOutcome.FAIL if shared else PolicyOutcome.PASS
        if not _is_number(observed):
            return PolicyOutcome.ERROR  # check could not execute on this value type
        ok = observed >= expected if op == "gte" else observed <= expected
        return PolicyOutcome.PASS if ok else PolicyOutcome.FAIL


class Framework(StrictModel):
    name: NonEmpty
    version: NonEmpty


class PolicyPack(StrictModel):
    pack_id: Slug
    version: NonEmpty
    description: str = ""
    report_notice: str | None = None  # shown prominently on every report from this pack
    framework: Framework
    rules: list[PackRule] = Field(min_length=1)

    @property
    def key(self) -> str:
        return f"{self.pack_id}:{self.version}"

    @property
    def needs_opa(self) -> bool:
        return any(r.check.op == "rego" for r in self.rules)

    @property
    def pack_hash(self) -> str:
        return canonical_hash(self.model_dump(mode="json"))

    def rule(self, rule_id: str) -> PackRule | None:
        return next((r for r in self.rules if r.rule_id == rule_id), None)

    def control_ids(self) -> set[str]:
        return {r.control_id for r in self.rules}


class PolicyEvaluator(Protocol):
    runs_rego: bool

    def applicable_rules(self, pack: PolicyPack, attrs: Mapping[str, Any]) -> list[PackRule]: ...

    def evaluate_observation(
        self, pack: PolicyPack, *, rule_id: str, value: Any, attrs: Mapping[str, Any]
    ) -> PolicyOutcome | None: ...


class PythonRuleEvaluator:
    runs_rego = False

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
