"""Rollups from rule-level outcomes to controls, assets and findings (all deterministic)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from aisw.contracts.base import canonical_hash
from aisw.contracts.enums import PolicyOutcome
from aisw.policy.engine import PackRule, PolicyPack

# Worst outcome wins. PASS is only reachable when EVERYTHING applicable passed with evidence.
PRECEDENCE = [
    PolicyOutcome.FAIL,
    PolicyOutcome.ERROR,
    PolicyOutcome.UNKNOWN,
    PolicyOutcome.NOT_ASSESSED,
    PolicyOutcome.EXCEPTION,
    PolicyOutcome.PASS,
]


def rollup(outcomes: Iterable[PolicyOutcome]) -> PolicyOutcome:
    seen = set(outcomes)
    if not seen:
        return PolicyOutcome.NOT_APPLICABLE
    for o in PRECEDENCE:
        if o in seen:
            return o
    return PolicyOutcome.NOT_APPLICABLE  # only NOT_APPLICABLE entries


@dataclass(frozen=True)
class RuleResult:
    asset_id: str
    rule: PackRule
    outcome: PolicyOutcome
    observation_id: str | None
    evidence_ref: str | None
    observed: object = None


def dedupe_key(pack: PolicyPack, rule_id: str, asset_id: str) -> str:
    return canonical_hash({"pack": pack.pack_id, "rule": rule_id, "asset": asset_id})


def finding_id(pack: PolicyPack, rule_id: str, asset_id: str) -> str:
    return "f-" + dedupe_key(pack, rule_id, asset_id).removeprefix("sha256:")[:20]
