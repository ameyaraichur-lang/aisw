"""AVP trigger policy (versioned configuration): which agent outcomes the reviewer model checks.

A rule only ever selects targets for review; skipping a target leaves it to the deterministic
validator, which already covers everything. Sampling is a hash of the policy version and the
target reference, so the same run always samples the same items.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field, model_validator

from aisw.contracts.base import NonEmpty, StrictModel
from aisw.llm.validation import ValidationTarget

POLICY_DIR = Path(__file__).parent / "policy"
DEFAULT_VERSION = "1.0.0"
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class Rule(StrictModel):
    always: bool | None = None
    coverage_below: float | None = Field(default=None, gt=0, le=1)
    zero_asset_anomaly: bool | None = None
    source_failed: bool | None = None
    has_gaps: bool | None = None
    severity_at_least: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] | None = None
    outcome_in: list[NonEmpty] | None = None
    tier_in: list[Literal["P0", "P1", "P2", "P3"]] | None = None
    sample_rate: float | None = Field(default=None, gt=0, le=1)

    @model_validator(mode="after")
    def _one(self) -> Rule:
        if len(self.model_dump(exclude_none=True)) != 1:
            raise ValueError("a trigger rule has exactly one condition")
        return self

    @property
    def name(self) -> str:
        ((k, v),) = self.model_dump(exclude_none=True).items()
        return k if v is True else f"{k}={v}"


class AgentTriggers(StrictModel):
    rules: list[Rule] = Field(min_length=1)
    why: NonEmpty


class TriggerPolicy(StrictModel):
    version: NonEmpty
    status: NonEmpty
    priority: list[int]
    agents: dict[int, AgentTriggers]
    sha256: str = ""

    @model_validator(mode="after")
    def _complete(self) -> TriggerPolicy:
        expected = set(range(9))
        if set(self.agents) != expected or sorted(self.priority) != sorted(expected):
            raise ValueError("the trigger policy must cover agents 0-8 exactly once")
        return self


@dataclass(frozen=True)
class Decision:
    agent_id: int
    target_ref: str
    triggered: bool
    rule: str


@cache
def load(version: str = DEFAULT_VERSION) -> TriggerPolicy:
    path = POLICY_DIR / f"triggers-{version}.yaml"
    raw = path.read_bytes()
    body = yaml.safe_load(raw)
    return TriggerPolicy.model_validate({**body, "sha256": hashlib.sha256(raw).hexdigest()})


def _sampled(policy: TriggerPolicy, ref: str, rate: float) -> bool:
    h = hashlib.sha256(f"{policy.version}|{ref}".encode()).digest()
    return int.from_bytes(h[:8], "big") / 2**64 < rate


def _matches(rule: Rule, t: ValidationTarget, policy: TriggerPolicy) -> bool:
    d: dict[str, Any] = t.data
    if rule.always:
        return True
    if rule.coverage_below is not None:
        expected = int(d.get("expected_count") or 0)
        return expected > 0 and int(d.get("reconciled_count") or 0) / expected < rule.coverage_below
    if rule.zero_asset_anomaly:
        return bool(d.get("source_ok")) and int(d.get("discovered_count") or 0) == 0
    if rule.source_failed:
        return d.get("source_ok") is False
    if rule.has_gaps:
        return bool(d.get("reasons"))
    if rule.severity_at_least is not None:
        rank = SEVERITY_RANK.get(str(d.get("severity")), 9)
        return rank <= SEVERITY_RANK[rule.severity_at_least]
    if rule.outcome_in is not None:
        return str(d.get("outcome")) in rule.outcome_in
    if rule.tier_in is not None:
        return d.get("tier") in rule.tier_in
    if rule.sample_rate is not None:
        return _sampled(policy, t.target_ref, rule.sample_rate)
    return False  # unreachable: the model allows exactly one condition


def select(
    policy: TriggerPolicy, agent_id: int, targets: Iterable[ValidationTarget]
) -> tuple[list[ValidationTarget], list[Decision]]:
    kept: list[ValidationTarget] = []
    decisions: list[Decision] = []
    rules = policy.agents[agent_id].rules
    for t in targets:
        hit = next((r for r in rules if _matches(r, t, policy)), None)
        decisions.append(
            Decision(
                agent_id, t.target_ref, hit is not None, hit.name if hit else "no_rule_matched"
            )
        )
        if hit is not None:
            kept.append(t)
    return kept, decisions


def order(policy: TriggerPolicy, agent_ids: Sequence[int]) -> list[int]:
    """Indices of ``agent_ids`` in policy priority order (stable within an agent)."""
    rank = {a: i for i, a in enumerate(policy.priority)}
    return sorted(range(len(agent_ids)), key=lambda i: rank[agent_ids[i]])
