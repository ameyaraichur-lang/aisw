"""AVP trigger policy: versioned configuration, one condition per rule, deterministic sampling."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from pydantic import ValidationError

from aisw.llm.triggers import POLICY_DIR, Rule, TriggerPolicy, load, order, select
from aisw.llm.validation import ValidationTarget


def t(ref: str, kind: str = "finding", **data: Any) -> ValidationTarget:
    return ValidationTarget(target_ref=ref, kind=kind, data=data)


def hits(agent: int, *targets: ValidationTarget) -> dict[str, str]:
    _, decisions = select(load(), agent, targets)
    return {d.target_ref: d.rule for d in decisions if d.triggered}


def test_the_shipped_policy_covers_every_agent_and_is_pinned_by_hash() -> None:
    p = load()
    assert p.version == "1.0.0" and set(p.agents) == set(range(9))
    assert p.sha256 == hashlib.sha256((POLICY_DIR / "triggers-1.0.0.yaml").read_bytes()).hexdigest()
    assert p.priority[:3] == [0, 7, 8]  # scope, assurance and the report come first in a budget
    with pytest.raises(FileNotFoundError):
        load("9.9.9")


def test_a_rule_has_exactly_one_condition() -> None:
    with pytest.raises(ValidationError):
        Rule(always=True, severity_at_least="HIGH")
    with pytest.raises(ValidationError):
        Rule()
    with pytest.raises(ValidationError):
        TriggerPolicy.model_validate({**load().model_dump(), "priority": [0, 1]})


def test_finding_rules_select_severe_and_uncertain_outcomes() -> None:
    got = hits(
        2, t("f:crit", severity="CRITICAL", outcome="FAIL"), t("f:med", severity="MEDIUM", outcome="FAIL"),
        t("f:na", severity="LOW", outcome="NOT_APPLICABLE"), t("f:unk", severity="LOW", outcome="UNKNOWN"),
    )  # fmt: skip
    assert got == {"f:crit": "severity_at_least=HIGH", "f:na": "outcome_in=['NOT_APPLICABLE', "
                   "'UNKNOWN', 'ERROR']", "f:unk": "outcome_in=['NOT_APPLICABLE', 'UNKNOWN', "
                   "'ERROR']"}  # fmt: skip
    assert set(hits(4, t("x", severity="MEDIUM"), t("y", severity="LOW"))) == {"x"}


def test_coverage_rules_select_only_what_needs_explaining() -> None:
    full = dict(
        expected_count=3, discovered_count=3, reconciled_count=3, source_ok=True, reasons=[]
    )
    got = hits(
        1, t("c:full", "coverage", **full),
        t("c:low", "coverage", **{**full, "reconciled_count": 2}),
        t("c:zero", "coverage", **{**full, "discovered_count": 0, "reconciled_count": 0, "expected_count": 0}),
        t("c:failed", "coverage", **{**full, "source_ok": False, "reasons": ["TIMEOUT"]}),
        t("c:gaps", "coverage", **{**full, "reasons": ["UNMODELLED_RULE"]}),
    )  # fmt: skip
    assert got == {"c:low": "coverage_below=0.95", "c:zero": "zero_asset_anomaly",
                   "c:failed": "source_failed", "c:gaps": "has_gaps"}  # fmt: skip


def test_scenarios_review_all_high_tiers_and_a_stable_sample_of_the_rest() -> None:
    assert hits(5, t("s:p0", "scenario", tier="P0"), t("s:p1", "scenario", tier="P1")) == {
        "s:p0": "tier_in=['P0', 'P1']", "s:p1": "tier_in=['P0', 'P1']",
    }  # fmt: skip
    rest = [t(f"s:{i}", "scenario", tier="P3") for i in range(2000)]
    first, second = hits(5, *rest), hits(5, *rest)
    assert first == second  # deterministic for the same policy and targets
    assert 0.17 < len(first) / len(rest) < 0.23 and set(first.values()) == {"sample_rate=0.2"}


def test_skips_are_decisions_too_and_packets_follow_the_priority() -> None:
    kept, decisions = select(load(), 2, [t("f:low", severity="LOW", outcome="FAIL")])
    assert kept == [] and [(d.triggered, d.rule) for d in decisions] == [(False, "no_rule_matched")]
    agents = [4, 2, 6, 0, 8, 7, 5]
    assert [agents[i] for i in order(load(), agents)] == [0, 7, 8, 5, 6, 2, 4]
