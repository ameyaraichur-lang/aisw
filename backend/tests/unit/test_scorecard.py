"""Pure scorecard rules: nothing defaults to a pass, and every shortfall names its cause (ADR-039)."""

from __future__ import annotations

import json
from dataclasses import replace
from importlib import resources
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from aisw.evaluation.answer_key import AnswerKey, for_fixture, load
from aisw.evaluation.scorecard import RunFacts, _scope_violations, score, signature
from aisw.policy.results import finding_id_for
from aisw.reporting.report import DISCLAIMER

KEY = load("maple-trust-1.0.0")
ROOT = Path(__file__).resolve().parents[3]


def facts(**over: Any) -> RunFacts:
    base = RunFacts(
        run_id="r-1", policy_version="fixture-baseline:1.0.0", fixture_set="baseline-ok",
        expected=frozenset({"a", "b", "c"}), statuses={"a": "SCANNED", "b": "UNREACHABLE", "x": "SCANNED"},
        flagged_absent=frozenset({"c"}), flagged_unexpected=frozenset({"x"}),
        findings={"f-1": ["ev-1"]}, evidence=frozenset({"ev-1"}),
        observations={("r", "a"): ("FAIL", "ev-1")}, exceptions=frozenset(),
        report_text=f"Report. {DISCLAIMER} No gap observed.", control_gaps=None, violations=[],
        blocked_tasks=0, digest="sha256:aa",
    )  # fmt: skip
    return replace(base, **over)


def metrics(f: RunFacts, key: AnswerKey | None = None, **kw: Any) -> dict[str, dict[str, Any]]:
    return {m["metric"]: m for m in score(f, key, **kw)["metrics"]}


def test_a_clean_run_meets_targets_and_unmeasurable_metrics_say_so() -> None:
    m = metrics(facts())
    assert m["asset_reconciliation"]["display"] == "4 of 4 (100.0%)"
    assert m["status_coverage"]["status"] == "MET"
    assert m["finding_traceability"]["status"] == "MET"
    assert m["unsupported_compliance_claims"]["value"] == 0  # the fixed disclaimer is not a claim
    for name in ("detection_recall", "detection_precision", "validator_catch_rate",
                 "reproducibility"):  # fmt: skip
        assert m[name]["status"] == "NOT_MEASURED" and m[name]["value"] is None


def test_unflagged_assets_and_a_missing_expected_list_fail_reconciliation() -> None:
    m = metrics(facts(flagged_unexpected=frozenset()))
    assert m["asset_reconciliation"]["detail"]["unaccounted"] == ["x"]
    assert m["asset_reconciliation"]["value"] == 0.75
    assert m["asset_reconciliation"]["status"] == "NOT_MET"
    none = metrics(facts(expected=frozenset(), flagged_absent=frozenset()))
    assert none["asset_reconciliation"]["status"] == "NOT_MET"
    assert none["asset_reconciliation"]["detail"]["reason"] == "NO_EXPECTED_ASSET_LIST"
    gap = metrics(facts(flagged_absent=frozenset()))
    assert gap["status_coverage"]["status"] == "NOT_MET"
    assert gap["status_coverage"]["detail"]["without_status"] == ["c"]


def test_broken_traceability_claims_and_scope_violations_are_counted() -> None:
    m = metrics(facts(
        findings={"f-1": ["ev-1"], "f-2": ["ev-gone"]},
        report_text="The estate is fully compliant and passed the audit.",
        control_gaps={"frameworks": [{"framework": "CIS", "rows": [
            {"control_id": "1.1", "state": "NO_GAP_OBSERVED",
             "pack_controls": [{"control_id": "FB-1", "outcome": "UNKNOWN"}]}]}]},
        violations=["task t: target not in the manifest"], blocked_tasks=2,
    ))  # fmt: skip
    assert m["finding_traceability"]["detail"]["untraceable"] == ["f-2"]
    claims = m["unsupported_compliance_claims"]
    assert claims["value"] == 3 and claims["detail"]["gap_rows_without_support"] == ["CIS 1.1"]
    assert m["scope_enforcement"]["display"] == "1 successful, 2 blocked"
    assert m["scope_enforcement"]["status"] == "NOT_MET"
    assert metrics(facts(report_text=None))["unsupported_compliance_claims"]["status"] == (
        "NOT_MEASURED")  # fmt: skip


def test_scope_violations_compare_executed_tasks_with_the_manifest() -> None:
    body = {"targets": [{"kind": "asset_group", "selector": "g"}],
            "exclusions": [{"kind": "asset_group", "selector": "bad"}],
            "allowed_adapters": ["fixture"],
            "profiles": {"fixture": {"profile_id": "P", "profile_class": "READ_ONLY"}}}  # fmt: skip

    def task(**kw: Any) -> SimpleNamespace:
        d = {"task_id": "t", "adapter_id": "fixture", "profile": "P", "target_kind": "asset_group",
             "target_selector": "g", "status": "SUCCEEDED"}  # fmt: skip
        return SimpleNamespace(**(d | kw))

    assert _scope_violations([task(), task(status="REJECTED", adapter_id="nmap")], body) == []
    got = _scope_violations([task(adapter_id="nmap"), task(target_selector="bad")], body)
    assert any("adapter not allowed" in v for v in got)
    assert any("target is excluded" in v for v in got)
    assert any("target not in the manifest" in v for v in got)


def test_validator_and_reproducibility_and_cost() -> None:
    labelled = json.loads((ROOT / "docs/implementation/evaluation/labelled-1.0.0-gpt-5.4.json")
                          .read_text())  # fmt: skip
    m = metrics(facts(model_calls=[(100, 20, 300, "VALIDATED"), (None, None, 50, "REJECTED")]),
                labelled=labelled, previous=("r-0", "sha256:bb"))  # fmt: skip
    assert m["validator_catch_rate"]["status"] == "MET"
    assert m["validator_catch_rate"]["display"] == "15 of 15 (100.0%)"
    assert m["validator_false_dissent"]["value"] == 0.0
    assert m["reproducibility"]["status"] == "NOT_MET"
    assert m["reproducibility"]["detail"]["compared_with"] == "r-0"
    cost = m["model_cost_latency"]["detail"]
    assert (cost["calls"], cost["input_tokens"], cost["unmetered_calls"]) == (2, 100, 1)
    assert (cost["latency_ms_max"], cost["not_validated_calls"]) == (300, 1)
    same = metrics(facts(), previous=("r-0", "sha256:aa"))["reproducibility"]
    assert same["status"] == "MET"


def test_detection_explains_every_miss_and_false_positive() -> None:
    issue, clean = KEY.known_issues[0], KEY.known_clean[0]
    fid = finding_id_for(KEY.pack_id, clean.rule_id, clean.asset_id)
    f = facts(fixture_set="maple-trust", statuses={issue.asset_id: "SCANNED"},
              findings={fid: ["ev-1"], "f-other": ["ev-1"]})  # fmt: skip
    m = metrics(f, KEY)
    missed = {x["asset_id"]: x["reason"] for x in m["detection_recall"]["detail"]["missed"]}
    assert missed[issue.asset_id].startswith("NOT_ASSESSED")
    assert m["detection_recall"]["value"] == 0.0
    p = m["detection_precision"]
    assert (p["value"], p["detail"]["unlabelled"]) == (0.0, ["f-other"])
    assert p["detail"]["false_positive"][0]["asset_id"] == clean.asset_id


def test_signature_ignores_task_order_but_not_inputs() -> None:
    a = SimpleNamespace(adapter_id="fixture", profile="P", target_kind="k", target_selector="s",
                        params={"fixture_set": "x"}, expected_assets=["b", "a"])  # fmt: skip
    b = SimpleNamespace(**(vars(a) | {"target_selector": "t"}))
    assert signature([a, b], "p:1") == signature([b, a], "p:1")
    assert signature([a], "p:1") != signature([a], "p:2")
    assert signature([a], "p:1") != signature(
        [SimpleNamespace(**(vars(a) | {"params": {}}))], "p:1"
    )


def test_answer_keys_are_closed_and_internally_consistent() -> None:
    with pytest.raises(KeyError):
        load("../../etc/passwd")
    assert for_fixture("maple-trust", "fixture-baseline:1.0.0") is KEY
    assert for_fixture("maple-trust", "other:1.0.0") is None
    raw = KEY.model_dump()
    raw["known_clean"] = [*raw["known_clean"], raw["known_issues"][0]]
    with pytest.raises(ValidationError, match="both a known issue"):
        AnswerKey.model_validate(raw)


def test_the_key_matches_the_packaged_estate() -> None:
    estate = json.loads((resources.files("aisw.adapters") / "fixture_data" / "maple-trust.json")
                        .read_text())  # fmt: skip
    hosts = {h["id"]: h for h in estate["hosts"]}
    assert len(KEY.cmdb_expected_assets) == 60 and len(hosts) == 60
    assert {a for a, s in KEY.reconciliation.items() if s != "ABSENT"} == set(hosts)
    assert {a for a, s in KEY.reconciliation.items() if s != "UNEXPECTED"} == set(
        KEY.cmdb_expected_assets)  # fmt: skip
    for a, s in KEY.asset_status.items():
        assert hosts[a]["state"].upper() == s
    assert all(c.asset_id in hosts for c in [*KEY.known_issues, *KEY.known_clean])
