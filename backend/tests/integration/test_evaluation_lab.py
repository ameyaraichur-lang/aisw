"""The Maple Trust estate scored end to end against its answer key (ADR-039)."""

from __future__ import annotations

from typing import Any

from aisw.core.db import tenant_connection
from aisw.evaluation.answer_key import load
from aisw.evaluation.scorecard import run_scorecard
from tests.slice import Slice

KEY = load("maple-trust-1.0.0")


def scored_run(sl: Slice) -> tuple[str, dict[str, Any]]:
    _, _, run_id = sl.full_run(KEY.cmdb_expected_assets, fixture_set="maple-trust")
    sl.drain()
    r = sl.call("GET", f"/api/v1/evaluation/runs/{run_id}/scorecard", "carol")
    assert r.status_code == 200, r.text
    return run_id, {m["metric"]: m for m in r.json()["metrics"]}


def test_maple_trust_is_scored_against_its_answer_key(sl: Slice) -> None:
    first, _ = scored_run(sl)
    sl.clock.advance(minutes=1)
    run_id, m = scored_run(sl)

    rec = m["asset_reconciliation"]
    assert (rec["status"], rec["display"]) == ("MET", "62 of 62 (100.0%)")
    assert rec["detail"]["answer_key_agreement"] == {"agree": 62, "of": 62, "disagree": []}
    assert m["status_coverage"]["status"] == "MET"
    assert m["status_coverage"]["detail"]["by_status"] == {
        "ABSENT": 2, "SCANNED": 55, "UNREACHABLE": 2, "UNSUPPORTED": 3}  # fmt: skip

    recall = m["detection_recall"]
    assert (recall["value"], recall["display"]) == (0.8333, "15 of 18 (83.3%)")
    missed = {(x["asset_id"], x["reason"].split(":")[0]) for x in recall["detail"]["missed"]}
    assert missed == {("mt-legacy-02", "ASSET_UNREACHABLE"), ("mt-dns-03", "UNKNOWN"),
                      ("mt-app-09", "NOT_ASSESSED")}  # fmt: skip
    precision = m["detection_precision"]
    assert precision["value"] == 0.9375
    assert [(x["asset_id"], x["rule_id"]) for x in precision["detail"]["false_positive"]] == [
        ("mt-win-07", "password.min_length")]  # fmt: skip
    assert precision["detail"]["unlabelled"] == []

    assert (m["finding_traceability"]["status"], m["finding_traceability"]["value"]) == ("MET", 1.0)
    assert m["unsupported_compliance_claims"]["value"] == 0, m["unsupported_compliance_claims"][
        "detail"
    ]
    assert m["scope_enforcement"]["status"] == "MET"
    assert m["validator_catch_rate"]["status"] == "NOT_MEASURED"
    repro = m["reproducibility"]
    assert repro["status"] == "MET" and repro["detail"]["compared_with"] == first
    assert m["model_cost_latency"]["detail"]["calls"] == 0

    trend = sl.call("GET", "/api/v1/evaluation/runs?fixture_set=maple-trust", "carol").json()
    assert [t["run_id"] for t in trend[:2]] == [run_id, first]
    assert trend[0]["metrics"]["reproducibility"]["status"] == "MET"
    assert trend[0]["answer_key"] == "maple-trust-1.0.0"


def test_a_run_without_an_answer_key_says_so(sl: Slice) -> None:
    _, _, run_id = sl.full_run(
        ["host-1", "host-2", "host-3", "host-4"], fixture_set="baseline-partial"
    )
    sl.drain()
    card = sl.call("GET", f"/api/v1/evaluation/runs/{run_id}/scorecard", "carol").json()
    m = {x["metric"]: x for x in card["metrics"]}
    assert card["answer_key"] is None
    assert m["detection_recall"]["status"] == "NOT_MEASURED"
    assert m["status_coverage"]["status"] == "MET"
    assert "answer_key_agreement" not in m["asset_reconciliation"]["detail"]


def test_scorecards_are_tenant_scoped_and_need_finding_read(sl: Slice) -> None:
    _, _, run_id = sl.full_run(["host-1"])
    sl.drain()
    with tenant_connection(sl.app_engine, "tenant-b") as conn:
        assert run_scorecard(conn, run_id) is None
    with tenant_connection(sl.app_engine, "tenant-a") as conn:
        assert run_scorecard(conn, run_id) is not None
    for user in ("dave", "paula"):
        assert sl.call("GET", "/api/v1/evaluation/runs", user).status_code == 403
    assert sl.call("GET", "/api/v1/evaluation/runs/nope/scorecard", "carol").status_code == 404
    keys = sl.call("GET", "/api/v1/evaluation/answer-keys", "carol").json()
    assert keys[0]["key_id"] == "maple-trust-1.0.0" and len(keys[0]["cmdb_expected_assets"]) == 60
