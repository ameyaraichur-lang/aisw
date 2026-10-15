from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from aisw.contracts.domain import CoverageLedger
from aisw.contracts.enums import PolicyOutcome as O
from aisw.reporting.coverage import build_ledger
from aisw.reporting.report import ReportInputs, build_report, render_html

T = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)


def ledger(**over: Any) -> CoverageLedger:
    d: dict[str, Any] = {
        "tenant_id": "t", "run_id": "r", "segment": "seg", "expected": ["a", "b"],
        "statuses": {"a": ("SCANNED", None), "b": ("SCANNED", None)},
        "asset_outcomes": {"a": O.PASS, "b": O.PASS}, "source_ok": True, "source_reasons": [],
        "last_success_at": T,
    }  # fmt: skip
    d.update(over)
    return build_ledger(**d)


def test_complete_only_when_everything_expected_was_assessed() -> None:
    L = ledger()
    assert L.is_complete and L.assessed_by_outcome == {O.PASS: 2} and L.reasons == []


@pytest.mark.parametrize(
    ("over", "expect"),
    [
        ({"statuses": {"a": ("SCANNED", None)}, "asset_outcomes": {"a": O.PASS}}, "EXPECTED_ASSET_ABSENT:b"),
        ({"statuses": {"a": ("SCANNED", None), "b": ("UNREACHABLE", "timeout")}}, "ASSET_UNREACHABLE:b:timeout"),
        ({"statuses": {"a": ("SCANNED", None), "b": ("UNSUPPORTED", "old os")}}, "ASSET_UNSUPPORTED:b:old os"),
        ({"statuses": {"a": ("SCANNED", None), "b": ("SCANNED", None), "z": ("SCANNED", None)}}, "UNEXPECTED_ASSET:z"),
        ({"source_ok": False, "source_reasons": ["TASK_FAILED"]}, "TASK_FAILED"),
    ],
)  # fmt: skip
def test_anything_missing_makes_it_incomplete_and_named(over: dict[str, Any], expect: str) -> None:
    L = ledger(**over)
    assert expect in " ".join(L.reasons)
    if "UNEXPECTED_ASSET" in expect:
        assert L.is_complete is True  # an extra asset is visible but does not hide missing ones
        assert L.discovered_count == 3 and L.reconciled_count == 2
    else:
        assert not L.is_complete


def test_zero_assets_is_an_anomaly() -> None:
    L = ledger(statuses={}, asset_outcomes={})
    assert not L.source_ok and "ZERO_ASSETS_RETURNED" in L.reasons and not L.is_complete
    assert L.assessed_by_outcome == {O.NOT_ASSESSED: 2} and L.unknown_count == 2


def test_unreachable_is_unknown_and_unsupported_is_not_assessed() -> None:
    L = ledger(statuses={"a": ("UNREACHABLE", None), "b": ("UNSUPPORTED", None)}, asset_outcomes={})
    assert L.assessed_by_outcome == {O.UNKNOWN: 1, O.NOT_ASSESSED: 1}
    assert (L.unknown_count, L.unsupported_count) == (1, 1)


def inputs(**over: Any) -> ReportInputs:
    finding = {"finding_id": "f-1", "severity": "HIGH", "title": "T <b>x</b>", "affected_assets": ["a"],
               "evidence_refs": ["evidence://t/p/r/x"]}  # fmt: skip
    d: dict[str, Any] = {
        "tenant_id": "t", "project_id": "p", "run_id": "r", "manifest_hash": "sha256:" + "a" * 64,
        "manifest_version": 1, "policy_version": "pk:1", "pack_hash": "sha256:" + "b" * 64,
        "tasks": [{"adapter_id": "fixture", "target": "g", "status": "SUCCEEDED", "tool_version": "x@1"}],
        "ledgers": [ledger()], "controls": [], "accepted": [finding], "needs_review": [],
        "rejected_count": 0, "evidence": [{"ref": "evidence://t/p/r/x", "hash": "sha256:" + "c" * 64}],
        "run_partial": False, "generated_at": T,
    }  # fmt: skip
    d.update(over)
    return ReportInputs(**d)


def test_clean_report_has_no_banner_and_reconciled_counts() -> None:
    bundle, body, _ = build_report(inputs())
    assert body["banner"] is None and bundle.coverage_complete and bundle.limitations == []
    assert body["finding_counts"] == {"total": 1, "HIGH": 1} == bundle.finding_counts
    assert bundle.report_hash.startswith("sha256:") and bundle.report_id == "rep-r"


def test_partial_or_incomplete_coverage_is_loud() -> None:
    _, body, html = build_report(inputs(ledgers=[ledger(source_ok=False, source_reasons=["x"])]))
    assert body["banner"].startswith("PARTIAL ASSESSMENT") and 'role="alert"' in html
    _, body2, _ = build_report(inputs(run_partial=True))
    assert body2["banner"] is not None
    _, body3, _ = build_report(inputs(ledgers=[]))
    assert body3["coverage_complete"] is False and "No coverage information" in " ".join(
        body3["limitations"]
    )


def test_excluded_findings_are_disclosed() -> None:
    pending = [{"finding_id": "f-2", "severity": "CRITICAL", "title": "needs eyes"}]
    _, body, _ = build_report(inputs(needs_review=pending, rejected_count=3))
    text = " ".join(body["limitations"])
    assert "3 candidate finding(s) failed independent assurance" in text and "await review" in text
    assert body["pending_review"] == pending and body["assurance"] == {
        "accepted": 1,
        "needs_review": 1,
        "rejected": 3,
    }


def test_failed_tasks_are_listed() -> None:
    t = [{"adapter_id": "fixture", "target": "g", "status": "FAILED", "tool_version": None}]
    _, body, _ = build_report(inputs(tasks=t))
    assert any("FAILED" in x for x in body["limitations"])


def test_report_hash_is_deterministic_and_content_bound() -> None:
    a = build_report(inputs())[0].report_hash
    assert a == build_report(inputs())[0].report_hash
    assert a != build_report(inputs(rejected_count=1))[0].report_hash


def test_html_escapes_every_untrusted_value() -> None:
    evil = "<script>alert(1)</script>\"'&"
    f = {
        "finding_id": "f",
        "severity": "HIGH",
        "title": evil,
        "affected_assets": [evil],
        "evidence_refs": [evil],
    }
    _, body, html = build_report(inputs(accepted=[f], ledgers=[ledger(segment=evil)]))
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "default-src 'none'" in html  # report carries its own CSP too
    assert render_html(body) == html
