"""M3 gate: approved scope -> fixture adapter -> evidence -> policy -> findings/coverage -> report,
driven through the real API with a real worker, without any scanner or credentials."""

from __future__ import annotations

from tests.slice import Slice

EXPECTED = ["host-1", "host-2", "host-3"]


def test_complete_run_end_to_end(sl: Slice) -> None:
    pid, m, run_id = sl.full_run(EXPECTED)
    assert sl.status(run_id)["state"] == "AUTHORIZED"
    assert sl.executions == 0  # accepting a run executes nothing
    sl.drain()
    st = sl.status(run_id)
    assert (st["state"], st["partial"]) == ("REPORT_READY", False)
    assert st["tasks"] == {"SUCCEEDED": 1}

    rep = sl.report(run_id)
    assert rep["coverage_complete"] is True and rep["banner"] is None
    assert rep["finding_counts"] == {"total": 2, "HIGH": 1, "MEDIUM": 1}
    assert {f["title"] for f in rep["findings"]} == {
        "Direct root login over SSH is disabled",
        "Minimum password length is at least 12",
    }
    assert all(f["affected_assets"] == ["host-2"] for f in rep["findings"])
    controls = {c["control_id"]: c["outcome"] for c in rep["controls"]}
    assert controls == {"FB-1": "FAIL", "FB-2": "FAIL", "FB-3": "PASS"}
    assert rep["scope_manifest_hash"] == m["canonical_hash"]
    assert rep["policy_versions"] == ["fixture-baseline:1.0.0"]
    cov = rep["coverage"][0]
    assert (cov["expected_count"], cov["reconciled_count"], cov["unknown_count"]) == (3, 3, 0)


def test_report_counts_reconcile_to_stored_records(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    rep = sl.report(run_id)
    (db_accepted,) = sl.sql(
        "SELECT count(*) FROM findings WHERE run_id=:r AND assurance_verdict='ACCEPT'", r=run_id
    )[0]
    api = sl.call("GET", f"/api/v1/assessments/{run_id}/findings", "alice").json()
    assert (
        db_accepted == rep["finding_counts"]["total"] == len(rep["findings"]) == api["total"] == 2
    )
    assert all(i["authoritative"] for i in api["items"])
    by_sev: dict[str, int] = {}
    for f in rep["findings"]:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    assert {k: v for k, v in rep["finding_counts"].items() if k != "total"} == by_sev
    refs = {
        r[0]
        for r in sl.sql("SELECT evidence_ref FROM evidence_artifacts WHERE run_id=:r", r=run_id)
    }
    assert refs == {e["ref"] for e in rep["evidence_manifest"]}
    for f in rep["findings"]:  # every finding traces to stored evidence
        assert set(f["evidence_refs"]) <= refs


def test_partial_sources_stay_visible_and_never_pass(sl: Slice) -> None:
    expected = ["host-1", "host-2", "host-3", "host-4"]
    _, _, run_id = sl.full_run(expected, fixture_set="baseline-partial")
    sl.drain()
    st = sl.status(run_id)
    assert (st["state"], st["partial"]) == ("PARTIAL", True)
    assert st["tasks"] == {"PARTIAL": 1}
    cov = sl.call("GET", f"/api/v1/assessments/{run_id}/coverage", "alice").json()
    assert cov["final"] is True and cov["complete"] is False
    seg = cov["segments"][0]
    assert seg["expected_count"] == 4 and seg["discovered_count"] == 4  # host-1,2,3 + rogue host-9
    assert seg["reconciled_count"] == 3  # host-4 never seen
    assert seg["unknown_count"] == 2  # host-2 unreachable + host-4 absent
    assert seg["unsupported_count"] == 1  # host-3
    reasons = " ".join(seg["reasons"])
    for needle in ("EXPECTED_ASSET_ABSENT:host-4", "ASSET_UNREACHABLE:host-2",
                   "ASSET_UNSUPPORTED:host-3", "UNEXPECTED_ASSET:host-9"):  # fmt: skip
        assert needle in reasons
    assert seg["assessed_by_outcome"] == {"PASS": 1, "UNKNOWN": 2, "NOT_ASSESSED": 2}
    rep = sl.report(run_id)
    assert rep["banner"].startswith("PARTIAL ASSESSMENT") and rep["coverage_complete"] is False
    assert any("coverage incomplete" in x for x in rep["limitations"])
    controls = {c["control_id"]: c["outcome"] for c in rep["controls"]}
    assert controls["FB-3"] == "UNKNOWN"  # one host passed, one is unknown: NOT pass
    assert controls["FB-1"] == "PASS" and controls["FB-2"] == "PASS"  # only scanned hosts counted
    types = [e["type"] for e in sl.events(run_id)]
    assert "task.partial" in types and "report.partial" in types and "report.ready" not in types


def test_zero_assets_is_a_coverage_anomaly_not_a_success(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED, fixture_set="baseline-zero")
    sl.drain()
    st = sl.status(run_id)
    assert st["state"] == "PARTIAL" and st["tasks"] == {"PARTIAL": 1}
    seg = sl.call("GET", f"/api/v1/assessments/{run_id}/coverage", "alice").json()["segments"][0]
    assert seg["source_ok"] is False and "ZERO_ASSETS_RETURNED" in seg["reasons"]
    assert seg["assessed_by_outcome"] == {"NOT_ASSESSED": 3}
    rep = sl.report(run_id)
    assert rep["finding_counts"] == {"total": 0} and rep["coverage_complete"] is False
    assert all(c["outcome"] in {"NOT_APPLICABLE"} for c in rep["controls"])


def test_cancel_before_start_dispatches_nothing(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    assert sl.call("POST", f"/api/v1/assessments/{run_id}/cancel", "carol").status_code == 403
    r = sl.call("POST", f"/api/v1/assessments/{run_id}/cancel", "alice")
    assert r.json()["queued_tasks_cancelled"] == 1
    sl.drain()
    assert sl.status(run_id)["state"] == "CANCELLED" and sl.executions == 0
    assert "assessment.cancelled" in [e["type"] for e in sl.events(run_id)]
    assert sl.call("POST", f"/api/v1/assessments/{run_id}/cancel", "alice").status_code == 409


def test_events_are_ordered_replayable_and_deduplicated(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    evs = sl.events(run_id)
    seqs = [e["seq"] for e in evs]
    assert seqs == list(range(1, len(seqs) + 1)) and len({e["event_id"] for e in evs}) == len(evs)
    types = [e["type"] for e in evs]
    for needed in ("assessment.accepted", "preflight.completed", "task.queued", "task.started",
                   "evidence.batch.stored", "task.completed", "report.ready"):  # fmt: skip
        assert needed in types
    assert types.index("task.queued") < types.index("task.started") < types.index("task.completed")
    mid = seqs[len(seqs) // 2]
    tail = sl.events(run_id, cursor=mid)  # reconnect from a cursor: no gaps, no repeats
    assert [e["seq"] for e in tail] == [s for s in seqs if s > mid]
    assert sl.status(run_id)["event_cursor"] == seqs[-1]


def test_report_approval_flow_and_html_export(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    rep = sl.report(run_id)
    rid = sl.call("GET", f"/api/v1/assessments/{run_id}/reports", "carol").json()[0]["report_id"]
    html = sl.call("GET", f"/api/v1/reports/{rid}?format=html", "carol")
    assert html.status_code == 200 and html.headers["content-type"].startswith("text/html")
    assert html.headers["content-security-policy"] == "default-src 'none'"
    assert html.headers["x-content-type-options"] == "nosniff"
    assert "Direct root login over SSH is disabled" in html.text and "<script" not in html.text
    assert (
        sl.call("GET", f"/api/v1/reports/{rid}", "alice").status_code == 403
    )  # operator: no REPORT_READ
    assert sl.call("GET", f"/api/v1/reports/{rid}", "dave").status_code in (403, 404)
    assert rep["run_id"] == run_id
    h = sl.call("GET", f"/api/v1/reports/{rid}", "carol").headers["x-report-hash"]
    bad = sl.call(
        "POST", f"/api/v1/reports/{rid}/approve", "rita", json={"report_hash": "sha256:" + "0" * 64}
    )
    assert bad.status_code == 409  # approval is bound to the exact report hash
    assert (
        sl.call(
            "POST", f"/api/v1/reports/{rid}/approve", "carol", json={"report_hash": h}
        ).status_code
        == 403
    )
    ok = sl.call("POST", f"/api/v1/reports/{rid}/approve", "rita", json={"report_hash": h})
    assert ok.status_code == 200 and ok.json()["run_state"] == "CLOSED"
    assert sl.status(run_id)["state"] == "CLOSED"
    assert (
        sl.call(
            "POST", f"/api/v1/reports/{rid}/approve", "rita", json={"report_hash": h}
        ).status_code
        == 409
    )
    assert "assessment.closed" in [e["type"] for e in sl.events(run_id)]


def test_launcher_cannot_approve_their_own_report(sl: Slice) -> None:
    pid = sl.project()
    sl.inventory(pid, EXPECTED)
    m = sl.approved_manifest(pid)
    run_id = sl.launch(pid, m, user="sam").json()["run_id"]  # sam: operator + reviewer
    sl.drain()
    rid = sl.call("GET", f"/api/v1/assessments/{run_id}/reports", "carol").json()[0]["report_id"]
    h = sl.call("GET", f"/api/v1/reports/{rid}", "carol").headers["x-report-hash"]
    assert (
        sl.call(
            "POST", f"/api/v1/reports/{rid}/approve", "sam", json={"report_hash": h}
        ).status_code
        == 403
    )
    assert (
        sl.call(
            "POST", f"/api/v1/reports/{rid}/approve", "rita", json={"report_hash": h}
        ).status_code
        == 200
    )


def test_launch_replay_is_idempotent(sl: Slice) -> None:
    pid = sl.project()
    sl.inventory(pid, EXPECTED)
    m = sl.approved_manifest(pid)
    a = sl.launch(pid, m, key="k-1")
    b = sl.launch(pid, m, key="k-1")
    assert a.status_code == b.status_code == 202 and a.json()["run_id"] == b.json()["run_id"]
    assert b.headers["idempotent-replay"] == "true"
    assert sl.sql("SELECT count(*) FROM assessment_runs WHERE project_id=:p", p=pid)[0][0] == 1
    assert sl.sql("SELECT count(*) FROM run_tasks WHERE run_id=:r", r=a.json()["run_id"])[0][0] == 1
    c = sl.launch(pid, m, key="k-1", fixture_set="baseline-partial")  # same key, different params
    assert c.status_code == 409 and c.json()["error"] == "idempotency_conflict"
    assert sl.launch(pid, m).json()["run_id"] != a.json()["run_id"]  # new key: new run
    sl.drain()
    assert sl.executions == 2  # one per distinct run, never per replay
