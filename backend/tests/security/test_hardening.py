"""M8 hardening: retry storms, cancellation mid-run, event integrity under concurrency, export controls."""

from __future__ import annotations

from typing import Any

import pytest

from tests.slice import Slice

pytestmark = pytest.mark.security
EXPECTED = ["host-1", "host-2", "host-3"]


def test_retry_storm_is_bounded_spaced_and_always_terminates(sl: Slice) -> None:
    runs = [sl.full_run(EXPECTED)[2] for _ in range(12)]

    def down(job: Any) -> Any:
        raise RuntimeError("scanner down")

    calls = {"n": 0}

    def counted(job: Any) -> Any:
        calls["n"] += 1
        return down(job)

    sl.fixture.execute = counted  # type: ignore[union-attr,method-assign]
    sl.drain()
    assert calls["n"] == 12  # one attempt each; the rest wait out their backoff
    assert sl.drain() == 0 and calls["n"] == 12  # no hot loop while the delay has not elapsed
    for _ in range(40):
        sl.clock.advance(seconds=30)
        before = calls["n"]
        sl.drain()
        if calls["n"] == before and not sl.sql(
            "SELECT 1 FROM run_tasks WHERE run_id = ANY(:r) AND status='QUEUED'", r=runs
        ):
            break
    assert calls["n"] == 12 * 3  # bounded by max_attempts, never more
    states = {sl.status(r)["state"] for r in runs}
    assert states == {"FAILED"}
    for r in runs:
        assert sl.sql("SELECT attempts, status FROM run_tasks WHERE run_id=:r", r=r)[0] == (
            3,
            "FAILED",
        )


def test_backoff_grows_with_each_attempt(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)

    def down(job: Any) -> Any:
        raise RuntimeError("down")

    sl.fixture.execute = down  # type: ignore[union-attr,method-assign]
    gaps = []
    for _ in range(2):
        sl.drain()
        due = sl.sql("SELECT available_at FROM run_tasks WHERE run_id=:r", r=run_id)[0][0]
        gaps.append((due - sl.clock.now).total_seconds())
        sl.clock.advance(seconds=gaps[-1] + 0.5)
    assert gaps[1] > gaps[0] * 1.5


def test_cancel_while_a_task_is_running_keeps_its_evidence_and_publishes_no_report(
    sl: Slice,
) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    real = sl.fixture.execute  # type: ignore[union-attr]

    def cancel_midway(job: Any) -> Any:
        r = sl.call("POST", f"/api/v1/assessments/{run_id}/cancel", "alice")
        assert r.status_code == 200
        return real(job)

    sl.fixture.execute = cancel_midway  # type: ignore[union-attr,method-assign]
    sl.drain()
    st = sl.status(run_id)
    assert st["state"] == "CANCELLED"
    assert sl.sql("SELECT count(*) FROM evidence_artifacts WHERE run_id=:r", r=run_id)[0][0] >= 1
    assert sl.sql("SELECT count(*) FROM reports WHERE run_id=:r", r=run_id)[0][0] == 0
    assert "assessment.cancelled" in [e["type"] for e in sl.events(run_id)]
    assert sl.call("POST", f"/api/v1/assessments/{run_id}/cancel", "alice").status_code == 409


def test_two_workers_racing_leave_one_ordered_event_log_per_run(sl: Slice) -> None:
    runs = [sl.full_run(EXPECTED)[2] for _ in range(4)]
    other = sl.container.make_worker(sl.worker_engine, worker_id="w-2")
    for _ in range(200):
        a, b = sl.worker.step(), other.step()
        if not (a or b):
            break
    for r in runs:
        ev = sl.events(r)
        seqs = [e["seq"] for e in ev]
        ids = [e["event_id"] for e in ev]
        assert seqs == sorted(set(seqs)) and len(set(ids)) == len(
            ids
        )  # strictly ordered, no duplicates
        types = [e["type"] for e in ev]
        assert types.count("evidence.batch.stored") == 1 and types.count("report.ready") == 1
        assert sl.status(r)["state"] == "REPORT_READY"
        assert sl.events(r, cursor=seqs[-1]) == []  # replay from the end yields nothing
        half = sl.events(r, cursor=seqs[len(seqs) // 2])
        assert [e["seq"] for e in half] == seqs[len(seqs) // 2 + 1 :]  # resume is exact


# ---- report export ----------------------------------------------------------------------------
def finished(sl: Slice) -> tuple[str, dict[str, Any]]:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    (rep,) = sl.call("GET", f"/api/v1/assessments/{run_id}/reports", "rita").json()
    return run_id, rep


def test_draft_reports_are_watermarked_and_only_approvers_can_download_them(sl: Slice) -> None:
    _, rep = finished(sl)
    rid = rep["report_id"]
    r = sl.call("GET", f"/api/v1/reports/{rid}?format=html", "carol")  # preview
    assert r.status_code == 200 and "DRAFT: this report has not been approved" in r.text
    assert "Exported by carol" in r.text and rep["report_hash"] in r.text
    assert r.headers["x-report-approval"] == "PENDING" and "content-disposition" not in r.headers
    assert (
        sl.call("GET", f"/api/v1/reports/{rid}?format=html&download=1", "carol").status_code == 403
    )
    assert (
        sl.call("GET", f"/api/v1/reports/{rid}?format=json&download=1", "carol").status_code == 403
    )
    ok = sl.call("GET", f"/api/v1/reports/{rid}?format=json&download=1", "rita")
    assert ok.status_code == 200 and ok.headers["content-disposition"].startswith("attachment")
    assert ok.headers["x-exported-by"] == "rita" and ok.json()["run_id"]
    results = {
        r[0]
        for r in sl.sql(
            "SELECT result FROM audit_events WHERE action='report.export' AND actor IN ('carol','rita')"
        )
    }
    assert results == {
        "DENIED",
        "SUCCESS",
    }  # the refused export and the allowed one are both recorded


def test_approved_reports_can_be_downloaded_by_readers_without_the_draft_notice(sl: Slice) -> None:
    _, rep = finished(sl)
    rid = rep["report_id"]
    assert (
        sl.call(
            "POST",
            f"/api/v1/reports/{rid}/approve",
            "rita",
            json={"report_hash": rep["report_hash"]},
        ).status_code
        == 200
    )
    r = sl.call("GET", f"/api/v1/reports/{rid}?format=html&download=1", "carol")
    assert r.status_code == 200 and "DRAFT" not in r.text and "Approval state: APPROVED" in r.text
    assert r.headers["x-report-hash"] == rep["report_hash"]  # the stored hash is unchanged


def test_export_requires_read_permission_and_is_tenant_scoped(sl: Slice) -> None:
    _, rep = finished(sl)
    rid = rep["report_id"]
    for user in ("alice", "bob"):  # operator and approver cannot read reports at all
        assert sl.call("GET", f"/api/v1/reports/{rid}?download=1", user).status_code == 403
    assert sl.call("GET", f"/api/v1/reports/{rid}?download=1", "dave").status_code in (403, 404)
    assert sl.call("GET", f"/api/v1/reports/{rid}?download=1", "nobody").status_code == 401


def test_watermark_values_are_escaped(sl: Slice) -> None:
    from aisw.api.assessments import _watermark

    out = _watermark("<script>alert(1)</script>", "t&t", "now", "PENDING", "sha256:x")
    assert "<script>" not in out and "&lt;script&gt;" in out and "t&amp;t" in out
