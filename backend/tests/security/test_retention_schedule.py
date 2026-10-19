"""Scheduled retention checks: always a recorded dry run; automatic soft purge only when switched on
and the identical plan was seen a full confirmation window earlier."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aisw.evaluation import answer_key
from aisw.evidence import retention_schedule
from aisw.evidence.retention_schedule import SYSTEM_ACTOR, run_check
from tests.security.test_retention import blob, closed_run
from tests.slice import Slice

pytestmark = pytest.mark.security


def check(sl: Slice, *, auto: bool, hours: int = 24) -> retention_schedule.CheckResult:
    store = sl.container.evidence
    assert store is not None
    return run_check(
        sl.app_engine, store, "tenant-a", sl.clock.now,
        import_retention_days=sl.container.settings.evidence_retention_days,
        auto_execute=auto, confirm_hours=hours,
    )  # fmt: skip


def evidence_paths(sl: Slice, run_id: str) -> list[Path]:
    return [blob(sl, h) for (h,) in sl.sql(
        "SELECT content_hash FROM evidence_artifacts WHERE run_id=:r", r=run_id)]  # fmt: skip


def test_without_auto_execute_the_check_records_a_due_plan_and_moves_nothing(sl_iso: Slice) -> None:
    assert check(sl_iso, auto=False).outcome == "NOTHING_DUE"
    run_id = closed_run(sl_iso)
    sl_iso.clock.advance(days=31)
    for _ in range(3):
        r = check(sl_iso, auto=False)
        assert r.outcome == "DUE" and r.items > 0
        sl_iso.clock.advance(days=2)
    assert all(p.exists() for p in evidence_paths(sl_iso, run_id))
    assert sl_iso.sql("SELECT count(*) FROM retention_actions") == [(0,)]
    rows = sl_iso.call("GET", "/api/v1/retention/checks", "alice").json()
    assert [x["outcome"] for x in rows] == ["DUE", "DUE", "DUE", "NOTHING_DUE"]
    assert sl_iso.sql(
        "SELECT count(*) FROM audit_events WHERE actor=:a AND action='retention.check'",
        a=SYSTEM_ACTOR,
    ) == [(4,)]


def test_auto_execute_waits_for_the_same_plan_a_full_window_later(sl_iso: Slice) -> None:
    run_id = closed_run(sl_iso)
    sl_iso.clock.advance(days=31)
    first = check(sl_iso, auto=True)
    assert first.outcome == "AWAITING_CONFIRMATION"
    sl_iso.clock.advance(hours=23)
    assert check(sl_iso, auto=True).outcome == "AWAITING_CONFIRMATION"
    assert all(p.exists() for p in evidence_paths(sl_iso, run_id))
    sl_iso.clock.advance(hours=1)
    done = check(sl_iso, auto=True)
    assert done.outcome == "EXECUTED" and done.plan_hash == first.plan_hash
    assert done.moved_blobs > 0
    assert not any(p.exists() for p in evidence_paths(sl_iso, run_id))
    assert {who for (who,) in sl_iso.sql("SELECT DISTINCT executed_by FROM retention_actions")} == {
        SYSTEM_ACTOR
    }
    assert check(sl_iso, auto=True).outcome == "NOTHING_DUE"  # nothing is purged twice


def closed_maple_run(sl: Slice) -> str:
    _, _, run_id = sl.full_run(answer_key.load("maple-trust-1.0.0").cmdb_expected_assets,
                               fixture_set="maple-trust")  # fmt: skip
    sl.drain()
    (rep,) = sl.call("GET", f"/api/v1/assessments/{run_id}/reports", "rita").json()
    r = sl.call("POST", f"/api/v1/reports/{rep['report_id']}/approve", "rita",
                json={"report_hash": rep["report_hash"]})  # fmt: skip
    assert r.status_code == 200, r.text
    return run_id


def test_a_change_between_checks_restarts_the_confirmation_window(sl_iso: Slice) -> None:
    run_a = closed_run(sl_iso)
    sl_iso.clock.advance(minutes=1)
    run_b = closed_maple_run(sl_iso)  # different evidence: no blobs shared with run_a
    sl_iso.clock.advance(days=31)
    first = check(sl_iso, auto=True)
    assert first.outcome == "AWAITING_CONFIRMATION"
    r = sl_iso.call(
        "POST", f"/api/v1/assessments/{run_b}/retention-hold", "alice", json={"reason": "legal"}
    )
    assert r.status_code == 201, r.text
    sl_iso.clock.advance(hours=25)
    second = check(sl_iso, auto=True)  # the hold changed the plan: a new window starts
    assert second.outcome == "AWAITING_CONFIRMATION" and second.plan_hash != first.plan_hash
    assert second.held_runs == 1 and 0 < second.items < first.items
    assert all(p.exists() for p in evidence_paths(sl_iso, run_a))
    sl_iso.clock.advance(hours=24)
    assert check(sl_iso, auto=True).outcome == "EXECUTED"
    assert not any(p.exists() for p in evidence_paths(sl_iso, run_a))
    assert all(p.exists() for p in evidence_paths(sl_iso, run_b))  # held evidence stays


def test_a_hold_on_a_run_sharing_blobs_keeps_them_all(sl_iso: Slice) -> None:
    closed_run(sl_iso)
    sl_iso.clock.advance(minutes=1)
    run_b = closed_run(sl_iso)  # byte-identical fixture evidence: every blob is shared
    sl_iso.clock.advance(days=31)
    sl_iso.call("POST", f"/api/v1/assessments/{run_b}/retention-hold", "alice",
                json={"reason": "legal"})  # fmt: skip
    r = check(sl_iso, auto=True)
    assert r.outcome == "NOTHING_DUE" and r.held_runs == 1
    assert sl_iso.sql("SELECT count(*) FROM retention_actions") == [(0,)]


def test_checks_and_holds_are_readable_by_retention_managers_and_auditors_only(
    sl_iso: Slice,
) -> None:
    run_id = closed_run(sl_iso)
    sl_iso.call("POST", f"/api/v1/assessments/{run_id}/retention-hold", "alice",
                json={"reason": "audit request 42"})  # fmt: skip
    check(sl_iso, auto=False)
    for user in ("alice", "erin"):
        holds = sl_iso.call("GET", "/api/v1/retention/holds", user)
        assert holds.status_code == 200
        assert [(h["run_id"], h["reason"], h["placed_by"]) for h in holds.json()] == [
            (run_id, "audit request 42", "alice")
        ]
        assert sl_iso.call("GET", "/api/v1/retention/checks", user).status_code == 200
    for user in ("carol", "bob"):
        assert sl_iso.call("GET", "/api/v1/retention/holds", user).status_code == 403
        assert sl_iso.call("GET", "/api/v1/retention/checks", user).status_code == 403
    assert sl_iso.call("GET", "/api/v1/retention/checks", "dave").json() == []  # other tenant
    plan: dict[str, Any] = sl_iso.call("GET", "/api/v1/retention/plan", "alice").json()
    assert plan["schedule"] == {
        "auto_execute": False, "confirm_hours": 24,
        "import_retention_days": sl_iso.container.settings.evidence_retention_days,
    }  # fmt: skip


def test_the_command_needs_a_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AISW_RETENTION_TENANTS", raising=False)
    assert retention_schedule.main([]) == 2
