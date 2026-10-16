"""Retention: dry-run first, hash-pinned execution, holds, shared blobs, soft purge, RBAC."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from aisw.core.db import tenant_connection
from tests.slice import Slice

pytestmark = pytest.mark.security
EXPECTED = ["host-1", "host-2", "host-3"]


def closed_run(sl: Slice) -> str:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    (rep,) = sl.call("GET", f"/api/v1/assessments/{run_id}/reports", "rita").json()
    r = sl.call(
        "POST",
        f"/api/v1/reports/{rep['report_id']}/approve",
        "rita",
        json={"report_hash": rep["report_hash"]},
    )
    assert r.status_code == 200, r.text
    assert sl.status(run_id)["state"] == "CLOSED"
    return run_id


def plan(sl: Slice, user: str = "alice") -> dict[str, Any]:
    r = sl.call("GET", "/api/v1/retention/plan", user)
    assert r.status_code == 200, r.text
    return dict(r.json())


def mine(p: dict[str, Any], run_id: str) -> list[dict[str, Any]]:
    return [i for i in p["items"] if i["run_id"] == run_id]


def blob(sl: Slice, h: str) -> Path:
    hexd = h.removeprefix("sha256:")
    return sl.evidence_dir / "tenant-a" / hexd[:2] / hexd


def execute(
    sl: Slice, p: dict[str, Any], user: str = "alice", reason: str = "retention review"
) -> Any:
    return sl.call(
        "POST",
        "/api/v1/retention/execute",
        user,
        json={"plan_hash": p["plan_hash"], "reason": reason},
    )


def test_nothing_is_eligible_before_the_run_is_closed_or_the_period_ends(sl_iso: Slice) -> None:
    _, _, run_id = sl_iso.full_run(EXPECTED)
    sl_iso.drain()  # REPORT_READY, awaiting approval
    sl_iso.clock.advance(days=400)
    assert mine(plan(sl_iso), run_id) == []
    sl_iso.clock.now = sl_iso.clock.now.replace(year=2026, month=10, day=15)  # back to launch time
    closed = closed_run(sl_iso)
    sl_iso.clock.advance(days=29)
    assert mine(plan(sl_iso), closed) == []  # the manifest keeps evidence for 30 days


def test_dry_run_changes_nothing_and_execution_is_hash_pinned(sl_iso: Slice) -> None:
    run_id = closed_run(sl_iso)
    sl_iso.clock.advance(days=31)
    p = plan(sl_iso)
    items = mine(p, run_id)
    assert items and p["mode"].startswith("DRY_RUN")
    assert all(blob(sl_iso, i["content_hash"]).exists() for i in items)  # planning moved nothing
    stale = {**p, "plan_hash": "sha256:" + "0" * 64}
    assert execute(sl_iso, stale).status_code == 409
    assert all(blob(sl_iso, i["content_hash"]).exists() for i in items)
    r = execute(sl_iso, p)
    assert r.status_code == 200 and r.json()["deleted"] == 0
    for i in items:
        h = i["content_hash"]
        assert not blob(sl_iso, h).exists()
        q = sl_iso.evidence_dir / ".quarantine" / "tenant-a" / h.removeprefix("sha256:")
        assert q.exists() and q.stat().st_size == i["size_bytes"]  # moved, never deleted
    assert sl_iso.sql(
        "SELECT count(*) FROM retention_actions a JOIN evidence_artifacts e ON a.ref=e.evidence_ref "
        "WHERE a.kind='EVIDENCE' AND e.run_id=:r",
        r=run_id,
    )[0][0] == len(items)
    assert mine(plan(sl_iso), run_id) == []  # idempotent: nothing left to do
    assert (
        sl_iso.call("GET", "/api/v1/retention/actions", "erin").json()[0]["executed_by"] == "alice"
    )
    assert ("retention.purge",) in sl_iso.sql(
        "SELECT action FROM audit_events WHERE action='retention.purge'"
    )


def test_reports_and_findings_survive_a_purge_and_say_so(sl_iso: Slice) -> None:
    run_id = closed_run(sl_iso)
    sl_iso.clock.advance(days=31)
    execute(sl_iso, plan(sl_iso))
    (rep,) = sl_iso.call("GET", f"/api/v1/assessments/{run_id}/reports", "carol").json()
    body = sl_iso.call("GET", f"/api/v1/reports/{rep['report_id']}", "carol").json()
    assert body["findings"] and body["evidence_manifest"]  # the record of what existed stays
    fid = body["findings"][0]["finding_id"]
    d = sl_iso.call("GET", f"/api/v1/assessments/{run_id}/findings/{fid}", "carol").json()
    assert all(e["purged_at"] for e in d["evidence"])


def test_a_legal_hold_blocks_purge_until_released(sl_iso: Slice) -> None:
    run_id = closed_run(sl_iso)
    sl_iso.clock.advance(days=31)
    assert (
        sl_iso.call(
            "POST",
            f"/api/v1/assessments/{run_id}/retention-hold",
            "alice",
            json={"reason": "audit request 42"},
        ).status_code
        == 201
    )
    assert (
        sl_iso.call(
            "POST",
            f"/api/v1/assessments/{run_id}/retention-hold",
            "alice",
            json={"reason": "again"},
        ).status_code
        == 409
    )
    p = plan(sl_iso)
    assert mine(p, run_id) == [] and run_id in p["held_runs"]
    assert (
        sl_iso.call(
            "POST", f"/api/v1/assessments/{run_id}/retention-hold/release", "alice"
        ).status_code
        == 200
    )
    assert (
        sl_iso.call(
            "POST", f"/api/v1/assessments/{run_id}/retention-hold/release", "alice"
        ).status_code
        == 409
    )
    assert mine(plan(sl_iso), run_id)


def test_a_plan_goes_stale_if_a_hold_appears_after_review(sl_iso: Slice) -> None:
    run_id = closed_run(sl_iso)
    sl_iso.clock.advance(days=31)
    p = plan(sl_iso)
    sl_iso.call(
        "POST",
        f"/api/v1/assessments/{run_id}/retention-hold",
        "alice",
        json={"reason": "late hold"},
    )
    assert execute(sl_iso, p).status_code == 409
    assert all(blob(sl_iso, i["content_hash"]).exists() for i in mine(p, run_id))


def test_a_blob_shared_with_retained_evidence_is_kept(sl_iso: Slice) -> None:
    old = closed_run(sl_iso)
    sl_iso.clock.advance(days=20)
    newer = closed_run(sl_iso)  # same fixture bytes may hash identically: shared blob
    sl_iso.clock.advance(days=15)  # old: 35 days, newer: 15 days
    p = plan(sl_iso)
    newer_hashes = {
        r[0]
        for r in sl_iso.sql("SELECT content_hash FROM evidence_artifacts WHERE run_id=:r", r=newer)
    }
    assert mine(p, newer) == []
    assert not ({i["content_hash"] for i in mine(p, old)} & newer_hashes)  # never planned
    execute(sl_iso, p)
    assert all(
        blob(sl_iso, h).exists() for h in newer_hashes
    )  # still readable for the retained run
    assert sl_iso.container.evidence is not None
    assert all(sl_iso.container.evidence.verify("tenant-a", h) for h in newer_hashes)


def test_old_uploads_not_used_by_any_run_become_eligible(sl_iso: Slice) -> None:
    pid = sl_iso.project()
    assert sl_iso.container.imports is not None
    meta = sl_iso.container.imports.upload(
        tenant_id="tenant-a", project_id=pid, actor="alice", kind="cmdb_csv", filename="a.csv",
        content="asset_id,hostname\nh1,web-01\n", now=sl_iso.clock.now,
    )  # fmt: skip
    assert not [i for i in plan(sl_iso)["items"] if i["ref"] == meta.import_id]
    sl_iso.clock.advance(days=366)
    p = plan(sl_iso)
    assert [i for i in p["items"] if i["ref"] == meta.import_id]
    execute(sl_iso, p)
    assert not blob(sl_iso, meta.content_hash).exists()
    assert (
        sl_iso.evidence_dir / ".quarantine" / "tenant-a" / meta.content_hash.removeprefix("sha256:")
    ).exists()


def test_only_the_right_role_in_the_right_tenant_can_manage_retention(sl_iso: Slice) -> None:
    run_id = closed_run(sl_iso)
    sl_iso.clock.advance(days=31)
    for user in ("bob", "carol", "rita", "erin"):
        assert sl_iso.call("GET", "/api/v1/retention/plan", user).status_code == 403
        assert (
            sl_iso.call(
                "POST",
                "/api/v1/retention/execute",
                user,
                json={"plan_hash": "sha256:" + "0" * 64, "reason": "x"},
            ).status_code
            == 403
        )
        assert (
            sl_iso.call(
                "POST", f"/api/v1/assessments/{run_id}/retention-hold", user, json={"reason": "x"}
            ).status_code
            == 403
        )
    assert sl_iso.call("GET", "/api/v1/retention/actions", "carol").status_code == 403
    assert mine(plan(sl_iso, "dave"), run_id) == []  # tenant-b sees nothing of tenant-a
    assert (
        sl_iso.call(
            "POST", f"/api/v1/assessments/{run_id}/retention-hold", "dave", json={"reason": "x"}
        ).status_code
        == 404
    )


def test_retention_records_are_append_only_and_tenant_scoped(sl_iso: Slice) -> None:
    run_id = closed_run(sl_iso)
    sl_iso.clock.advance(days=31)
    execute(sl_iso, plan(sl_iso))
    for stmt in (
        "UPDATE retention_actions SET quarantined=false",
        "DELETE FROM retention_actions",
        "DELETE FROM retention_holds",
    ):
        with pytest.raises(DBAPIError), tenant_connection(sl_iso.app_engine, "tenant-a") as c:
            c.execute(text(stmt))
    with tenant_connection(sl_iso.app_engine, "tenant-b") as c:
        assert c.execute(text("SELECT count(*) FROM retention_actions")).scalar_one() == 0
    assert run_id
