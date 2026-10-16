"""Negative, abuse and resilience tests for the vertical slice (blueprint 14.1 and Appendix G)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from aisw.core.db import tenant_connection
from aisw.core.rbac import ActorContext, Role
from tests.slice import Slice

pytestmark = pytest.mark.security
EXPECTED = ["host-1", "host-2", "host-3"]


def event_codes(sl: Slice, run_id: str, kind: str) -> list[str]:
    out: list[str] = []
    for e in sl.events(run_id):
        if e["type"] == kind:
            out += e["payload"].get("error_codes", []) + e["payload"].get("codes", [])
    return out


# ---- rejected scope = zero tool calls ------------------------------------------------------
def test_rejected_scope_and_launch_attempts_dispatch_nothing(sl: Slice) -> None:
    pid = sl.project()
    sl.inventory(pid, EXPECTED)
    # 1) target outside inventory, 2) wildcard, 3) unknown adapter, 4) unknown policy pack
    bad_targets: list[tuple[dict[str, Any], str]] = [
        (
            {"targets": [{"kind": "asset_group", "selector": "not-in-inventory"}]},
            "TARGET_NOT_IN_INVENTORY",
        ),
        ({"targets": [{"kind": "asset_group", "selector": "*"}]}, "WILDCARD_SCOPE"),
        (
            {
                "allowed_adapters": ["nmap"],
                "profiles": {"nmap": {"profile_id": "x", "profile_class": "READ_ONLY"}},
            },
            "UNKNOWN_ADAPTER",
        ),
    ]
    for over, code in bad_targets:
        r = sl.call(
            "POST", "/api/v1/scope-manifests", "alice", json=sl.manifest_payload(pid, **over)
        )
        assert r.status_code == 422 and code in r.json()["reason_codes"], r.text
    m = sl.approved_manifest(pid)
    # unapproved manifest, stale hash, wrong role, unknown pack, foreign tenant
    draft = sl.call(
        "POST",
        "/api/v1/scope-manifests",
        "alice",
        json=sl.manifest_payload(pid, policy_version="nope:1"),
    ).json()["manifest"]
    sl.call("POST", f"/api/v1/scope-manifests/{draft['manifest_id']}/preflight", "alice")
    unapproved = sl.launch(pid, draft)
    assert unapproved.status_code == 422 and unapproved.json()["reason_codes"] == [
        "MANIFEST_NOT_APPROVED"
    ]
    sl.call("POST", f"/api/v1/scope-manifests/{draft['manifest_id']}/approve", "bob", json={})
    # (draft v2 is now approved and v1 superseded) -> v1 launch refused
    assert sl.launch(pid, m).json()["reason_codes"] == ["MANIFEST_NOT_APPROVED"]
    nopack = sl.launch(pid, {**draft, "canonical_hash": draft["canonical_hash"]})
    assert nopack.status_code == 422 and nopack.json()["reason_codes"] == ["POLICY_PACK_UNKNOWN"]
    stale = sl.launch(pid, {**draft, "canonical_hash": "sha256:" + "1" * 64})
    assert stale.json()["reason_codes"] == ["STALE_HASH"]
    assert sl.launch(pid, draft, user="bob").status_code == 403  # approvers cannot launch
    assert sl.launch(pid, draft, user="dave").status_code == 403
    sl.drain()
    assert sl.executions == 0 and sl.container.gateway.dispatched == 0  # type: ignore[union-attr]
    assert sl.sql("SELECT count(*) FROM assessment_runs WHERE project_id=:p", p=pid)[0][0] == 0
    assert sl.sql("SELECT count(*) FROM execution_permits WHERE project_id=:p", p=pid)[0][0] == 0


def test_domain_and_adapter_params_cannot_exceed_the_manifest(sl: Slice) -> None:
    pid = sl.project()
    sl.inventory(pid, EXPECTED)
    m = sl.approved_manifest(pid)
    r = sl.launch(pid, m, requested_domains=["network"])
    assert r.status_code == 422 and r.json()["reason_codes"] == ["DOMAIN_NOT_IN_MANIFEST"]
    r2 = sl.launch(pid, m, adapter_params={"shell": {"cmd": "id"}})
    assert r2.json()["reason_codes"] == ["ADAPTER_PARAMS_FOR_UNLISTED_ADAPTER"]
    assert sl.executions == 0


def test_hostile_adapter_params_are_rejected_by_the_gateway(sl: Slice) -> None:
    pid = sl.project()
    sl.inventory(pid, EXPECTED)
    m = sl.approved_manifest(pid)
    for bad in ("../../etc/passwd", "baseline-ok; rm -rf /", "/etc/shadow"):
        run_id = sl.launch(pid, m, fixture_set=bad).json()["run_id"]
        sl.drain()
        assert sl.status(run_id)["state"] == "FAILED"
        assert event_codes(sl, run_id, "task.failed") == ["INVALID_PARAMS"]
    assert sl.executions == 0


# ---- tenant isolation across the whole pipeline ---------------------------------------------
def test_other_tenant_sees_nothing_of_the_run(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    rows = sl.call("GET", f"/api/v1/assessments/{run_id}/reports", "carol").json()
    rid = rows[0]["report_id"]
    for url in (f"/api/v1/assessments/{run_id}", f"/api/v1/assessments/{run_id}/events",
                f"/api/v1/assessments/{run_id}/coverage", f"/api/v1/assessments/{run_id}/findings",
                f"/api/v1/assessments/{run_id}/reports"):  # fmt: skip
        r = sl.call("GET", url, "dave")
        assert r.status_code in (403, 404), (url, r.status_code)
    assert sl.call("GET", f"/api/v1/assessments/{run_id}", "dave").status_code == 404
    assert sl.call("POST", f"/api/v1/assessments/{run_id}/cancel", "dave").status_code in (403, 404)
    assert sl.call("GET", f"/api/v1/reports/{rid}", "dave").status_code in (403, 404)


def test_database_roles_cannot_cross_tenants(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    # app role without tenant context: nothing, for every pipeline table
    tables = ["assessment_runs", "run_tasks", "run_events", "evidence_artifacts", "assets",
              "observations", "findings", "coverage_ledger", "reports", "inventory_entries"]  # fmt: skip
    with sl.app_engine.connect() as c:
        for t in tables:
            assert c.execute(text(f"SELECT count(*) FROM {t}")).scalar_one() == 0, t
    # worker role may discover OPEN tasks/runs across tenants but nothing else
    with sl.worker_engine.connect() as c:
        assert (
            c.execute(
                text("SELECT count(*) FROM run_tasks WHERE run_id=:r"), {"r": run_id}
            ).scalar_one()
            == 1
        )
        assert (
            c.execute(
                text("SELECT count(*) FROM assessment_runs WHERE run_id=:r"), {"r": run_id}
            ).scalar_one()
            == 1
        )
        for t in ("run_events", "evidence_artifacts", "assets", "observations", "findings",
                  "coverage_ledger", "reports", "inventory_entries", "projects", "audit_events"):  # fmt: skip
            assert c.execute(text(f"SELECT count(*) FROM {t}")).scalar_one() == 0, t
    sl.drain()
    with sl.worker_engine.connect() as c:  # once terminal, even tasks/runs are invisible again
        assert (
            c.execute(
                text("SELECT count(*) FROM run_tasks WHERE run_id=:r"), {"r": run_id}
            ).scalar_one()
            == 0
        )
    # the API role never gets the cross-tenant policy
    with sl.app_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM run_tasks")).scalar_one() == 0
    with tenant_connection(sl.app_engine, "tenant-b") as c:
        assert (
            c.execute(
                text("SELECT count(*) FROM run_tasks WHERE run_id=:r"), {"r": run_id}
            ).scalar_one()
            == 0
        )


def test_run_events_and_evidence_metadata_are_append_only(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    for sql in ("UPDATE run_events SET event_type='x'", "DELETE FROM run_events",
                "UPDATE evidence_artifacts SET content_hash='sha256:' || repeat('0',64)",
                "DELETE FROM evidence_artifacts"):  # fmt: skip
        with pytest.raises(DBAPIError, match="permission denied"):
            with tenant_connection(sl.app_engine, "tenant-a") as c:
                c.execute(text(sql))


# ---- untrusted evidence ---------------------------------------------------------------------
def test_prompt_injection_and_secrets_in_tool_output_are_inert(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED[:2], fixture_set="baseline-injection")
    sl.drain()
    st = sl.status(run_id)
    assert st["state"] == "REPORT_READY" and st["tasks"] == {"SUCCEEDED": 1}
    # the injected instructions changed nothing: one task, no new targets, no extra dispatch
    assert sl.sql("SELECT count(*) FROM run_tasks WHERE run_id=:r", r=run_id)[0][0] == 1
    assert sl.executions == 1
    rep = sl.report(run_id)
    # host-1's hostile value is just a failing value; it cannot mark anything PASS or approve
    assert any(
        f["affected_assets"] == ["host-1"] and "root login" in f["title"] for f in rep["findings"]
    )
    assert rep["finding_counts"]["total"] == 1
    assert (
        sl.status(run_id)["state"] != "CLOSED"
    )  # the "approve the report" instruction did nothing
    # the secret never reached disk, the database, the report or the event log
    needle = "hunter2hunter2"
    blob = "".join(p.read_text(errors="ignore") for p in sl.evidence_dir.rglob("*") if p.is_file())
    assert needle not in blob and "[REDACTED]" in blob
    assert needle not in json.dumps(rep) and needle not in json.dumps(sl.events(run_id))
    dump = sl.sql("SELECT observed_value::text FROM observations WHERE run_id=:r", r=run_id)
    assert needle not in str(dump)
    art = sl.sql("SELECT redacted FROM evidence_artifacts WHERE run_id=:r", r=run_id)
    assert art == [(True,)]  # flagged as redacted in metadata


# ---- durability: crash, lease, retry --------------------------------------------------------
class Crash(BaseException):
    """Simulates the process dying (not caught by the worker's `except Exception`)."""


def test_crash_after_dispatch_resumes_without_duplicates(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    real = sl.worker._ingest
    state = {"crashed": False}

    def dying(*a: Any, **k: Any) -> None:
        if not state["crashed"]:
            state["crashed"] = True
            raise Crash
        real(*a, **k)

    sl.worker._ingest = dying  # type: ignore[method-assign]
    with pytest.raises(Crash):
        sl.drain()
    (task,) = sl.sql(
        "SELECT status, attempts, locked_until FROM run_tasks WHERE run_id=:r", r=run_id
    )
    assert task[0] == "RUNNING" and task[1] == 1 and sl.executions == 1
    assert sl.drain() == 0 or sl.status(run_id)["state"] != "REPORT_READY"  # lease still held
    sl.clock.advance(minutes=6)  # lease (5 min) expires
    sl.drain()
    st = sl.status(run_id)
    assert st["state"] == "REPORT_READY" and st["tasks"] == {"SUCCEEDED": 1}
    assert sl.executions == 2  # the tool call was repeated...
    assert sl.sql("SELECT count(*) FROM evidence_artifacts WHERE run_id=:r", r=run_id)[0][0] == 1
    assert sl.sql("SELECT count(*) FROM observations WHERE run_id=:r", r=run_id)[0][0] == 8
    assert sl.sql("SELECT count(*) FROM findings WHERE run_id=:r", r=run_id)[0][0] == 2
    assert sl.sql("SELECT attempts FROM run_tasks WHERE run_id=:r", r=run_id)[0][0] == 2
    assert len(sl.report(run_id)["findings"]) == 2  # ...but nothing was duplicated


def test_repeated_crashes_exhaust_attempts_and_fail_the_task(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)

    def dying(*a: Any, **k: Any) -> None:
        raise Crash

    sl.worker._ingest = dying  # type: ignore[method-assign]
    for _ in range(3):
        with pytest.raises(Crash):
            sl.drain()
        sl.clock.advance(minutes=6)
    sl.drain()  # 4th claim sees attempts == max_attempts and fails the task instead of retrying
    st = sl.status(run_id)
    assert (
        st["state"] == "FAILED"
        and st["reason"] == "ALL_TASKS_FAILED"
        and st["tasks"] == {"FAILED": 1}
    )
    assert "LEASE_EXPIRED_MAX_ATTEMPTS" in event_codes(sl, run_id, "task.failed")
    assert sl.executions == 3


def test_adapter_errors_retry_with_backoff_then_fail(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    calls = {"n": 0}
    real = sl.fixture.execute  # type: ignore[union-attr]

    def flaky(job: Any) -> Any:
        calls["n"] += 1
        if calls["n"] < 2:
            raise RuntimeError("scanner timeout")
        return real(job)

    sl.fixture.execute = flaky  # type: ignore[union-attr,method-assign]
    sl.drain()
    (row,) = sl.sql(
        "SELECT status, attempts, available_at FROM run_tasks WHERE run_id=:r", r=run_id
    )
    assert row[0] == "QUEUED" and row[1] == 1 and row[2] > sl.clock.now  # backoff, not a hot loop
    assert sl.drain() == 0  # nothing runnable until the delay elapses
    sl.clock.advance(seconds=10)
    sl.drain()
    assert sl.status(run_id)["state"] == "REPORT_READY" and calls["n"] == 2
    assert "retry scheduled" in json.dumps(sl.events(run_id))


def test_retries_are_bounded(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)

    def always(job: Any) -> Any:
        raise RuntimeError("down")

    sl.fixture.execute = always  # type: ignore[union-attr,method-assign]
    for _ in range(5):
        sl.drain()
        sl.clock.advance(minutes=1)
    st = sl.status(run_id)
    assert st["state"] == "FAILED" and st["tasks"] == {"FAILED": 1}
    assert "RETRIES_EXHAUSTED" in event_codes(sl, run_id, "task.failed")
    assert sl.sql("SELECT attempts FROM run_tasks WHERE run_id=:r", r=run_id)[0][0] == 3


def test_permit_revoked_after_launch_blocks_every_task(sl: Slice) -> None:
    pid, _, run_id = sl.full_run(EXPECTED)
    permit = sl.sql("SELECT permit_id::text FROM assessment_runs WHERE run_id=:r", r=run_id)[0][0]
    svc = sl.container.service
    assert svc is not None
    operator = ActorContext("tenant-a", "alice", frozenset({Role.ASSESSMENT_OPERATOR}))
    svc.revoke_permit(operator, permit, cid="t")
    sl.drain()
    st = sl.status(run_id)
    assert st["state"] == "FAILED" and st["tasks"] == {"REJECTED": 1}
    assert event_codes(sl, run_id, "task.failed") == ["PERMIT_REVOKED"]
    assert sl.executions == 0


def test_expired_permit_during_queueing_rejects_instead_of_running(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.clock.advance(minutes=20)  # permit TTL is 15 minutes
    sl.drain()
    assert sl.status(run_id)["state"] == "FAILED" and sl.executions == 0
    assert event_codes(sl, run_id, "task.failed") == ["PERMIT_EXPIRED_OR_TASK_NOT_ALLOWED"]


# ---- independent assurance ------------------------------------------------------------------
def advance_to_assurance(sl: Slice, run_id: str) -> None:
    for _ in range(50):
        if sl.status(run_id)["state"] == "ASSURANCE":
            return
        assert sl.worker.step()
    raise AssertionError("run never reached ASSURANCE")


def evidence_files(sl: Slice) -> list[Path]:
    return [p for p in sl.evidence_dir.rglob("*") if p.is_file()]


def test_tampered_evidence_rejects_findings_and_keeps_them_out_of_the_report(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    advance_to_assurance(sl, run_id)
    (f,) = evidence_files(sl)
    f.write_text(
        f.read_text().replace('"ssh.permit_root_login":"yes"', '"ssh.permit_root_login":"no"')
    )
    sl.drain()
    st = sl.status(run_id)
    assert st["state"] in {"REPORT_READY", "PARTIAL"}
    rep = sl.report(run_id)
    assert rep["findings"] == [] and rep["finding_counts"] == {"total": 0}
    assert rep["assurance"]["rejected"] == 2
    assert any("failed independent assurance" in x for x in rep["limitations"])
    verdicts = sl.sql(
        "SELECT verdict, defect_codes::text FROM assurance_results WHERE run_id=:r "
        "AND item_ref LIKE 'finding:%'",
        r=run_id,
    )
    assert {v[0] for v in verdicts} == {"REJECT"} and all(
        "EVIDENCE_HASH_MISMATCH" in v[1] for v in verdicts
    )
    assert sl.call("GET", f"/api/v1/assessments/{run_id}/findings", "alice").json()["total"] == 0
    assert (
        sl.call("GET", f"/api/v1/assessments/{run_id}/findings?verdict=REJECT", "alice").status_code
        == 403
    )
    rejected = sl.call(
        "GET", f"/api/v1/assessments/{run_id}/findings?verdict=REJECT", "erin"
    ).json()
    assert rejected["total"] == 2 and not any(
        i["authoritative"] for i in rejected["items"]
    )  # preserved


def test_missing_evidence_file_is_rejected(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    advance_to_assurance(sl, run_id)
    (f,) = evidence_files(sl)
    f.unlink()
    sl.drain()
    assert sl.report(run_id)["findings"] == []
    assert sl.sql(
        "SELECT DISTINCT verdict FROM assurance_results WHERE run_id=:r "
        "AND item_ref LIKE 'finding:%'",
        r=run_id,
    ) == [("REJECT",)]


def test_stale_evidence_needs_review_and_is_disclosed_not_dropped(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    advance_to_assurance(sl, run_id)
    sl.clock.advance(hours=25)  # beyond the 24h freshness window
    sl.drain()
    rep = sl.report(run_id)
    assert rep["findings"] == []  # not authoritative
    assert sorted(p["severity"] for p in rep["pending_review"]) == ["HIGH", "MEDIUM"]  # but visible
    assert rep["assurance"]["needs_review"] == 2
    assert any("await review" in x for x in rep["limitations"])
    items = sl.call("GET", f"/api/v1/assessments/{run_id}/findings", "alice").json()["items"]
    assert len(items) == 2 and not any(i["authoritative"] for i in items)
    assert {i["assurance_verdict"] for i in items} == {"NEEDS_REVIEW"}


def test_evidence_store_outage_means_review_not_approval(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    advance_to_assurance(sl, run_id)

    def down(tenant: str, h: str) -> bool:
        raise OSError("storage unavailable")

    sl.worker.evidence.verify = down  # type: ignore[method-assign,assignment]
    sl.drain()
    assert sl.report(run_id)["findings"] == []
    assert sl.sql(
        "SELECT DISTINCT verdict FROM assurance_results WHERE run_id=:r "
        "AND item_ref LIKE 'finding:%'",
        r=run_id,
    ) == [("NEEDS_REVIEW",)]


def test_only_accepted_findings_reach_the_report_dataset(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    rows = sl.sql("SELECT assurance_verdict FROM findings WHERE run_id=:r", r=run_id)
    assert {r[0] for r in rows} == {"ACCEPT"}
    assert (
        sl.sql(
            "SELECT count(*) FROM assurance_results WHERE run_id=:r AND verdict='ACCEPT' "
            "AND item_ref LIKE 'finding:%'",
            r=run_id,
        )[0][0]
        == 2
    )


def test_database_refuses_untraceable_findings_and_unevidenced_pass(sl: Slice) -> None:
    pid, _, run_id = sl.full_run(EXPECTED)
    with pytest.raises(DBAPIError, match="check constraint"):
        with tenant_connection(sl.app_engine, "tenant-a") as c:
            c.execute(
                text(
                    "INSERT INTO findings (tenant_id, run_id, finding_id, stable_dedupe_key, "
                    "project_id, severity, outcome, body) VALUES ('tenant-a', :r, 'f-x', 'k', :p, "
                    "'HIGH', 'FAIL', '{\"evidence_refs\": []}')"
                ),
                {"r": run_id, "p": pid},
            )
    with pytest.raises(DBAPIError, match="check constraint"):
        with tenant_connection(sl.app_engine, "tenant-a") as c:
            c.execute(
                text(
                    "INSERT INTO control_assessments (tenant_id, run_id, framework, version, "
                    "control_id, applicability, outcome, policy_version) VALUES ('tenant-a', :r, "
                    "'f', '1', 'c', 'APPLICABLE', 'PASS', 'p')"
                ),
                {"r": run_id},
            )
    with pytest.raises(DBAPIError, match="check constraint"):  # ACCEPT cannot carry defects
        with tenant_connection(sl.app_engine, "tenant-a") as c:
            c.execute(
                text(
                    "INSERT INTO assurance_results (tenant_id, run_id, item_ref, verdict, "
                    "defect_codes, validation_version, validated_at) VALUES ('tenant-a', :r, 'x', "
                    "'ACCEPT', '[\"BROKEN\"]', '1', now())"
                ),
                {"r": run_id},
            )


def test_worker_whose_lease_expired_cannot_write_after_losing_the_task(sl: Slice) -> None:
    """Fencing: a slow worker finishing after another worker re-claimed the task changes nothing."""
    _, _, run_id = sl.full_run(EXPECTED)
    for _ in range(5):  # let AUTHORIZED -> ASSESSMENT_DISPATCH happen first
        if sl.status(run_id)["state"] == "ASSESSMENT_DISPATCH":
            break
        sl.worker.advance_one()
    slow = sl.worker
    stale_task = slow.claim()
    assert stale_task is not None and stale_task["attempts"] == 1
    sl.clock.advance(minutes=6)  # lease expires while the "slow" worker is still running
    fast = sl.container.make_worker(sl.worker_engine, worker_id="w-2")
    fresh_task = fast.claim()
    assert fresh_task is not None and fresh_task["attempts"] == 2
    fast.process(fresh_task)
    before = (
        sl.sql("SELECT count(*) FROM run_events WHERE run_id=:r", r=run_id)[0][0],
        sl.sql("SELECT count(*) FROM observations WHERE run_id=:r", r=run_id)[0][0],
    )
    slow.process(stale_task)  # the original worker finally finishes: must be a no-op
    after = (
        sl.sql("SELECT count(*) FROM run_events WHERE run_id=:r", r=run_id)[0][0],
        sl.sql("SELECT count(*) FROM observations WHERE run_id=:r", r=run_id)[0][0],
    )
    assert before == after
    types = [e["type"] for e in sl.events(run_id)]
    assert types.count("task.completed") == 1 and types.count("evidence.batch.stored") == 1
    assert sl.sql("SELECT status, attempts FROM run_tasks WHERE run_id=:r", r=run_id) == [
        ("SUCCEEDED", 2)
    ]
    sl.drain()
    assert sl.status(run_id)["state"] == "REPORT_READY" and len(sl.report(run_id)["findings"]) == 2
