"""Human resolution of AI validator dissents (ADR-022) through the real API, Postgres and worker.

OVERRULE re-runs assurance at a new revision without the dissent and issues a new report revision
that supersedes the unapproved one; UPHOLD only records the decision. History is never rewritten.
"""

from __future__ import annotations

from typing import Any

import pytest
import sqlalchemy.exc
from sqlalchemy import text

from aisw.core.db import tenant_connection
from aisw.llm.validation import DISSENT_DEFECT
from tests.evaluation.stub import ScriptedModel
from tests.integration.test_ai_validation_pipeline import ai_run, reviewer
from tests.integration.test_analysis_pipeline import EXPECTED
from tests.slice import Slice

URL = "/api/v1/assessments/{}/ai-validations/resolutions"


def held_run(sl: Slice) -> tuple[str, str]:
    """A finished run whose reviewer dissented on exactly one finding."""
    held: list[str] = []

    def decide(t: dict[str, Any]) -> str:
        if t["kind"] == "finding" and (not held or held[0] == t["target_ref"]):
            held[:1] = [t["target_ref"]]
            return "DISSENT"
        return "CONCUR"

    _, run_id = ai_run(sl, reviewer(decide))
    return run_id, held[0]


def reports(sl: Slice, run_id: str) -> list[dict[str, Any]]:
    return list(sl.call("GET", f"/api/v1/assessments/{run_id}/reports", "carol").json())


def approve(sl: Slice, row: dict[str, Any]) -> Any:
    return sl.call("POST", f"/api/v1/reports/{row['report_id']}/approve", "rita",
                   json={"report_hash": row["report_hash"]})  # fmt: skip


def resolve(
    sl: Slice,
    run_id: str,
    ref: str,
    decision: str,
    user: str = "rita",
    reason: str = "Evidence re-read by the reviewer; the check result stands.",
) -> Any:
    return sl.call("POST", URL.format(run_id), user,
                   json={"target_ref": ref, "decision": decision, "reason": reason})  # fmt: skip


def test_overrule_reassesses_and_supersedes_the_unapproved_report(sl: Slice) -> None:
    run_id, ref = held_run(sl)
    fid = ref.removeprefix("finding:")
    assert fid in {f["finding_id"] for f in sl.report(run_id)["pending_review"]}
    (first,) = reports(sl, run_id)

    r = resolve(sl, run_id, ref, "OVERRULE")
    assert r.status_code == 200, r.text
    assert r.json()["assurance_revision"] == 2 and r.json()["reassessing"]
    assert sl.status(run_id)["state"] == "ASSURANCE"
    sl.drain()
    assert sl.status(run_id)["state"] in {"REPORT_READY", "PARTIAL"}

    rows = reports(sl, run_id)
    assert [(x["revision"], x["approval_state"]) for x in rows] == [
        (2, "PENDING"),
        (1, "SUPERSEDED"),
    ]
    assert rows[0]["report_id"] == f"rep-{run_id}-r2"
    assert rows[0]["supersedes"] == first["report_id"]
    second = sl.report(run_id)
    assert second["revision"] == {"number": 2, "supersedes": first["report_id"]}
    assert fid in {f["finding_id"] for f in second["findings"]}
    assert fid not in {f["finding_id"] for f in second["pending_review"]}
    assert second["ai"]["validation"]["held_for_review"] == 0
    assert second["ai"]["validation"]["overruled"] == 1
    assert any("overruled 1" in x for x in second["limitations"])
    html = sl.call("GET", f"/api/v1/reports/{rows[0]['report_id']}?format=html", "carol").text
    assert f"supersedes report {first['report_id']}" in html

    history = sl.sql("SELECT revision, verdict, defect_codes FROM assurance_results "
                     "WHERE run_id=:r AND item_ref=:i ORDER BY revision", r=run_id, i=ref)  # fmt: skip
    assert history[0][:2] == (1, "NEEDS_REVIEW") and DISSENT_DEFECT in history[0][2]
    assert history[1][:2] == (2, "ACCEPT") and DISSENT_DEFECT not in history[1][2]
    assert sl.status(run_id)["report"]["report_id"] == rows[0]["report_id"]

    assert approve(sl, first).status_code == 409
    new = approve(sl, rows[0])
    assert new.status_code == 200, new.text

    phases = [e["payload"] for e in sl.events(run_id) if e["type"] == "phase.changed"]
    assert any(p.get("to") == "ASSURANCE" and p.get("reason") == "AI_DISSENT_OVERRULED"
               for p in phases)  # fmt: skip
    audit = sl.sql("SELECT action, actor, resource FROM audit_events WHERE action LIKE "
                   "'ai_validation.%'")  # fmt: skip
    assert ("ai_validation.overrule", "rita", f"ai_validation:{run_id}:{ref}") in audit


def test_uphold_records_the_decision_and_changes_nothing(sl: Slice) -> None:
    run_id, ref = held_run(sl)
    before = reports(sl, run_id)
    r = resolve(sl, run_id, ref, "UPHOLD", reason="Agree: the observed value is ambiguous.")
    assert r.status_code == 200, r.text
    assert not r.json()["reassessing"]
    assert sl.drain() == 0
    assert reports(sl, run_id) == before
    items = sl.call("GET", f"/api/v1/assessments/{run_id}/ai-validations", "carol").json()["items"]
    (item,) = [i for i in items if i["target_ref"] == ref]
    assert item["resolution"]["decision"] == "UPHOLD" and item["resolution"]["decided_by"] == "rita"
    summary = sl.call("GET", f"/api/v1/assessments/{run_id}/ai-validations", "carol").json()
    assert summary["summary"]["upheld"] == 1 and summary["summary"]["held_for_review"] == 1


def test_replay_is_idempotent_and_a_conflicting_decision_is_rejected(sl: Slice) -> None:
    run_id, ref = held_run(sl)
    assert resolve(sl, run_id, ref, "UPHOLD").status_code == 200
    again = resolve(sl, run_id, ref, "UPHOLD")
    assert again.status_code == 200 and again.headers.get("Idempotent-Replay") == "true"
    assert resolve(sl, run_id, ref, "OVERRULE").status_code == 409
    rows = sl.sql("SELECT count(*) FROM ai_validation_resolutions WHERE run_id=:r", r=run_id)
    assert rows[0][0] == 1


def test_only_a_report_approver_other_than_the_requester_may_resolve(sl: Slice) -> None:
    run_id, ref = held_run(sl)
    assert resolve(sl, run_id, ref, "OVERRULE", user="carol").status_code == 403
    assert resolve(sl, run_id, ref, "OVERRULE", user="alice").status_code == 403
    assert resolve(sl, run_id, ref, "OVERRULE", user="dave").status_code == 403
    rows = sl.sql("SELECT count(*) FROM ai_validation_resolutions WHERE run_id=:r", r=run_id)
    assert rows[0][0] == 0


def test_requester_cannot_resolve_their_own_run(sl: Slice) -> None:
    held: list[str] = []

    def decide(t: dict[str, Any]) -> str:
        if t["kind"] == "finding" and not held:
            held.append(t["target_ref"])
        return "DISSENT" if held and t["target_ref"] == held[0] else "CONCUR"

    sl.enable_ai(ScriptedModel(reviewer(decide)))
    sl.worker.ai_validation = True
    sl.worker.validation_concurrency = 1
    pid = sl.project()
    sl.inventory(pid, EXPECTED)
    r = sl.launch(pid, sl.approved_manifest(pid), user="sam", ai_assist=True)
    assert r.status_code == 202, r.text
    run_id = r.json()["run_id"]
    sl.drain()
    assert resolve(sl, run_id, held[0], "OVERRULE", user="sam").status_code == 403
    assert resolve(sl, run_id, held[0], "OVERRULE", user="rita").status_code == 200


def test_only_a_dissent_on_a_pending_report_can_be_resolved(sl: Slice) -> None:
    run_id, ref = held_run(sl)
    other = next(
        t
        for (t,) in sl.sql(
            "SELECT target_ref FROM ai_validations WHERE run_id=:r AND verdict='CONCUR'", r=run_id
        )  # fmt: skip
    )
    assert resolve(sl, run_id, other, "OVERRULE").status_code == 409
    assert resolve(sl, run_id, "finding:does-not-exist", "OVERRULE").status_code == 404

    ok = approve(sl, reports(sl, run_id)[0])
    assert ok.status_code == 200, ok.text
    assert resolve(sl, run_id, ref, "OVERRULE").status_code == 409


def test_reason_is_required_redacted_and_bounded(sl: Slice) -> None:
    run_id, ref = held_run(sl)
    assert resolve(sl, run_id, ref, "UPHOLD", reason="").status_code == 422
    secret = "password=hunter2-" + "x" * 2000  # aisw:allow-secret
    assert resolve(sl, run_id, ref, "UPHOLD", reason=secret).status_code == 200
    ((reason,),) = sl.sql("SELECT reason FROM ai_validation_resolutions WHERE run_id=:r", r=run_id)
    assert "hunter2" not in reason and len(reason) <= 1000


def test_resolutions_are_append_only_and_tenant_scoped(sl: Slice) -> None:
    run_id, ref = held_run(sl)
    assert resolve(sl, run_id, ref, "UPHOLD").status_code == 200
    with pytest.raises(sqlalchemy.exc.DBAPIError):
        with tenant_connection(sl.app_engine, "tenant-a") as c:
            c.execute(text("UPDATE ai_validation_resolutions SET decision='OVERRULE' "
                           "WHERE run_id=:r"), {"r": run_id})  # fmt: skip
    with pytest.raises(sqlalchemy.exc.DBAPIError):
        with tenant_connection(sl.app_engine, "tenant-a") as c:
            c.execute(text("DELETE FROM ai_validation_resolutions WHERE run_id=:r"), {"r": run_id})
    with tenant_connection(sl.app_engine, "tenant-b") as c:
        n = c.execute(text("SELECT count(*) FROM ai_validation_resolutions WHERE run_id=:r"),
                      {"r": run_id})  # fmt: skip
        assert n.scalar() == 0
    with pytest.raises(sqlalchemy.exc.DBAPIError):
        with tenant_connection(sl.app_engine, "tenant-a") as c:
            c.execute(text("UPDATE reports SET revision=9 WHERE run_id=:r"), {"r": run_id})
