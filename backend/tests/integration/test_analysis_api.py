"""Recommendation decisions, ticket drafts, listings and the agent registry (API level)."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from aisw.agents.registry import AGENTS, agent_for_adapter
from aisw.core.config import Settings
from aisw.core.db import tenant_connection
from tests.evaluation.stub import ScriptedModel
from tests.integration.test_analysis_pipeline import grounded
from tests.slice import Slice

EXPECTED = ["host-1", "host-2", "host-3"]


def finished_run(sl: Slice) -> tuple[str, list[dict[str, Any]]]:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    recs = sl.call("GET", f"/api/v1/assessments/{run_id}/recommendations", "carol").json()
    assert len(recs) == 2
    return run_id, list(recs)


def decide(
    sl: Slice, run_id: str, rid: str, decision: str, reason: str = "reviewed", user: str = "bob"
) -> Any:
    return sl.call(
        "POST", f"/api/v1/assessments/{run_id}/recommendations/{rid}/decision", user,
        json={"decision": decision, "reason": reason},
    )  # fmt: skip


def enable_tickets(sl: Slice) -> None:
    sl.container.settings = Settings(
        env="test", dev_auth_stub=True, enable_itsm_ticket_creation=True
    )


def test_listings_expose_only_what_is_authoritative(sl: Slice) -> None:
    run_id, recs = finished_run(sl)
    assert all(r["assurance_verdict"] == "ACCEPT" and r["authoritative"] for r in recs)
    assert all(r["executable"] is False and r["status"] == "DRAFT" for r in recs)
    assert all(r["effort"]["value"] is None for r in recs)
    scen = sl.call("GET", f"/api/v1/assessments/{run_id}/scenarios", "carol").json()
    assert len(scen) == 1 and scen[0]["narrative"] is None
    page = sl.call("GET", "/api/v1/recommendations", "carol").json()
    assert page["total"] >= 2 and all(i["run_id"] for i in page["items"])


def test_listings_require_a_read_permission_and_respect_tenancy(sl: Slice) -> None:
    run_id, recs = finished_run(sl)
    assert (
        sl.call("GET", f"/api/v1/assessments/{run_id}/recommendations", "nobody").status_code == 401
    )
    assert sl.call("GET", f"/api/v1/assessments/{run_id}/recommendations", "dave").status_code in {
        403,
        404,
    }
    assert sl.call("GET", f"/api/v1/assessments/{run_id}/scenarios", "dave").status_code in {
        403,
        404,
    }
    assert decide(sl, run_id, recs[0]["recommendation_id"], "ACCEPT", user="dave").status_code in {
        403,
        404,
    }


def test_only_an_approver_can_decide_and_decision_executes_nothing(sl: Slice) -> None:
    run_id, recs = finished_run(sl)
    rid = recs[0]["recommendation_id"]
    for user in ("alice", "carol", "rita", "erin"):
        assert decide(sl, run_id, rid, "ACCEPT", user=user).status_code == 403
    r = decide(sl, run_id, rid, "ACCEPT", reason="Approved for the Q4 plan")
    assert r.status_code == 200 and r.json()["status"] == "APPROVED_FOR_PLANNING"
    assert r.json()["executed"] is False
    row = sl.sql(
        "SELECT status, decided_by, decision_reason FROM recommendations WHERE run_id=:r AND recommendation_id=:i",
        r=run_id,
        i=rid,
    )[0]
    assert row == ("APPROVED_FOR_PLANNING", "bob", "Approved for the Q4 plan")
    audit = sl.sql("SELECT action FROM audit_events WHERE action LIKE 'recommendation.%'")
    assert ("recommendation.accept",) in audit


def test_decision_is_idempotent_and_final(sl: Slice) -> None:
    run_id, recs = finished_run(sl)
    rid = recs[0]["recommendation_id"]
    assert decide(sl, run_id, rid, "ACCEPT", "ok").status_code == 200
    again = decide(sl, run_id, rid, "ACCEPT", "ok")
    assert again.status_code == 200 and again.headers["idempotent-replay"] == "true"
    assert decide(sl, run_id, rid, "REJECT", "changed my mind").status_code == 409
    deferred = recs[1]["recommendation_id"]
    assert (
        decide(sl, run_id, deferred, "DEFER", "need owner input").json()["status"] == "NEEDS_REVIEW"
    )
    assert decide(sl, run_id, deferred, "REJECT", "no").json()["status"] == "REJECTED"


def test_decision_reason_is_redacted_and_unknown_items_are_404(sl: Slice) -> None:
    run_id, recs = finished_run(sl)
    rid = recs[0]["recommendation_id"]
    decide(sl, run_id, rid, "DEFER", "see password=Hunter2Hunter2 in the ticket")
    stored = sl.sql(
        "SELECT decision_reason FROM recommendations WHERE run_id=:r AND recommendation_id=:i",
        r=run_id,
        i=rid,
    )[0][0]
    assert "Hunter2Hunter2" not in stored
    assert decide(sl, run_id, "rec-nope", "ACCEPT").status_code == 404
    assert sl.call("POST", f"/api/v1/assessments/{run_id}/recommendations/{rid}/decision", "bob",
                   json={"decision": "ACCEPT"}).status_code == 422  # reason is mandatory  # fmt: skip
    assert sl.call("POST", f"/api/v1/assessments/{run_id}/recommendations/{rid}/decision", "bob",
                   json={"decision": "EXECUTE", "reason": "x"}).status_code == 422  # fmt: skip


def test_database_refuses_acceptance_without_a_human_decision_or_assurance(sl: Slice) -> None:
    run_id, recs = finished_run(sl)
    rid = recs[0]["recommendation_id"]
    for stmt in (
        "UPDATE recommendations SET status='APPROVED_FOR_PLANNING' WHERE run_id=:r AND recommendation_id=:i",
        "UPDATE recommendations SET status='APPROVED_FOR_PLANNING', decided_by='x' WHERE run_id=:r AND recommendation_id=:i",
        "UPDATE recommendations SET assurance_verdict='REJECT' WHERE run_id=:r AND recommendation_id=:i",
    ):
        if "assurance_verdict='REJECT'" in stmt:
            # flipping the verdict is allowed (Agent 7 owns it) but then acceptance must fail
            with tenant_connection(sl.app_engine, "tenant-a") as c:
                c.execute(text(stmt), {"i": rid, "r": run_id})
            with pytest.raises(DBAPIError), tenant_connection(sl.app_engine, "tenant-a") as c:
                c.execute(text(
                    "UPDATE recommendations SET status='APPROVED_FOR_PLANNING', decided_by='x', "
                    "decision_reason='y' WHERE run_id=:r AND recommendation_id=:i"), {"i": rid, "r": run_id})  # fmt: skip
        else:
            with pytest.raises(DBAPIError), tenant_connection(sl.app_engine, "tenant-a") as c:
                c.execute(text(stmt), {"i": rid, "r": run_id})


def test_cannot_accept_a_recommendation_that_failed_assurance(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    for _ in range(80):
        if sl.status(run_id)["state"] == "ASSURANCE":
            break
        assert sl.worker.step()
    (f,) = [p for p in sl.evidence_dir.rglob("*") if p.is_file()]
    f.write_text(
        f.read_text().replace('"ssh.permit_root_login":"yes"', '"ssh.permit_root_login":"no"')
    )
    sl.drain()
    assert sl.call("GET", f"/api/v1/assessments/{run_id}/recommendations", "carol").json() == []
    auditor = sl.call("GET", f"/api/v1/assessments/{run_id}/recommendations", "erin").json()
    assert auditor and all(
        r["assurance_verdict"] == "REJECT" and not r["authoritative"] for r in auditor
    )
    rid = auditor[0]["recommendation_id"]
    assert decide(sl, run_id, rid, "ACCEPT").status_code == 404  # approver cannot even see it


def test_ticket_drafts_are_disabled_by_default(sl: Slice) -> None:
    run_id, recs = finished_run(sl)
    rid = recs[0]["recommendation_id"]
    decide(sl, run_id, rid, "ACCEPT")
    r = sl.call(
        "POST", "/api/v1/tickets/drafts", "bob", json={"run_id": run_id, "recommendation_id": rid}
    )
    assert r.status_code == 403 and "disabled" in r.json()["detail"]
    assert sl.sql("SELECT count(*) FROM ticket_outbox")[0][0] == 0


def test_ticket_draft_requires_acceptance_is_idempotent_and_never_delivered(sl: Slice) -> None:
    enable_tickets(sl)
    run_id, recs = finished_run(sl)
    rid, other = recs[0]["recommendation_id"], recs[1]["recommendation_id"]
    body = {"run_id": run_id, "recommendation_id": rid}
    assert (
        sl.call("POST", "/api/v1/tickets/drafts", "bob", json=body).status_code == 409
    )  # not accepted yet
    decide(sl, run_id, rid, "ACCEPT", "approved")
    assert sl.call("POST", "/api/v1/tickets/drafts", "carol", json=body).status_code == 403
    first = sl.call("POST", "/api/v1/tickets/drafts", "bob", json=body)
    assert first.status_code == 201
    j = first.json()
    assert (
        j["status"] == "DRAFT"
        and j["delivered"] is False
        and j["payload"]["delivery"] == "NOT_SENT"
    )
    assert "Effort: unknown" in j["payload"]["description"]
    second = sl.call("POST", "/api/v1/tickets/drafts", "bob", json=body)
    assert second.status_code == 200 and second.json()["outbox_id"] == j["outbox_id"]
    assert sl.sql("SELECT count(*) FROM ticket_outbox")[0][0] == 1
    assert sl.call("POST", "/api/v1/tickets/drafts", "bob",
                   json={"run_id": run_id, "recommendation_id": other}).status_code == 409  # fmt: skip
    listed = sl.call("GET", f"/api/v1/tickets/drafts?run_id={run_id}", "carol").json()
    assert len(listed) == 1 and listed[0]["delivered"] is False
    # the outbox can only ever hold drafts: delivery is not representable
    with pytest.raises(DBAPIError), tenant_connection(sl.app_engine, "tenant-a") as c:
        c.execute(text("UPDATE ticket_outbox SET status='SENT'"))


def test_agent_registry_maps_every_adapter_and_reports_ai_state(sl: Slice) -> None:
    ids = {a.agent_id for a in AGENTS}
    assert ids == set(range(9))
    for adapter in sl.container.registry.ids():
        assert agent_for_adapter(adapter) is not None, (
            f"adapter {adapter} is outside the agent model"
        )
    assert len({x for a in AGENTS for x in a.adapter_ids}) == sum(
        len(a.adapter_ids) for a in AGENTS
    )
    j = sl.call("GET", "/api/v1/agents", "carol").json()
    assert len(j["agents"]) == 9 and j["ai"]["enabled"] is False
    assert j["ai"]["tools_available_to_model"] is False and j["ai"]["may_decide"] is False
    assert j["ai"]["model_id"] is None and j["ticket_drafts_enabled"] is False
    assert j["ai"]["provider"] is None and j["ai"]["endpoint_local_only"] is True
    assert not any(a["ai_active"] for a in j["agents"])
    sl.enable_ai(ScriptedModel(grounded))
    on = sl.call("GET", "/api/v1/agents", "carol").json()
    assert {a["agent_id"] for a in on["agents"] if a["ai_active"]} == {4, 5, 6, 8}
    assert on["ai"]["model_id"] == "stub-model-0" and on["ai"]["model_license"] == "Apache-2.0"
    assert on["ai"]["provider"] == "ollama" and on["ai"]["endpoint_local_only"] is True


def test_finding_detail_carries_risk_without_inventing_business_risk(sl: Slice) -> None:
    run_id, _ = finished_run(sl)
    items = sl.call("GET", f"/api/v1/findings?run_id={run_id}", "carol").json()["items"]
    fid = next(i["finding_id"] for i in items if i["severity"] == "HIGH")
    d = sl.call("GET", f"/api/v1/assessments/{run_id}/findings/{fid}", "carol").json()
    rx = d["risk_explanation"]
    assert rx["business_risk"] is None and rx["risk"]["basis"] == "NEEDS_POLICY_REVIEW"
    assert rx["risk"]["provisional_tier"] == "P2" and rx["risk"]["assurance_verdict"] == "ACCEPT"
    assert rx["ai_narrative"] is None and len(rx["scenarios"]) == 1


def test_acceptance_needs_an_assurance_accepted_recommendation_of_a_finished_run(sl: Slice) -> None:
    from tests.integration.test_analysis_pipeline import run_to

    _, _, early = sl.full_run(EXPECTED)
    run_to(sl, early, "ASSURANCE")  # recommendations exist but nothing has been assured yet
    (rid,) = [
        r[0]
        for r in sl.sql(
            "SELECT recommendation_id FROM recommendations WHERE run_id=:r AND "
            "body->>'catalog_ref' LIKE 'AC-HOST%'", r=early,
        )
    ]  # fmt: skip
    r = decide(sl, early, rid, "ACCEPT")
    assert r.status_code == 409 and "assurance-accepted" in r.json()["detail"]
    sl.drain()  # now finished and ACCEPTed: the same call succeeds
    assert decide(sl, early, rid, "ACCEPT").status_code == 200

    run_id, recs = finished_run(sl)
    rid = recs[0]["recommendation_id"]
    with tenant_connection(sl.app_engine, "tenant-a") as c:  # a pending (not rejected) verdict
        c.execute(
            text(
                "UPDATE recommendations SET assurance_verdict='NEEDS_REVIEW' WHERE run_id=:r AND recommendation_id=:i"
            ),
            {"r": run_id, "i": rid},
        )
    assert decide(sl, run_id, rid, "ACCEPT").status_code == 409
    assert (
        decide(sl, run_id, rid, "DEFER", "waiting").status_code == 200
    )  # non-acceptance is still allowed
