"""Ticket delivery through the API against a loopback fake ITSM (ADR-037)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from aisw.core.config import Settings
from aisw.core.db import tenant_connection
from tests.integration.test_analysis_api import decide, enable_tickets, finished_run
from tests.itsm_fake import FakeItsm
from tests.slice import Slice


@pytest.fixture
def fake() -> Iterator[FakeItsm]:
    f = FakeItsm().start()
    yield f
    f.stop()


def deliver_to(sl: Slice, fake: FakeItsm, target: str = "jira", **kw: Any) -> None:
    sl.container.settings = Settings(
        env="test", dev_auth_stub=True, enable_itsm_ticket_creation=True,
        enable_itsm_ticket_delivery=True, itsm_target=target, itsm_base_url=fake.url,
        itsm_username=fake.username, itsm_token=kw.pop("token", fake.token),
        itsm_jira_project_key="SEC", itsm_timeout_seconds=1, **kw,
    )  # fmt: skip


def drafted(sl: Slice, n: int = 1) -> tuple[str, list[str]]:
    enable_tickets(sl)
    run_id, recs = finished_run(sl)
    ids = []
    for rec in recs[:n]:
        decide(sl, run_id, rec["recommendation_id"], "ACCEPT", "approved")
        r = sl.call("POST", "/api/v1/tickets/drafts", "bob",
                    json={"run_id": run_id, "recommendation_id": rec["recommendation_id"]})  # fmt: skip
        assert r.status_code == 201
        ids.append(r.json()["outbox_id"])
    return run_id, ids


def row(sl: Slice, oid: str) -> tuple[Any, ...]:
    return tuple(
        sl.sql(
            "SELECT status, target, attempts, external_ref, last_error, sent_by FROM ticket_outbox "
            f"WHERE outbox_id='{oid}'"
        )[0]
    )


def test_a_second_approver_sends_once_and_a_timed_out_create_is_not_duplicated(
    sl: Slice, fake: FakeItsm
) -> None:
    run_id, [oid] = drafted(sl)
    send = f"/api/v1/tickets/drafts/{oid}/send"
    off = sl.call("POST", send, "vic")
    assert off.status_code == 403 and "disabled" in off.json()["detail"]
    deliver_to(sl, fake)
    assert sl.call("POST", send, "carol").status_code == 403  # cannot decide recommendations
    author = sl.call("POST", send, "bob")
    assert author.status_code == 403 and "other than its author" in author.json()["detail"]
    assert fake.requests == []

    fake.slow_creates = 1  # created on the ITSM side, reply arrives after our timeout
    late = sl.call("POST", send, "vic")
    assert late.status_code == 502
    assert late.json()["detail"] == {"code": "ITSM_UNREACHABLE", "retryable": True}
    assert row(sl, oid) == ("FAILED", "jira", 1, None, "ITSM_UNREACHABLE", None)
    assert len(fake.jira) == 1

    retry = sl.call("POST", send, "vic")
    assert retry.status_code == 200, retry.text  # found by correlation label, not re-created
    j = retry.json()
    assert j["created"] is False and j["external_ref"] == "SEC-1" and j["status"] == "SENT"
    assert j["external_url"] == f"{fake.url}/browse/SEC-1"
    assert len(fake.jira) == 1 and f"aisw-{oid}" in fake.jira[0]["fields"]["labels"]
    assert row(sl, oid) == ("SENT", "jira", 2, "SEC-1", None, "vic")

    seen = len(fake.requests)
    replay = sl.call("POST", send, "vic")
    assert replay.status_code == 200 and replay.headers["Idempotent-Replay"] == "true"
    assert len(fake.requests) == seen  # a sent ticket never reaches the ITSM again

    listed = sl.call("GET", f"/api/v1/tickets/drafts?run_id={run_id}", "carol").json()
    assert listed[0]["delivered"] is True and listed[0]["external_ref"] == "SEC-1"
    audit = sl.sql(
        "SELECT result FROM audit_events WHERE action='ticket.send' "
        f"AND resource='ticket:{oid}' ORDER BY seq"
    )
    assert [r[0] for r in audit] == ["FAILURE", "SUCCESS"]
    agents = sl.call("GET", "/api/v1/agents", "carol").json()
    assert agents["ticket_delivery"] == {"enabled": True, "target": "jira"}


def test_the_database_keeps_a_sent_ticket_final(sl: Slice, fake: FakeItsm) -> None:
    _, [oid] = drafted(sl)
    deliver_to(sl, fake)
    assert sl.call("POST", f"/api/v1/tickets/drafts/{oid}/send", "vic").status_code == 201
    for stmt in (
        "UPDATE ticket_outbox SET status='DRAFT'",
        "UPDATE ticket_outbox SET status='SENDING', attempts=attempts+1",
        "UPDATE ticket_outbox SET target='servicenow'",
        "UPDATE ticket_outbox SET payload='{}'::jsonb",
        "DELETE FROM ticket_outbox",
    ):
        with pytest.raises(DBAPIError), tenant_connection(sl.app_engine, "tenant-a") as c:
            c.execute(text(f"{stmt} WHERE outbox_id='{oid}'"))
    with pytest.raises(DBAPIError), tenant_connection(sl.app_engine, "tenant-a") as c:
        c.execute(text("INSERT INTO ticket_outbox (tenant_id, run_id, recommendation_id, project_id, "
                       "payload, created_by, created_at, sent_by) SELECT tenant_id, run_id, 'x', "
                       "project_id, payload, 'bob', created_at, 'bob' FROM ticket_outbox "
                       f"WHERE outbox_id='{oid}'"))  # fmt: skip


def test_servicenow_delivery_refusals_and_an_in_flight_claim(sl: Slice, fake: FakeItsm) -> None:
    _, [oid, other] = drafted(sl, 2)
    preview = sl.call("GET", f"/api/v1/tickets/drafts/{oid}/render?target=servicenow", "carol")
    assert preview.status_code == 200
    p = preview.json()
    assert p["payload"]["correlation_id"] == f"aisw-{oid}" and p["delivery_enabled"] is False
    assert sl.call("GET", "/api/v1/tickets/drafts/not-a-uuid/render", "carol").status_code == 404
    assert sl.call("GET", f"/api/v1/tickets/drafts/{oid}/render", "dave").status_code in {403, 404}

    deliver_to(sl, fake, "servicenow", token="wrong-token")  # noqa: S106 - deliberately wrong
    refused = sl.call("POST", f"/api/v1/tickets/drafts/{oid}/send", "vic")
    assert refused.status_code == 502
    assert refused.json()["detail"] == {"code": "ITSM_REFUSED_401", "retryable": False}

    deliver_to(sl, fake, "servicenow")
    ok = sl.call("POST", f"/api/v1/tickets/drafts/{oid}/send", "vic")
    assert ok.status_code == 201 and ok.json()["external_ref"] == "INC0000001"
    assert fake.servicenow[0]["correlation_id"] == f"aisw-{oid}"

    deliver_to(sl, fake, "jira")  # a draft never moves to a second ITSM
    moved = sl.call("POST", f"/api/v1/tickets/drafts/{oid}/send", "vic")
    assert moved.status_code == 200 and moved.json()["target"] == "servicenow"

    with tenant_connection(sl.app_engine, "tenant-a") as c:  # another request holds the claim
        c.execute(text("UPDATE ticket_outbox SET status='SENDING', target='jira', "
                       "attempts=attempts+1, attempted_at=:n WHERE outbox_id=:o"),
                  {"n": sl.clock(), "o": other})  # fmt: skip
    busy = sl.call("POST", f"/api/v1/tickets/drafts/{other}/send", "vic")
    assert busy.status_code == 409 and "in progress" in busy.json()["detail"]
    sl.clock.advance(minutes=2)  # the claim is stale: the holder died
    assert sl.call("POST", f"/api/v1/tickets/drafts/{other}/send", "vic").status_code == 201
    assert len(fake.jira) == 1
