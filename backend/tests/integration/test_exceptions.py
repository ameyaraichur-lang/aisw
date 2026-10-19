"""Finding review actions and exceptions with expiry, through the real API and worker (ADR-033)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
import sqlalchemy
from sqlalchemy import text

from aisw.core.db import tenant_connection
from tests.slice import Slice

HOSTS = ["host-1", "host-2", "host-3"]
ROOT_LOGIN = "Direct root login over SSH is disabled"


def findings(sl: Slice, run_id: str) -> dict[str, dict[str, Any]]:
    items = sl.call("GET", f"/api/v1/assessments/{run_id}/findings", "alice").json()["items"]
    return {f["title"]: f for f in items}


def review(sl: Slice, run_id: str, fid: str, action: str, *, user: str = "rita",
           reason: str = "Verified on the host", **extra: Any) -> Any:  # fmt: skip
    return sl.call("POST", f"/api/v1/assessments/{run_id}/findings/{fid}/review", user,
                   json={"action": action, "reason": reason, **extra})  # fmt: skip


def detail(sl: Slice, run_id: str, fid: str, user: str = "rita") -> dict[str, Any]:
    r = sl.call("GET", f"/api/v1/assessments/{run_id}/findings/{fid}", user)
    assert r.status_code == 200, r.text
    return dict(r.json())


def expiry(sl: Slice, days: int) -> str:
    return (sl.clock.now + timedelta(days=days)).isoformat()


def decide(sl: Slice, exc_id: str, decision: str, *, user: str = "bob",
           reason: str = "Compensating control: bastion only") -> Any:  # fmt: skip
    return sl.call("POST", f"/api/v1/exceptions/{exc_id}/decision", user,
                   json={"decision": decision, "reason": reason})  # fmt: skip


def rerun(sl: Slice, pid: str) -> str:
    m = sl.approved_manifest(pid)
    r = sl.launch(pid, m)
    assert r.status_code == 202, r.text
    sl.drain()
    return str(r.json()["run_id"])


def controls(sl: Slice, run_id: str) -> dict[str, str]:
    rows = sl.sql("SELECT control_id, outcome FROM control_assessments WHERE run_id=:r", r=run_id)
    return {c: o for c, o in rows}


def test_review_actions_move_the_lifecycle_and_nothing_else(sl: Slice) -> None:
    _, _, run_id = sl.full_run(HOSTS)
    sl.drain()
    f = findings(sl, run_id)[ROOT_LOGIN]
    fid = f["finding_id"]
    assert detail(sl, run_id, fid)["review_actions"] == ["CONFIRM", "REJECT", "REQUEST_EXCEPTION"]
    assert detail(sl, run_id, fid, "carol")["review_actions"] == []  # cannot triage
    for user in ("carol", "bob", "erin"):
        assert review(sl, run_id, fid, "CONFIRM", user=user).status_code == 403
    assert review(sl, run_id, fid, "CONFIRM", expires_at=expiry(sl, 5)).status_code == 422
    assert review(sl, run_id, fid, "REOPEN").status_code == 409  # not a false positive
    r = review(sl, run_id, fid, "CONFIRM")
    assert r.status_code == 200 and r.json()["lifecycle"] == "TRIAGED"
    again = review(sl, run_id, fid, "CONFIRM")
    assert again.json()["replayed"] is True and again.headers["Idempotent-Replay"] == "true"
    assert review(sl, run_id, fid, "CONFIRM", reason="different").status_code == 409
    assert (
        review(sl, run_id, fid, "REJECT", reason="Root login is blocked by PAM").status_code == 200
    )
    assert (
        review(sl, run_id, fid, "REOPEN", user="sam", reason="PAM rule was removed").status_code
        == 200
    )
    d = detail(sl, run_id, fid)
    assert d["lifecycle"] == "REOPENED"
    assert [(h["action"], h["from"], h["to"], h["actor"]) for h in d["review_history"]] == [
        ("CONFIRM", "NEW", "TRIAGED", "rita"), ("REJECT", "TRIAGED", "FALSE_POSITIVE", "rita"),
        ("REOPEN", "FALSE_POSITIVE", "REOPENED", "sam")]  # fmt: skip
    # outcome, severity and assurance are untouched
    after = findings(sl, run_id)[ROOT_LOGIN]
    assert (after["outcome"], after["severity"], after["assurance_verdict"]) == (
        f["outcome"], f["severity"], f["assurance_verdict"])  # fmt: skip
    audit = [e["action"] for e in sl.call("GET", "/api/v1/audit/events?limit=20", "erin").json()["items"]
             if e["resource"] == f"finding:{run_id}/{fid}"]  # fmt: skip
    assert audit == ["finding.reopen", "finding.reject", "finding.confirm"]
    with (
        pytest.raises(sqlalchemy.exc.DBAPIError),
        tenant_connection(sl.app_engine, "tenant-a") as c,
    ):
        c.execute(text("UPDATE finding_reviews SET actor='x' WHERE run_id=:r"), {"r": run_id})


def test_exception_requests_are_validated(sl: Slice) -> None:
    _, _, run_id = sl.full_run(HOSTS)
    sl.drain()
    fid = findings(sl, run_id)[ROOT_LOGIN]["finding_id"]
    assert review(sl, run_id, fid, "REQUEST_EXCEPTION").status_code == 422  # no expiry
    for bad in (expiry(sl, 0), expiry(sl, -1), expiry(sl, 366)):
        assert review(sl, run_id, fid, "REQUEST_EXCEPTION", expires_at=bad).status_code == 422
    naive = (sl.clock.now + timedelta(days=5)).replace(tzinfo=None).isoformat()
    assert review(sl, run_id, fid, "REQUEST_EXCEPTION", expires_at=naive).status_code == 422
    assert (
        review(sl, run_id, fid, "REQUEST_EXCEPTION", expires_at=expiry(sl, 365)).status_code == 200
    )


def test_an_approved_exception_covers_later_runs_until_it_expires(sl_iso: Slice) -> None:
    sl = sl_iso
    pid, _, run1 = sl.full_run(HOSTS)
    sl.drain()
    fid = findings(sl, run1)[ROOT_LOGIN]["finding_id"]
    r = review(sl, run1, fid, "REQUEST_EXCEPTION", expires_at=expiry(sl, 30),
               reason="Legacy jump host; replacement in Q1")  # fmt: skip
    assert r.status_code == 200 and r.json()["lifecycle"] == "EXCEPTION_PENDING"
    exc_id = r.json()["exception_id"]
    listing = sl.call("GET", "/api/v1/exceptions?state=PENDING", "alice").json()
    assert [x["exception_id"] for x in listing["items"]] == [exc_id] and listing[
        "can_decide"
    ] is False
    assert sl.call("GET", "/api/v1/exceptions", "bob").json()["can_decide"] is True
    # a pending request covers nothing yet
    pending_run = rerun(sl, pid)
    assert controls(sl, pending_run)["FB-1"] == "FAIL"
    second = findings(sl, pending_run)[ROOT_LOGIN]["finding_id"]
    dup = review(sl, pending_run, second, "REQUEST_EXCEPTION", expires_at=expiry(sl, 10))
    assert dup.status_code == 409 and exc_id in dup.text  # one open exception per rule and asset

    for user in ("rita", "alice", "carol"):  # only an approver decides
        assert decide(sl, exc_id, "APPROVE", user=user).status_code == 403
    ok = decide(sl, exc_id, "APPROVE")
    assert ok.status_code == 200 and (ok.json()["state"], ok.json()["days_left"]) == ("ACTIVE", 30)
    assert decide(sl, exc_id, "APPROVE").json()["replayed"] is True
    assert decide(sl, exc_id, "REJECT").status_code == 409
    d = detail(sl, run1, fid)
    assert d["lifecycle"] == "ACCEPTED" and d["exception"]["state"] == "ACTIVE"
    assert d["review_history"][-1]["action"] == "EXCEPTION_APPROVED"
    ov = sl.call("GET", "/api/v1/overview", "alice").json()
    assert ov["exceptions"] == {"pending": 0, "active": 1, "expiring_30d": 1, "expired": 0}

    covered = rerun(sl, pid)
    assert controls(sl, covered) == {"FB-1": "EXCEPTION", "FB-2": "FAIL", "FB-3": "PASS"}
    assert set(findings(sl, covered)) == {"Minimum password length is at least 12"}
    raw = sl.sql("SELECT outcome FROM observations WHERE run_id=:r AND rule_id='ssh.permit_root_login' "
                 "AND asset_id='host-2'", r=covered)  # fmt: skip
    assert raw == [("FAIL",)]  # the evidence is kept as observed; only the control reads EXCEPTION
    rep = sl.report(covered)
    assert [(x["exception_id"], x["effect"], x["approved_by"]) for x in rep["exceptions"]] == [
        (exc_id, "APPLIED", "bob")]  # fmt: skip
    assert any("covered by an approved, unexpired exception" in x for x in rep["limitations"])
    assert rep["finding_counts"]["total"] == 1

    sl.clock.advance(days=31)
    lapsed = rerun(sl, pid)
    assert controls(sl, lapsed)["FB-1"] == "FAIL"
    back = findings(sl, lapsed)[ROOT_LOGIN]
    assert any(f"Exception {exc_id} expired" in a for a in back["assumptions"])
    rep = sl.report(lapsed)
    assert [x["effect"] for x in rep["exceptions"]] == ["EXPIRED"]
    assert any("had expired" in x for x in rep["limitations"])
    assert (
        sl.call("GET", "/api/v1/exceptions?state=EXPIRED", "alice").json()["items"][0][
            "exception_id"
        ]
        == exc_id
    )
    assert sl.call("GET", "/api/v1/overview", "alice").json()["exceptions"]["expired"] == 1
    revoke = sl.call("POST", f"/api/v1/exceptions/{exc_id}/revoke", "bob", json={"reason": "late"})
    assert revoke.status_code == 409  # nothing in force to revoke
    renew = review(sl, lapsed, back["finding_id"], "REQUEST_EXCEPTION", expires_at=expiry(sl, 30))
    assert renew.status_code == 200  # a lapsed exception does not block a new request


def test_rejected_and_revoked_exceptions(sl_iso: Slice) -> None:
    sl = sl_iso
    pid, _, run1 = sl.full_run(HOSTS)
    sl.drain()
    fid = findings(sl, run1)[ROOT_LOGIN]["finding_id"]
    first = review(sl, run1, fid, "REQUEST_EXCEPTION", expires_at=expiry(sl, 60)).json()[
        "exception_id"
    ]
    assert decide(sl, first, "REJECT", reason="No compensating control").status_code == 200
    assert detail(sl, run1, fid)["lifecycle"] == "TRIAGED"
    second = review(sl, run1, fid, "REQUEST_EXCEPTION", expires_at=expiry(sl, 60)).json()[
        "exception_id"
    ]
    assert decide(sl, second, "APPROVE").status_code == 200
    sl.clock.advance(days=1)
    rv = sl.call("POST", f"/api/v1/exceptions/{second}/revoke", "bob",
                 json={"reason": "Jump host replaced early"})  # fmt: skip
    assert rv.status_code == 200 and rv.json()["state"] == "REVOKED"
    assert detail(sl, run1, fid)["lifecycle"] == "REOPENED"
    after = rerun(sl, pid)
    assert controls(sl, after)["FB-1"] == "FAIL"  # revoked before this evidence: not applied
    assert sl.sql("SELECT count(*) FROM exception_applications WHERE run_id=:r", r=after) == [(0,)]
    hist = [h["action"] for h in detail(sl, run1, fid)["review_history"]]
    assert hist == ["REQUEST_EXCEPTION", "EXCEPTION_REJECTED", "REQUEST_EXCEPTION",
                    "EXCEPTION_APPROVED", "EXCEPTION_REVOKED"]  # fmt: skip


def test_the_database_enforces_separation_of_duties_and_transitions(sl_iso: Slice) -> None:
    sl = sl_iso
    _, _, run1 = sl.full_run(HOSTS)
    sl.drain()
    fid = findings(sl, run1)[ROOT_LOGIN]["finding_id"]
    exc_id = review(sl, run1, fid, "REQUEST_EXCEPTION", expires_at=expiry(sl, 5)).json()[
        "exception_id"
    ]

    def sql(stmt: str) -> None:
        with tenant_connection(sl.app_engine, "tenant-a") as c:
            c.execute(text(stmt), {"i": exc_id})

    with pytest.raises(sqlalchemy.exc.DBAPIError):  # the requester approving their own request
        sql("UPDATE finding_exceptions SET status='APPROVED', decided_by='rita', decided_at=now(), "
            "decision_reason='self' WHERE exception_id=:i")  # fmt: skip
    with pytest.raises(sqlalchemy.exc.DBAPIError):
        sql("DELETE FROM finding_exceptions WHERE exception_id=:i")
    with pytest.raises(sqlalchemy.exc.DBAPIError):  # immutable request columns
        sql(
            "UPDATE finding_exceptions SET expires_at = expires_at + interval '1 year' WHERE exception_id=:i"
        )
    assert decide(sl, exc_id, "APPROVE").status_code == 200
    with pytest.raises(sqlalchemy.exc.DBAPIError):
        sql(
            "UPDATE finding_exceptions SET status='REQUESTED', decided_by=NULL WHERE exception_id=:i"
        )
    with pytest.raises(sqlalchemy.exc.DBAPIError):
        sql("UPDATE finding_exceptions SET decision_reason='rewritten' WHERE exception_id=:i")
    with tenant_connection(sl.app_engine, "tenant-b") as c:
        assert c.execute(text("SELECT count(*) FROM finding_exceptions")).scalar() == 0
    assert sl.call("GET", "/api/v1/exceptions", "dave").status_code == 403
    # an approval that arrives after the requested expiry is refused
    sl.clock.advance(days=6)
    fid2 = findings(sl, run1)["Minimum password length is at least 12"]["finding_id"]
    late = review(sl, run1, fid2, "REQUEST_EXCEPTION", expires_at=expiry(sl, 1)).json()[
        "exception_id"
    ]
    sl.clock.advance(days=2)
    assert decide(sl, late, "APPROVE").status_code == 409
