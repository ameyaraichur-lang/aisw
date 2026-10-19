"""Control Matrix and policy-owner review of framework mappings (ADR-032)."""

from __future__ import annotations

from typing import Any

import pytest
import sqlalchemy
from sqlalchemy import text

from aisw.core.db import tenant_connection
from tests.slice import Slice

HOSTS = ["host-1", "host-2", "host-3"]
KEY = "FB-1|NIST-SP-800-53|AC-6(2)"


def review(sl: Slice, decision: str, *, user: str = "paula", key: str = KEY,
           reason: str = "Checked against the control text") -> Any:  # fmt: skip
    return sl.call("POST", "/api/v1/framework-mappings/reviews", user,
                   json={"key": key, "decision": decision, "reason": reason})  # fmt: skip


def matrix(sl: Slice, user: str = "carol", **params: str) -> dict[str, Any]:
    r = sl.call("GET", "/api/v1/control-matrix", user, params=params)
    assert r.status_code == 200, r.text
    return dict(r.json())


def mapping(m: dict[str, Any], key: str = KEY) -> dict[str, Any]:
    return next(x for row in m["controls"] for x in row["mappings"] if x["key"] == key)


def test_matrix_joins_run_outcomes_with_proposed_mappings(sl_iso: Slice) -> None:
    _, _, run_id = sl_iso.full_run(HOSTS)
    sl_iso.drain()
    m = matrix(sl_iso, run_id=run_id)
    assert (m["policy_version"], m["final"], m["can_review"]) == (
        "fixture-baseline:1.0.0",
        True,
        False,
    )
    assert {r["control_id"]: r["outcome"] for r in m["controls"]} == {
        "FB-1": "FAIL", "FB-2": "FAIL", "FB-3": "PASS"}  # fmt: skip
    assert {f["framework"] for f in m["frameworks"]} == {
        "NIST-CSF", "CIS-Controls", "NIST-SP-800-53", "ISO-IEC-27001", "MITRE-ATTACK"}  # fmt: skip
    fb1 = next(r for r in m["controls"] if r["control_id"] == "FB-1")
    assert fb1["rules"] == [{"rule_id": "ssh.permit_root_login",
                             "title": "Direct root login over SSH is disabled", "severity": "HIGH"}]  # fmt: skip
    assert {x["framework"] for x in fb1["mappings"]} == {f["framework"] for f in m["frameworks"]}
    # nothing is approved out of the box
    assert m["summary"]["APPROVED"] == m["summary"]["REJECTED"] == 0 < m["summary"]["NEEDS_REVIEW"]
    assert mapping(m)["title"] and mapping(m)["status"] == "NEEDS_REVIEW"
    # a pack can be browsed without a run; outcomes are then absent, not guessed
    p = matrix(sl_iso, policy_version="config-baseline:1.0.0")
    assert len(p["controls"]) == 20 and all(r["outcome"] is None for r in p["controls"])
    assert matrix(sl_iso, "paula", policy_version="config-baseline:1.0.0")["can_review"] is True


def test_policy_owner_reviews_are_audited_append_only_and_shown_everywhere(sl_iso: Slice) -> None:
    sl = sl_iso
    _, _, run_id = sl.full_run(HOSTS)
    sl.drain()
    for user in ("alice", "bob", "rita", "carol", "erin"):  # only the policy owner decides
        assert review(sl, "APPROVED", user=user).status_code == 403
    assert review(sl, "NEEDS_REVIEW").status_code == 409  # already pending: nothing to reset
    r = review(sl, "APPROVED")
    assert r.status_code == 200 and r.json()["status"] == "APPROVED"
    again = review(sl, "APPROVED")
    assert again.json()["replayed"] is True and again.headers["Idempotent-Replay"] == "true"
    m = mapping(matrix(sl, run_id=run_id))
    assert (m["status"], m["reviewed_by"], m["reason"]) == (
        "APPROVED", "paula", "Checked against the control text")  # fmt: skip
    # the finding detail shows the same reviewed state for its control
    fid = next(f["finding_id"] for f in sl.call(
        "GET", f"/api/v1/assessments/{run_id}/findings", "alice").json()["items"]
        if f["title"].startswith("Direct root login"))  # fmt: skip
    d = sl.call("GET", f"/api/v1/assessments/{run_id}/findings/{fid}", "carol").json()
    assert {x["key"]: x["status"] for x in d["framework_mappings"]}[KEY] == "APPROVED"
    # approving a mapping never changes an outcome
    assert {r["control_id"]: r["outcome"] for r in matrix(sl, run_id=run_id)["controls"]}[
        "FB-1"
    ] == "FAIL"
    # a change of mind is a new row; the latest one wins
    assert review(sl, "REJECTED", reason="Maps to AC-6(5) instead").status_code == 200
    assert mapping(matrix(sl, run_id=run_id))["status"] == "REJECTED"
    assert review(sl, "NEEDS_REVIEW", reason="Reopened for the 2027 catalog").status_code == 200
    assert mapping(matrix(sl, run_id=run_id))["status"] == "NEEDS_REVIEW"
    rows = sl.sql(
        "SELECT decision FROM framework_mapping_reviews WHERE mapping_key=:k ORDER BY seq", k=KEY
    )
    assert [x[0] for x in rows] == ["APPROVED", "REJECTED", "NEEDS_REVIEW"]
    actions = [e for e in sl.call("GET", "/api/v1/audit/events?limit=50", "erin").json()["items"]
               if e["resource"] == f"framework_mapping:{KEY}"]  # fmt: skip
    assert len(actions) == 3 and {e["actor"] for e in actions} == {"paula"}
    with (
        pytest.raises(sqlalchemy.exc.DBAPIError),
        tenant_connection(sl.app_engine, "tenant-a") as c,
    ):
        c.execute(text("UPDATE framework_mapping_reviews SET decision='APPROVED'"))
    with (
        pytest.raises(sqlalchemy.exc.DBAPIError),
        tenant_connection(sl.app_engine, "tenant-a") as c,
    ):
        c.execute(text("DELETE FROM framework_mapping_reviews"))
    with tenant_connection(sl.app_engine, "tenant-b") as c:
        assert c.execute(text("SELECT count(*) FROM framework_mapping_reviews")).scalar() == 0


def test_review_input_is_validated_and_redacted(sl_iso: Slice) -> None:
    sl = sl_iso
    assert review(sl, "APPROVED", key="FB-1|NIST-SP-800-53|AC-99").status_code == 404
    assert review(sl, "MAYBE").status_code == 422
    assert review(sl, "APPROVED", reason="").status_code == 422
    secret = "password=hunter2-" + "x" * 2000  # aisw:allow-secret
    assert review(sl, "APPROVED", reason=secret).status_code == 200
    ((reason,),) = sl.sql("SELECT reason FROM framework_mapping_reviews")
    assert "hunter2" not in reason and len(reason) <= 1000


def test_matrix_requires_a_run_or_pack_and_hides_other_tenants(sl: Slice) -> None:
    assert sl.call("GET", "/api/v1/control-matrix", "carol").status_code == 422
    assert (
        sl.call("GET", "/api/v1/control-matrix?policy_version=nope:1", "carol").status_code == 404
    )
    _, _, run_id = sl.full_run(HOSTS)
    assert sl.call("GET", f"/api/v1/control-matrix?run_id={run_id}", "dave").status_code == 404
    m = matrix(sl, run_id=run_id)  # not finished yet: outcomes absent, not final
    assert m["final"] is False and all(r["outcome"] is None for r in m["controls"])
