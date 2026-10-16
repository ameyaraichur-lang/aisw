"""Per-project roles: a grant adds a work role on ONE project; nothing leaks to other projects or
tenant-wide lists; only a tenant-wide project admin grants; nobody grants to themselves; a grant is
revoked once and never edited."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from aisw.core.db import tenant_connection
from tests.slice import Slice

pytestmark = pytest.mark.security
EXPECTED = ["host-1", "host-2", "host-3"]


def grant(sl: Slice, pid: str, who: str, role: str, by: str = "alice") -> Any:
    return sl.call("POST", f"/api/v1/projects/{pid}/roles", by,
                   json={"actor_id": who, "role": role, "reason": "contract 12"})  # fmt: skip


def granted(sl: Slice, pid: str, who: str, role: str) -> str:
    r = grant(sl, pid, who, role)
    assert r.status_code == 201, r.text
    return str(r.json()["grant_id"])


def run_in(sl: Slice, pid: str) -> str:
    sl.inventory(pid, EXPECTED)
    m = sl.approved_manifest(pid)
    r = sl.launch(pid, m)
    assert r.status_code == 202, r.text
    sl.drain()
    return str(r.json()["run_id"])


def test_without_a_grant_a_project_only_user_sees_nothing(sl: Slice) -> None:
    pid = sl.project()
    run_id = run_in(sl, pid)
    assert sl.call("GET", "/api/v1/projects", "pete").status_code == 403
    assert sl.call("GET", f"/api/v1/assessments/{run_id}", "pete").status_code == 403
    me = sl.call("GET", "/api/v1/me", "pete").json()
    assert me["permissions"] == [] and me["project_permissions"] == {}


def test_a_read_grant_opens_one_project_and_nothing_else(sl: Slice) -> None:
    p1, p2 = sl.project(), sl.project()
    r1, r2 = run_in(sl, p1), run_in(sl, p2)
    granted(sl, p1, "pete", "report_reader")
    projects = sl.call("GET", "/api/v1/projects", "pete").json()
    assert [p["project_id"] for p in projects] == [p1]
    me = sl.call("GET", "/api/v1/me", "pete").json()
    assert me["project_roles"] == {p1: ["report_reader"]}
    assert "finding:read" in me["project_permissions"][p1] and me["permissions"] == []
    for path in ("", "/findings", "/reports", "/coverage", "/events"):
        assert sl.call("GET", f"/api/v1/assessments/{r1}{path}", "pete").status_code == 200, path
        assert sl.call("GET", f"/api/v1/assessments/{r2}{path}", "pete").status_code == 403, path
    assert (
        sl.call("GET", "/api/v1/assessments", "pete", params={"project_id": p1}).status_code == 200
    )
    assert (
        sl.call("GET", "/api/v1/assessments", "pete", params={"project_id": p2}).status_code == 403
    )
    assert sl.call("GET", "/api/v1/assessments", "pete").status_code == 403  # tenant-wide list
    assert sl.call("GET", "/api/v1/findings", "pete").status_code == 403
    (rep,) = sl.call("GET", f"/api/v1/assessments/{r1}/reports", "pete").json()
    approve = sl.call("POST", f"/api/v1/reports/{rep['report_id']}/approve", "pete",
                      json={"report_hash": rep["report_hash"]})  # fmt: skip
    assert approve.status_code == 403  # reading is not approving


def test_an_operator_grant_drafts_and_launches_only_on_its_project(sl: Slice) -> None:
    p1, p2 = sl.project(), sl.project()
    for pid in (p1, p2):
        sl.inventory(pid, EXPECTED)
    granted(sl, p1, "pete", "assessment_operator")
    own = sl.call("POST", "/api/v1/scope-manifests", "pete", json=sl.manifest_payload(p1))
    assert own.status_code == 201, own.text
    other = sl.call("POST", "/api/v1/scope-manifests", "pete", json=sl.manifest_payload(p2))
    assert other.status_code == 403
    mid = own.json()["manifest"]["manifest_id"]
    assert sl.call("POST", f"/api/v1/scope-manifests/{mid}/preflight", "pete").status_code == 200
    ap = sl.call("POST", f"/api/v1/scope-manifests/{mid}/approve", "bob",
                 json={"acknowledge_active_adapters": []})  # fmt: skip
    assert ap.status_code == 200, ap.text
    m = ap.json()
    assert sl.launch(p1, m, user="pete").status_code == 202
    m2 = sl.approved_manifest(p2)
    assert sl.launch(p2, m2, user="pete").status_code == 403
    up = {"kind": "cmdb_csv", "filename": "c.csv", "content": "asset_id,hostname\nh,h\n"}
    assert (
        sl.call("POST", "/api/v1/imports", "pete", json={"project_id": p1, **up}).status_code == 201
    )
    assert (
        sl.call("POST", "/api/v1/imports", "pete", json={"project_id": p2, **up}).status_code == 403
    )


def test_an_approver_grant_keeps_separation_of_duties(sl: Slice) -> None:
    p1, p2 = sl.project(), sl.project()
    for pid in (p1, p2):
        sl.inventory(pid, EXPECTED)
    granted(sl, p1, "pete", "approver")
    granted(sl, p1, "pete", "assessment_operator")
    mine = sl.call("POST", "/api/v1/scope-manifests", "pete", json=sl.manifest_payload(p1)).json()
    mid = mine["manifest"]["manifest_id"]
    sl.call("POST", f"/api/v1/scope-manifests/{mid}/preflight", "pete")
    own = sl.call("POST", f"/api/v1/scope-manifests/{mid}/approve", "pete",
                  json={"acknowledge_active_adapters": []})  # fmt: skip
    assert own.status_code == 403  # the requester never approves their own manifest

    def drafted(pid: str) -> str:
        r = sl.call("POST", "/api/v1/scope-manifests", "alice", json=sl.manifest_payload(pid))
        m_id = str(r.json()["manifest"]["manifest_id"])
        assert (
            sl.call("POST", f"/api/v1/scope-manifests/{m_id}/preflight", "alice").status_code == 200
        )
        return m_id

    ok = sl.call("POST", f"/api/v1/scope-manifests/{drafted(p1)}/approve", "pete",
                 json={"acknowledge_active_adapters": []})  # fmt: skip
    assert ok.status_code == 200, ok.text
    no = sl.call("POST", f"/api/v1/scope-manifests/{drafted(p2)}/approve", "pete",
                 json={"acknowledge_active_adapters": []})  # fmt: skip
    assert no.status_code == 403


def test_revoking_a_grant_takes_effect_on_the_next_request(sl: Slice) -> None:
    pid = sl.project()
    run_id = run_in(sl, pid)
    gid = granted(sl, pid, "pete", "report_reader")
    assert sl.call("GET", f"/api/v1/assessments/{run_id}", "pete").status_code == 200
    r = sl.call("POST", f"/api/v1/projects/{pid}/roles/{gid}/revoke", "alice")
    assert r.status_code == 200, r.text
    assert sl.call("GET", f"/api/v1/assessments/{run_id}", "pete").status_code == 403
    again = sl.call("POST", f"/api/v1/projects/{pid}/roles/{gid}/revoke", "alice")
    assert again.status_code == 404
    assert sl.call("GET", f"/api/v1/projects/{pid}/roles", "alice").json() == []


def test_who_may_grant_what(sl: Slice) -> None:
    pid = sl.project()
    assert grant(sl, pid, "pete", "approver", by="bob").status_code == 403
    assert grant(sl, pid, "alice", "approver", by="alice").status_code == 403  # not to yourself
    assert grant(sl, pid, "pete", "auditor").status_code == 422  # tenant-wide duty
    assert grant(sl, pid, "pete", "project_admin").status_code == 422
    assert grant(sl, pid, "pete", "approver").status_code == 201
    assert grant(sl, pid, "pete", "approver").status_code == 409
    assert grant(sl, pid, "bad id!", "approver").status_code == 422
    assert grant(sl, pid, "pete", "approver", by="dave").status_code == 404  # other tenant
    assert sl.call("GET", f"/api/v1/projects/{pid}/roles", "dave").status_code == 404
    rows = sl.call("GET", f"/api/v1/projects/{pid}/roles", "carol").json()
    assert [(g["actor_id"], g["role"], g["granted_by"]) for g in rows] == [
        ("pete", "approver", "alice")
    ]
    assert sl.sql(
        "SELECT action, result FROM audit_events WHERE action LIKE 'project.role.%' "
        "AND resource=:r ORDER BY seq", r=f"project:{pid}",
    ) == [("project.role.grant", "SUCCESS")]  # fmt: skip


def test_the_database_refuses_edits_deletes_and_self_grants(sl: Slice) -> None:
    pid = sl.project()
    gid = granted(sl, pid, "pete", "reviewer")
    with tenant_connection(sl.app_engine, "tenant-a") as conn:
        for stmt in (
            "UPDATE project_role_grants SET role='approver' WHERE grant_id::text=:g",
            "DELETE FROM project_role_grants WHERE grant_id::text=:g",
        ):
            with pytest.raises(DBAPIError), conn.begin_nested():
                conn.execute(text(stmt), {"g": gid})
        with pytest.raises(DBAPIError), conn.begin_nested():
            conn.execute(
                text("INSERT INTO project_role_grants (tenant_id, project_id, actor_id, role, "
                     "reason, granted_by, granted_at) VALUES ('tenant-a', CAST(:p AS uuid), "
                     "'pete', 'approver', 'x', 'pete', now())"), {"p": pid},
            )  # fmt: skip
    r = sl.call("POST", f"/api/v1/projects/{pid}/roles/{gid}/revoke", "alice")
    assert r.status_code == 200
    with tenant_connection(sl.app_engine, "tenant-a") as conn, pytest.raises(DBAPIError):
        conn.execute(
            text("UPDATE project_role_grants SET revoked_by='x', revoked_at=now() "
                 "WHERE grant_id::text=:g"), {"g": gid},
        )  # fmt: skip
