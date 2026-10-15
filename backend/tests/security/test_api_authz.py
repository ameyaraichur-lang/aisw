"""Authentication, RBAC, cross-tenant access and idempotent replay through the real API."""

from __future__ import annotations

import threading
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from aisw.api.app import create_app
from aisw.core.config import Settings
from aisw.core.db import tenant_connection
from aisw.core.idempotency import IdempotencyConflict, run_idempotent
from tests.conftest import auth

pytestmark = pytest.mark.security


def body(uid: str, name: str = "p") -> dict[str, str]:
    return {"name": f"{name}-{uid}", "environment": "test"}


def create(c: TestClient, user: str, b: dict[str, str], key: str | None = None):  # type: ignore[no-untyped-def]
    return c.post(
        "/api/v1/projects",
        json=b,
        headers={**auth(user), "Idempotency-Key": key or uuid.uuid4().hex},
    )


# ---- authentication -------------------------------------------------------------------------
def test_unauthenticated_and_bad_credentials_get_401(client: TestClient) -> None:
    assert client.get("/api/v1/projects").status_code == 401
    assert (
        client.get("/api/v1/projects", headers={"Authorization": "Bearer nope"}).status_code == 401
    )
    assert client.get("/api/v1/projects", headers={"Authorization": "Basic abc"}).status_code == 401


def test_identity_stub_refused_outside_dev_and_test(app_engine: Engine) -> None:
    prod = TestClient(create_app(Settings(env="prod"), engine=app_engine))
    assert prod.get("/api/v1/projects", headers=auth("alice")).status_code == 401
    # stub flag off even in dev: still refused (fail closed)
    dev_off = TestClient(create_app(Settings(env="dev"), engine=app_engine))
    assert dev_off.get("/api/v1/projects", headers=auth("alice")).status_code == 401


def test_tenant_cannot_be_chosen_by_the_caller(client: TestClient, uid: str) -> None:
    r = client.post(  # a body-supplied tenant is an unknown field: rejected, not honoured
        "/api/v1/projects",
        json={**body(uid), "tenant_id": "tenant-b"},
        headers={**auth("alice"), "Idempotency-Key": uuid.uuid4().hex},
    )
    assert r.status_code == 422
    r = client.get("/api/v1/projects", headers={**auth("alice"), "X-Tenant-Id": "tenant-b"})
    assert r.status_code == 200  # header ignored; alice only ever sees tenant-a


# ---- RBAC -----------------------------------------------------------------------------------
@pytest.mark.parametrize("user", ["bob", "carol", "erin"])
def test_create_requires_project_admin(client: TestClient, uid: str, user: str) -> None:
    r = create(client, user, body(uid))
    assert r.status_code == 403
    assert client.get("/api/v1/projects", headers=auth("alice")).json() == [] or all(
        p["name"] != f"p-{uid}"
        for p in client.get("/api/v1/projects", headers=auth("alice")).json()
    )


def test_denied_attempt_is_audited(client: TestClient, app_engine: Engine, uid: str) -> None:
    before = client.get("/api/v1/audit/verify", headers=auth("erin")).json()["checked"]
    assert create(client, "carol", body(uid)).status_code == 403
    with tenant_connection(app_engine, "tenant-a") as c:
        row = c.execute(
            text(
                "SELECT actor, action, result FROM audit_events WHERE tenant_id='tenant-a' "
                "ORDER BY seq DESC LIMIT 1"
            )
        ).one()
    assert tuple(row) == ("carol", "project.create", "DENIED")
    after = client.get("/api/v1/audit/verify", headers=auth("erin")).json()
    assert after["ok"] and after["checked"] == before + 1


def test_audit_verify_requires_auditor(client: TestClient) -> None:
    assert client.get("/api/v1/audit/verify", headers=auth("alice")).status_code == 403
    assert client.get("/api/v1/audit/verify", headers=auth("erin")).status_code == 200


def test_reader_can_read_but_not_write(client: TestClient, uid: str) -> None:
    assert create(client, "alice", body(uid)).status_code == 201
    r = client.get("/api/v1/projects", headers=auth("carol"))
    assert r.status_code == 200 and any(p["name"] == f"p-{uid}" for p in r.json())


# ---- cross-tenant ---------------------------------------------------------------------------
def test_cross_tenant_read_is_indistinguishable_from_missing(client: TestClient, uid: str) -> None:
    pid = create(client, "alice", body(uid)).json()["project_id"]
    assert client.get(f"/api/v1/projects/{pid}", headers=auth("alice")).status_code == 200
    r = client.get(f"/api/v1/projects/{pid}", headers=auth("dave"))
    missing = client.get(f"/api/v1/projects/{uuid.uuid4()}", headers=auth("dave"))
    assert r.status_code == missing.status_code == 404
    assert r.json() == missing.json()
    assert all(
        p["project_id"] != pid for p in client.get("/api/v1/projects", headers=auth("dave")).json()
    )


def test_same_project_name_allowed_in_different_tenants(client: TestClient, uid: str) -> None:
    assert create(client, "alice", body(uid, "shared")).status_code == 201
    assert create(client, "dave", body(uid, "shared")).status_code == 201
    assert create(client, "alice", body(uid, "shared")).status_code == 409


# ---- idempotency & replay -------------------------------------------------------------------
def test_replay_returns_original_without_duplicate_side_effects(
    client: TestClient, app_engine: Engine, uid: str
) -> None:
    key = uuid.uuid4().hex
    first = create(client, "alice", body(uid), key)
    again = create(client, "alice", body(uid), key)
    assert first.status_code == again.status_code == 201
    assert first.json() == again.json()
    assert "idempotent-replay" not in first.headers and again.headers["idempotent-replay"] == "true"
    with tenant_connection(app_engine, "tenant-a") as c:
        assert (
            c.execute(
                text("SELECT count(*) FROM projects WHERE name=:n"), {"n": f"p-{uid}"}
            ).scalar_one()
            == 1
        )
        created = c.execute(
            text(
                "SELECT count(*) FROM audit_events WHERE tenant_id='tenant-a' AND action='project.create' AND resource=:r AND result='SUCCESS'"
            ),
            {"r": f"project:{first.json()['project_id']}"},
        ).scalar_one()
    assert created == 1  # replay wrote no second audit event


def test_key_reuse_with_different_body_conflicts(client: TestClient, uid: str) -> None:
    key = uuid.uuid4().hex
    assert create(client, "alice", body(uid, "one"), key).status_code == 201
    r = create(client, "alice", body(uid, "two"), key)
    assert r.status_code == 409 and r.json()["error"] == "idempotency_conflict"


def test_missing_key_rejected_and_keys_are_scoped_per_actor_and_tenant(
    client: TestClient, uid: str
) -> None:
    r = client.post("/api/v1/projects", json=body(uid), headers=auth("alice"))
    assert r.status_code == 400
    key = uuid.uuid4().hex
    a = create(client, "alice", body(uid, "ka"), key)
    d = create(client, "dave", body(uid, "kd"), key)  # same key, other tenant: independent
    assert a.status_code == d.status_code == 201 and a.json() != d.json()


def test_failed_handler_does_not_burn_the_key(client: TestClient, uid: str) -> None:
    key = uuid.uuid4().hex
    assert create(client, "alice", body(uid, "dup")).status_code == 201
    assert create(client, "alice", body(uid, "dup"), key).status_code == 409  # name clash
    # The 409 rolled back its idempotency record: the key is free, so a different body with the
    # same key succeeds instead of reporting an idempotency conflict.
    assert create(client, "alice", body(uid, "fresh"), key).status_code == 201


def test_concurrent_identical_requests_create_exactly_one_project(
    app_engine: Engine, uid: str
) -> None:
    key, results, errors = uuid.uuid4().hex, [], []
    payload = {"name": f"race-{uid}"}

    def worker() -> None:
        try:
            with tenant_connection(app_engine, "tenant-a") as c:

                def handler() -> tuple[int, dict[str, object]]:
                    row = c.execute(
                        text(
                            "INSERT INTO projects (tenant_id, name, environment, created_by) "
                            "VALUES ('tenant-a', :n, 'test', 'alice') RETURNING project_id"
                        ),
                        {"n": payload["name"]},
                    ).scalar_one()
                    return 201, {"project_id": str(row)}

                results.append(
                    run_idempotent(
                        c,
                        tenant_id="tenant-a",
                        actor="alice",
                        scope="race",
                        key=key,
                        request_body=payload,
                        handler=handler,
                    )  # fmt: skip
                )
        except IdempotencyConflict as exc:  # pragma: no cover - timing dependent
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(results) == 6 and len({r.body["project_id"] for r in results}) == 1
    assert sum(not r.replayed for r in results) == 1
    with tenant_connection(app_engine, "tenant-a") as c:
        assert (
            c.execute(
                text("SELECT count(*) FROM projects WHERE name=:n"), {"n": payload["name"]}
            ).scalar_one()
            == 1
        )
