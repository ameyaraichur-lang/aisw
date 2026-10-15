"""Row-level security is the backstop: app code forgetting a filter must not leak tenants."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from aisw.core.db import tenant_connection

pytestmark = pytest.mark.security


def _insert_project(engine: Engine, tenant: str, name: str) -> str:
    with tenant_connection(engine, tenant) as c:
        row = c.execute(
            text(
                "INSERT INTO projects (tenant_id, name, environment, created_by) "
                "VALUES (:t, :n, 'test', 'x') RETURNING project_id"
            ),
            {"t": tenant, "n": name},
        ).one()
        return str(row[0])


def test_app_role_is_unprivileged(app_engine: Engine) -> None:
    with app_engine.connect() as c:
        sup, bypass = c.execute(
            text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        ).one()
    assert (sup, bypass) == (False, False)


def test_rls_forced_on_all_tenant_tables(owner_engine: Engine) -> None:
    with owner_engine.connect() as c:
        rows = c.execute(
            text(
                "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname IN ('projects','scope_manifests','execution_permits',"
                "'idempotency_records','audit_events')"
            )
        ).all()
    assert len(rows) == 5
    assert all(r[1] and r[2] for r in rows)


def test_tenants_cannot_see_each_other(app_engine: Engine, uid: str) -> None:
    pa = _insert_project(app_engine, "tenant-a", f"a-{uid}")
    _insert_project(app_engine, "tenant-b", f"b-{uid}")
    with tenant_connection(app_engine, "tenant-a") as c:
        names = {r[0] for r in c.execute(text("SELECT name FROM projects"))}
    assert f"a-{uid}" in names and f"b-{uid}" not in names
    with tenant_connection(app_engine, "tenant-b") as c:
        assert (
            c.execute(text("SELECT 1 FROM projects WHERE project_id=:p"), {"p": pa}).first() is None
        )


def test_no_tenant_context_yields_no_rows(app_engine: Engine, uid: str) -> None:
    _insert_project(app_engine, "tenant-a", f"n-{uid}")
    with app_engine.connect() as c:  # no set_config: fail closed
        assert c.execute(text("SELECT count(*) FROM projects")).scalar_one() == 0
    with app_engine.connect() as c:
        c.execute(text("SELECT set_config('app.tenant_id', '', false)"))
        assert c.execute(text("SELECT count(*) FROM projects")).scalar_one() == 0


def test_cannot_write_into_another_tenant(app_engine: Engine, uid: str) -> None:
    with pytest.raises(DBAPIError, match="row-level security"):
        with tenant_connection(app_engine, "tenant-a") as c:
            c.execute(
                text(
                    "INSERT INTO projects (tenant_id, name, environment, created_by) "
                    "VALUES ('tenant-b', :n, 'x', 'x')"
                ),
                {"n": f"x-{uid}"},
            )


def test_cannot_update_other_tenant_rows_and_cannot_delete_at_all(
    app_engine: Engine, uid: str
) -> None:
    pid = _insert_project(app_engine, "tenant-b", f"victim-{uid}")
    with tenant_connection(app_engine, "tenant-b") as c:
        c.execute(
            text(
                "INSERT INTO scope_manifests (tenant_id, project_id, version, status, body, "
                "canonical_hash, created_by) VALUES ('tenant-b', :p, 1, 'DRAFT', '{}', :h, 'x')"
            ),
            {"p": pid, "h": "sha256:" + "0" * 64},
        )
    with tenant_connection(app_engine, "tenant-a") as c:  # RLS: row invisible, 0 rows touched
        res = c.execute(text("UPDATE scope_manifests SET status='REVOKED' WHERE project_id=:p"),
                        {"p": pid})  # fmt: skip
        assert res.rowcount == 0
    with tenant_connection(app_engine, "tenant-b") as c:
        status = c.execute(text("SELECT status FROM scope_manifests WHERE project_id=:p"),
                           {"p": pid}).scalar_one()  # fmt: skip
        assert status == "DRAFT"
    with pytest.raises(DBAPIError, match="permission denied"):  # least privilege: no DELETE grant
        with tenant_connection(app_engine, "tenant-b") as c:
            c.execute(text("DELETE FROM projects WHERE project_id=:p"), {"p": pid})


def test_cross_tenant_foreign_key_is_rejected(app_engine: Engine, uid: str) -> None:
    """A manifest in tenant-a cannot hang off tenant-b's project even if the id is known."""
    pid = _insert_project(app_engine, "tenant-b", f"fk-{uid}")
    with pytest.raises(DBAPIError), tenant_connection(app_engine, "tenant-a") as c:
        c.execute(
            text(
                "INSERT INTO scope_manifests (tenant_id, project_id, version, status, body, "
                "canonical_hash, created_by) VALUES ('tenant-a', :p, 1, 'DRAFT', '{}', "
                ":h, 'x')"
            ),
            {"p": pid, "h": "sha256:" + "0" * 64},
        )


def test_tenant_connection_requires_tenant(app_engine: Engine) -> None:
    with pytest.raises(ValueError), tenant_connection(app_engine, ""):
        pass


def test_uuid_sanity() -> None:
    assert uuid.UUID(str(uuid.uuid4()))
