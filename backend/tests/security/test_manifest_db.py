"""Scope manifests are immutable per version and approval invariants hold in the database."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from aisw.core.db import tenant_connection

pytestmark = pytest.mark.security
HASH = "sha256:" + "1" * 64


def _setup(engine: Engine, tenant: str, uid: str) -> tuple[str, str]:
    with tenant_connection(engine, tenant) as c:
        pid = c.execute(
            text(
                "INSERT INTO projects (tenant_id, name, environment, created_by) "
                "VALUES (:t, :n, 'test', 'alice') RETURNING project_id"
            ),
            {"t": tenant, "n": f"m-{uid}"},
        ).scalar_one()
        mid = c.execute(
            text(
                "INSERT INTO scope_manifests (tenant_id, project_id, version, status, body, "
                "canonical_hash, created_by) VALUES (:t, :p, 1, 'DRAFT', CAST(:b AS jsonb), :h, "
                "'alice') RETURNING manifest_id"
            ),
            {"t": tenant, "p": pid, "b": json.dumps({"ports": [443]}), "h": HASH},
        ).scalar_one()
    return str(pid), str(mid)


def test_body_and_hash_cannot_change_for_app_role(app_engine: Engine, uid: str) -> None:
    _, mid = _setup(app_engine, "tenant-a", uid)
    for col, val in (("body", "'{\"ports\":[22]}'::jsonb"), ("canonical_hash", f"'{HASH[:-1]}2'")):
        with pytest.raises(DBAPIError, match="permission denied"):
            with tenant_connection(app_engine, "tenant-a") as c:
                c.execute(text(f"UPDATE scope_manifests SET {col}={val} WHERE manifest_id=:m"),
                          {"m": mid})  # fmt: skip


def test_immutability_trigger_blocks_even_the_owner(
    app_engine: Engine, owner_engine: Engine, uid: str
) -> None:
    _, mid = _setup(app_engine, "tenant-a", uid)
    with pytest.raises(DBAPIError, match="immutable"), owner_engine.begin() as c:
        c.execute(
            text("UPDATE scope_manifests SET body='{\"ports\":[22]}' WHERE manifest_id=:m"),
            {"m": mid},
        )


def test_status_transition_allowed_but_approval_needs_signature(
    app_engine: Engine, uid: str
) -> None:
    _, mid = _setup(app_engine, "tenant-a", uid)
    with tenant_connection(app_engine, "tenant-a") as c:
        c.execute(text("UPDATE scope_manifests SET status='PREFLIGHTED' WHERE manifest_id=:m"),
                  {"m": mid})  # fmt: skip
    for sets in (
        "status='APPROVED'",  # unsigned
        "status='APPROVED', signature='s', key_id='k'",  # no approver
        "status='APPROVED', signature='s', key_id='k', approved_by=ARRAY['alice']",  # self-approval
    ):
        with pytest.raises(DBAPIError, match="check constraint"):
            with tenant_connection(app_engine, "tenant-a") as c:
                c.execute(text(f"UPDATE scope_manifests SET {sets} WHERE manifest_id=:m"),
                          {"m": mid})  # fmt: skip
    with tenant_connection(app_engine, "tenant-a") as c:
        c.execute(
            text(
                "UPDATE scope_manifests SET status='APPROVED', signature='s', key_id='k', "
                "approved_by=ARRAY['bob'] WHERE manifest_id=:m"
            ),
            {"m": mid},
        )


def test_versions_unique_per_project(app_engine: Engine, uid: str) -> None:
    pid, _ = _setup(app_engine, "tenant-a", uid)
    with pytest.raises(DBAPIError, match="unique"):
        with tenant_connection(app_engine, "tenant-a") as c:
            c.execute(
                text(
                    "INSERT INTO scope_manifests (tenant_id, project_id, version, status, body, "
                    "canonical_hash, created_by) VALUES ('tenant-a', :p, 1, 'DRAFT', '{}', :h, 'a')"
                ),
                {"p": pid, "h": HASH},
            )
