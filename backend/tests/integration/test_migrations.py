"""Migrations apply, are reversible, and re-apply cleanly on a fresh database."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import text

from tests.conftest import make_db, migrate

TABLES = {"projects", "scope_manifests", "execution_permits", "idempotency_records", "audit_events"}


def _tables(engine) -> set[str]:  # type: ignore[no-untyped-def]
    with engine.connect() as c:
        return {
            r[0]
            for r in c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname='public'"))
        } - {"alembic_version"}


def test_upgrade_downgrade_upgrade(pg_server: Any) -> None:
    eng = make_db(pg_server, f"mig_{uuid.uuid4().hex[:8]}")
    migrate(eng, "head")
    assert _tables(eng) == TABLES
    migrate(eng, "base", down=True)
    assert _tables(eng) == set()
    migrate(eng, "head")
    assert _tables(eng) == TABLES
    eng.dispose()
