"""Migrations apply, are reversible, and re-apply cleanly on a fresh database."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import text

from tests.conftest import make_db, migrate

FOUNDATION = {
    "projects",
    "scope_manifests",
    "execution_permits",
    "idempotency_records",
    "audit_events",
}
PIPELINE = {
    "inventory_entries", "assessment_runs", "run_tasks", "run_events", "evidence_artifacts",
    "assets", "run_asset_status", "observations", "control_assessments", "findings",
    "assurance_results", "coverage_ledger", "reports",
}  # fmt: skip
IMPORTS = {"imports"}
TABLES = FOUNDATION | PIPELINE | IMPORTS


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
    migrate(eng, "0003", down=True)  # 0004 (imports) is independently reversible
    assert _tables(eng) == FOUNDATION | PIPELINE
    migrate(eng, "0002", down=True)  # 0003 (asset attrs) is independently reversible
    with eng.connect() as c:
        cols = {
            r[0]
            for r in c.execute(
                text("SELECT column_name FROM information_schema.columns WHERE table_name='assets'")
            )
        }
    assert "attrs" not in cols and _tables(eng) == FOUNDATION | PIPELINE
    migrate(eng, "0001", down=True)
    assert _tables(eng) == FOUNDATION  # pipeline migration is independently reversible
    migrate(eng, "base", down=True)
    assert _tables(eng) == set()
    migrate(eng, "head")
    assert _tables(eng) == TABLES
    eng.dispose()
