"""Tenant isolation, least privilege and append-only guarantees for the analysis tables."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from aisw.core.db import tenant_connection
from tests.evaluation.stub import ScriptedModel
from tests.integration.test_analysis_pipeline import grounded
from tests.slice import Slice

pytestmark = pytest.mark.security
EXPECTED = ["host-1", "host-2", "host-3"]
TABLES = [
    "risk_assessments", "correlation_scenarios", "recommendations", "narratives", "llm_calls",
]  # fmt: skip


def seeded(sl: Slice) -> str:
    sl.enable_ai(ScriptedModel(grounded))
    _, _, run_id = sl.full_run(EXPECTED, ai_assist=True)
    sl.drain()
    return run_id


@pytest.mark.parametrize("table", TABLES)
def test_other_tenants_see_nothing(sl: Slice, table: str) -> None:
    run_id = seeded(sl)
    with tenant_connection(sl.app_engine, "tenant-a") as c:
        assert (
            c.execute(
                text(f"SELECT count(*) FROM {table} WHERE run_id=:r"), {"r": run_id}
            ).scalar_one()
            > 0
        )
    with tenant_connection(sl.app_engine, "tenant-b") as c:
        assert c.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 0


def test_cross_tenant_writes_are_refused(sl: Slice) -> None:
    run_id = seeded(sl)
    with pytest.raises(DBAPIError), tenant_connection(sl.app_engine, "tenant-b") as c:
        c.execute(
            text(
                "INSERT INTO llm_calls (tenant_id, run_id, purpose, subject_ref, prompt_version, "
                "input_hash, status, attempts, created_at) VALUES ('tenant-a', :r, 'scenario', 'x', "
                "'v', 'h', 'VALIDATED', 1, now())"
            ),
            {"r": run_id},
        )
    with tenant_connection(sl.app_engine, "tenant-b") as c:  # nothing to update or delete either
        assert c.execute(text("UPDATE recommendations SET status='REJECTED'")).rowcount == 0


@pytest.mark.parametrize(
    "stmt",
    [
        "UPDATE risk_assessments SET tier='P0'",
        "DELETE FROM risk_assessments",
        "DELETE FROM recommendations",
        "DELETE FROM correlation_scenarios",
        "UPDATE correlation_scenarios SET body='{}'::jsonb",
        "UPDATE narratives SET body='{}'::jsonb",
        "DELETE FROM narratives",
        "UPDATE recommendations SET body='{}'::jsonb",
        "UPDATE ticket_outbox SET payload='{}'::jsonb",
        "DELETE FROM ticket_outbox",
    ],
)
def test_application_role_cannot_rewrite_analysis_records(sl: Slice, stmt: str) -> None:
    seeded(sl)
    with pytest.raises(DBAPIError), tenant_connection(sl.app_engine, "tenant-a") as c:
        c.execute(text(stmt))


def test_rubric_basis_constraint_blocks_a_fabricated_tier_in_the_database(sl: Slice) -> None:
    seeded(sl)
    with pytest.raises(DBAPIError), tenant_connection(sl.app_engine, "tenant-a") as c:
        c.execute(
            text(
                "INSERT INTO risk_assessments (tenant_id, run_id, finding_id, rubric_version, tier, "
                "provisional_tier, basis, factors, rationale) VALUES ('tenant-a', 'r-x', 'f-x', '1.0.0', "
                "'P0', 'P1', 'NEEDS_POLICY_REVIEW', '{}'::jsonb, 'x')"
            )
        )
