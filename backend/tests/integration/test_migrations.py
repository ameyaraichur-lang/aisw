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
ANALYSIS = {
    "risk_assessments", "correlation_scenarios", "recommendations", "narratives", "llm_calls",
    "ticket_outbox",
}  # fmt: skip
HARDENING = {"retention_holds", "retention_actions"}
AI_VALIDATION = {"ai_validations"}
REVISIONS = {"ai_validation_resolutions"}
SESSIONS = {"auth_session_revocations"}
MAPPING_REVIEWS = {"framework_mapping_reviews"}
EXCEPTIONS = {"finding_exceptions", "finding_reviews", "exception_applications"}
TRIGGERS = {"ai_validation_triggers"}
TABLES = (
    FOUNDATION
    | PIPELINE
    | IMPORTS
    | ANALYSIS
    | HARDENING
    | AI_VALIDATION
    | REVISIONS
    | SESSIONS
    | MAPPING_REVIEWS
    | EXCEPTIONS
    | TRIGGERS
)


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
    grant = text("SELECT has_table_privilege('aisw_app', 'alembic_version', 'SELECT')")
    with eng.connect() as c:
        assert c.execute(grant).scalar() is True
    kind_check = text("SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                      "WHERE conname='imports_kind_check'")  # fmt: skip
    with eng.connect() as c:
        assert "trivy_json" in str(c.execute(kind_check).scalar())
    outbox_cols = text("SELECT count(*) FROM information_schema.columns "
                       "WHERE table_name='ticket_outbox' AND column_name='external_ref'")  # fmt: skip
    with eng.connect() as c:
        assert c.execute(outbox_cols).scalar() == 1
    sod = text("SELECT 1 FROM pg_proc WHERE proname='aisw_recommendation_sod'")
    with eng.connect() as c:
        assert c.execute(sod).first()
    migrate(eng, "0017", down=True)  # 0018 (recommendation separation of duties) is reversible
    with eng.connect() as c:
        assert not c.execute(sod).first()
    migrate(eng, "0016", down=True)  # 0017 (ticket delivery state) is reversible
    with eng.connect() as c:
        assert c.execute(outbox_cols).scalar() == 0
    migrate(eng, "0015", down=True)  # 0016 (AVP trigger decisions) is reversible
    assert _tables(eng) == TABLES - TRIGGERS
    migrate(eng, "0014", down=True)  # 0015 (import kinds) is reversible
    with eng.connect() as c:
        assert "trivy_json" not in str(c.execute(kind_check).scalar())
    migrate(eng, "0013", down=True)  # 0014 (exceptions and finding reviews) is reversible
    assert _tables(eng) == TABLES - TRIGGERS - EXCEPTIONS
    with eng.connect() as c:
        assert not c.execute(
            text("SELECT 1 FROM pg_proc WHERE proname='aisw_exception_transition'")
        ).first()
    migrate(eng, "0012", down=True)  # 0013 (mapping reviews) is independently reversible
    assert _tables(eng) == TABLES - TRIGGERS - EXCEPTIONS - MAPPING_REVIEWS
    migrate(eng, "0011", down=True)  # 0012 (ops grants) is independently reversible
    with eng.connect() as c:
        assert c.execute(grant).scalar() is False
    migrate(eng, "0010", down=True)  # 0011 (session revocations) is independently reversible
    assert _tables(eng) == TABLES - TRIGGERS - EXCEPTIONS - MAPPING_REVIEWS - SESSIONS
    migrate(eng, "0009", down=True)  # 0010 (generation agents) is independently reversible
    with eng.connect() as c:
        checks = {
            n: d for n, d in c.execute(text(
                "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint WHERE contype='c' "
                "AND conrelid IN ('ai_validations'::regclass, 'narratives'::regclass)"))
        }  # fmt: skip
    assert "ai_validations_dissent_effect" not in checks and "ai_validations_check" in checks
    assert "executive" not in checks["narratives_purpose_check"]
    migrate(eng, "head")
    migrate(eng, "0009", down=True)
    migrate(eng, "0008", down=True)  # 0009 (model-call usage) is independently reversible
    assert _tables(eng) == TABLES - TRIGGERS - EXCEPTIONS - MAPPING_REVIEWS - SESSIONS
    with eng.connect() as c:
        assert not c.execute(
            text("SELECT 1 FROM information_schema.columns WHERE table_name='llm_calls' "
                 "AND column_name IN ('input_tokens', 'latency_ms', 'replayed')")
        ).first()  # fmt: skip
    migrate(eng, "0007", down=True)  # 0008 (review revisions) is independently reversible
    assert _tables(eng) == TABLES - TRIGGERS - EXCEPTIONS - MAPPING_REVIEWS - SESSIONS - REVISIONS
    with eng.connect() as c:
        assert not c.execute(
            text("SELECT 1 FROM information_schema.columns WHERE table_name='reports' "
                 "AND column_name='revision'")
        ).first()  # fmt: skip
    migrate(eng, "0006", down=True)  # 0007 (agent validation) is independently reversible
    assert (
        _tables(eng)
        == TABLES - TRIGGERS - EXCEPTIONS - MAPPING_REVIEWS - SESSIONS - REVISIONS - AI_VALIDATION
    )
    migrate(eng, "0005", down=True)  # 0006 (hardening) is independently reversible
    assert (
        _tables(eng)
        == TABLES
        - TRIGGERS
        - EXCEPTIONS
        - MAPPING_REVIEWS
        - SESSIONS
        - REVISIONS
        - AI_VALIDATION
        - HARDENING
    )
    with eng.connect() as c:
        assert not c.execute(
            text("SELECT 1 FROM pg_trigger WHERE tgname='assessment_runs_permit_swap'")
        ).first()
    migrate(eng, "0004", down=True)  # 0005 (analysis) is independently reversible
    assert _tables(eng) == FOUNDATION | PIPELINE | IMPORTS
    with eng.connect() as c:
        assert not c.execute(
            text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name='assessment_runs' AND column_name='ai_mode'"
            )
        ).first()
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
