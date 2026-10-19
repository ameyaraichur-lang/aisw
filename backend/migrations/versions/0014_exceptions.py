"""Finding review actions and exceptions with expiry (ADR-033).

An exception covers one rule on one asset in one project (the finding's stable dedupe key). Only its
decision columns can change, and only along REQUESTED -> APPROVED|REJECTED and APPROVED -> REVOKED;
the approver can never be the requester. Reviews and per-run applications are append-only.

Revision ID: 0014
"""

from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

TABLES = ("exception_applications", "finding_reviews", "finding_exceptions")


def upgrade() -> None:
    op.execute("""
    CREATE TABLE finding_exceptions (
      exception_id text PRIMARY KEY,
      tenant_id text NOT NULL,
      project_id uuid NOT NULL,
      stable_dedupe_key text NOT NULL,
      pack_id text NOT NULL,
      rule_id text NOT NULL,
      asset_id text NOT NULL,
      title text NOT NULL,
      source_run_id text NOT NULL,
      source_finding_id text NOT NULL,
      reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1000),
      requested_by text NOT NULL,
      requested_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL CHECK (expires_at > requested_at),
      status text NOT NULL DEFAULT 'REQUESTED'
        CHECK (status IN ('REQUESTED','APPROVED','REJECTED','REVOKED')),
      decided_by text,
      decided_at timestamptz,
      decision_reason text CHECK (length(decision_reason) BETWEEN 1 AND 1000),
      revoked_by text,
      revoked_at timestamptz,
      revoke_reason text CHECK (length(revoke_reason) BETWEEN 1 AND 1000),
      FOREIGN KEY (source_run_id, source_finding_id) REFERENCES findings (run_id, finding_id),
      CHECK ((status = 'REQUESTED') = (decided_by IS NULL)),
      CHECK (decided_by IS NULL OR (decided_at IS NOT NULL AND decision_reason IS NOT NULL)),
      CHECK (decided_by IS DISTINCT FROM requested_by),
      CHECK ((status = 'REVOKED') = (revoked_by IS NOT NULL)),
      CHECK (revoked_by IS NULL OR (revoked_at IS NOT NULL AND revoke_reason IS NOT NULL))
    );
    CREATE INDEX finding_exceptions_key ON finding_exceptions (tenant_id, project_id, stable_dedupe_key);

    CREATE FUNCTION aisw_exception_transition() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'finding_exceptions rows are never deleted'; END IF;
      IF NOT ((OLD.status = 'REQUESTED' AND NEW.status IN ('APPROVED','REJECTED'))
              OR (OLD.status = 'APPROVED' AND NEW.status = 'REVOKED')) THEN
        RAISE EXCEPTION 'exception status cannot move from % to %', OLD.status, NEW.status;
      END IF;
      IF OLD.decided_by IS NOT NULL AND (NEW.decided_by, NEW.decided_at, NEW.decision_reason)
           IS DISTINCT FROM (OLD.decided_by, OLD.decided_at, OLD.decision_reason) THEN
        RAISE EXCEPTION 'an exception decision is never rewritten';
      END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER finding_exceptions_transition BEFORE UPDATE OR DELETE ON finding_exceptions
      FOR EACH ROW EXECUTE FUNCTION aisw_exception_transition();

    CREATE TABLE finding_reviews (
      review_id text PRIMARY KEY,
      seq bigint GENERATED ALWAYS AS IDENTITY,
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      finding_id text NOT NULL,
      action text NOT NULL CHECK (action IN ('CONFIRM','REJECT','REOPEN','REQUEST_EXCEPTION',
        'EXCEPTION_APPROVED','EXCEPTION_REJECTED','EXCEPTION_REVOKED')),
      from_lifecycle text NOT NULL,
      to_lifecycle text NOT NULL,
      reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1000),
      actor text NOT NULL,
      at timestamptz NOT NULL,
      exception_id text REFERENCES finding_exceptions (exception_id),
      FOREIGN KEY (run_id, finding_id) REFERENCES findings (run_id, finding_id)
    );
    CREATE INDEX finding_reviews_finding ON finding_reviews (run_id, finding_id, seq);
    CREATE TRIGGER finding_reviews_append_only BEFORE UPDATE OR DELETE ON finding_reviews
      FOR EACH ROW EXECUTE FUNCTION aisw_immutable_rows();

    CREATE TABLE exception_applications (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      exception_id text NOT NULL REFERENCES finding_exceptions (exception_id),
      rule_id text NOT NULL,
      asset_id text NOT NULL,
      effect text NOT NULL CHECK (effect IN ('APPLIED','EXPIRED')),
      observed_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL,
      PRIMARY KEY (run_id, exception_id)
    );
    CREATE TRIGGER exception_applications_append_only BEFORE UPDATE OR DELETE
      ON exception_applications FOR EACH ROW EXECUTE FUNCTION aisw_immutable_rows();

    GRANT SELECT, INSERT ON finding_exceptions TO aisw_app;
    GRANT UPDATE (status, decided_by, decided_at, decision_reason, revoked_by, revoked_at,
      revoke_reason) ON finding_exceptions TO aisw_app;
    GRANT SELECT, INSERT ON finding_reviews TO aisw_app;
    GRANT SELECT, INSERT ON exception_applications TO aisw_app;
    """)
    for t in TABLES:
        op.execute(f"""
        ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;
        ALTER TABLE {t} FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation ON {t}
          USING (tenant_id = aisw_current_tenant()) WITH CHECK (tenant_id = aisw_current_tenant());
        """)


def downgrade() -> None:
    for t in TABLES:
        op.execute(f"DROP TABLE IF EXISTS {t} CASCADE")
    op.execute("DROP FUNCTION IF EXISTS aisw_exception_transition()")
