"""Scheduled retention checks: one append-only row per dry-run plan the scheduler built.

Revision ID: 0020
"""

from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE retention_checks (
      check_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id text NOT NULL,
      checked_at timestamptz NOT NULL,
      plan_hash text NOT NULL CHECK (plan_hash ~ '^sha256:[0-9a-f]{64}$'),
      items int NOT NULL CHECK (items >= 0),
      blobs int NOT NULL CHECK (blobs >= 0),
      bytes bigint NOT NULL CHECK (bytes >= 0),
      held_runs int NOT NULL CHECK (held_runs >= 0),
      outcome text NOT NULL CHECK (outcome IN ('NOTHING_DUE','DUE','AWAITING_CONFIRMATION',
        'EXECUTED','PLAN_CHANGED')),
      auto_execute boolean NOT NULL
    );
    CREATE INDEX retention_checks_recent ON retention_checks (tenant_id, checked_at DESC);
    CREATE TRIGGER retention_checks_append_only BEFORE UPDATE OR DELETE
      ON retention_checks FOR EACH ROW EXECUTE FUNCTION aisw_immutable_rows();
    ALTER TABLE retention_checks ENABLE ROW LEVEL SECURITY;
    ALTER TABLE retention_checks FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON retention_checks
      USING (tenant_id = aisw_current_tenant()) WITH CHECK (tenant_id = aisw_current_tenant());
    GRANT SELECT, INSERT ON retention_checks TO aisw_app;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS retention_checks CASCADE")
