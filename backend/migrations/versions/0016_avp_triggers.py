"""AVP trigger decisions: one append-only row per agent outcome the trigger policy considered.

Revision ID: 0016
"""

from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE ai_validation_triggers (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      agent_id int NOT NULL CHECK (agent_id BETWEEN 0 AND 8),
      target_ref text NOT NULL CHECK (length(target_ref) BETWEEN 1 AND 300),
      triggered boolean NOT NULL,
      rule text NOT NULL CHECK (length(rule) BETWEEN 1 AND 200),
      policy_version text NOT NULL,
      policy_sha256 text NOT NULL CHECK (policy_sha256 ~ '^[0-9a-f]{64}$'),
      decided_at timestamptz NOT NULL,
      PRIMARY KEY (run_id, target_ref),
      FOREIGN KEY (run_id, tenant_id) REFERENCES assessment_runs (run_id, tenant_id)
    );
    CREATE TRIGGER ai_validation_triggers_append_only BEFORE UPDATE OR DELETE
      ON ai_validation_triggers FOR EACH ROW EXECUTE FUNCTION aisw_immutable_rows();
    ALTER TABLE ai_validation_triggers ENABLE ROW LEVEL SECURITY;
    ALTER TABLE ai_validation_triggers FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON ai_validation_triggers
      USING (tenant_id = aisw_current_tenant()) WITH CHECK (tenant_id = aisw_current_tenant());
    GRANT SELECT, INSERT ON ai_validation_triggers TO aisw_app;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS ai_validation_triggers CASCADE")
