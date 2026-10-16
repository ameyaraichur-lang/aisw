"""Agent validation pass (ADR-021): one append-only verdict row per validated item.

Revision ID: 0007
"""

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE ai_validations (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      target_ref text NOT NULL,
      agent_id int NOT NULL CHECK (agent_id BETWEEN 0 AND 8),
      packet_id text NOT NULL,
      verdict text NOT NULL CHECK (verdict IN ('CONCUR','CONCERN','DISSENT','INSUFFICIENT_EVIDENCE',
        'NO_VERDICT','VALIDATOR_INVALID','UNAVAILABLE')),
      effect text NOT NULL CHECK (effect IN ('ANNOTATION','REVIEW_ITEM','HOLD_FOR_REVIEW','NONE')),
      issues jsonb NOT NULL DEFAULT '[]'::jsonb,
      human_questions jsonb NOT NULL DEFAULT '[]'::jsonb,
      validator_confidence text CHECK (validator_confidence IN ('LOW','MEDIUM','HIGH')),
      defects jsonb NOT NULL DEFAULT '[]'::jsonb,
      model_id text,
      prompt_version text NOT NULL,
      input_hash text NOT NULL,
      output_hash text,
      created_at timestamptz NOT NULL,
      PRIMARY KEY (run_id, target_ref),
      FOREIGN KEY (run_id, tenant_id) REFERENCES assessment_runs (run_id, tenant_id),
      -- the only verdict that holds anything is DISSENT, and only as a hold for human review
      CHECK ((verdict = 'DISSENT') = (effect = 'HOLD_FOR_REVIEW')),
      CHECK (verdict IN ('CONCUR','CONCERN','DISSENT','INSUFFICIENT_EVIDENCE') OR effect = 'NONE')
    );
    CREATE TRIGGER ai_validations_append_only BEFORE UPDATE OR DELETE ON ai_validations
      FOR EACH ROW EXECUTE FUNCTION aisw_immutable_rows();
    ALTER TABLE ai_validations ENABLE ROW LEVEL SECURITY;
    ALTER TABLE ai_validations FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON ai_validations
      USING (tenant_id = aisw_current_tenant()) WITH CHECK (tenant_id = aisw_current_tenant());
    GRANT SELECT, INSERT ON ai_validations TO aisw_app;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS ai_validations CASCADE")
