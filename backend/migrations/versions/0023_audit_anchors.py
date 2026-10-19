"""Audit-chain anchors (ADR-042): signed chain-head statements and the witness's receipt.

Revision ID: 0023
"""

from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE audit_anchors (
      anchor_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id text NOT NULL,
      seq bigint NOT NULL CHECK (seq >= 1),
      head_hash text NOT NULL CHECK (head_hash ~ '^sha256:[0-9a-f]{64}$'),
      statement_hash text NOT NULL CHECK (statement_hash ~ '^sha256:[0-9a-f]{64}$'),
      key_id text NOT NULL,
      signature text NOT NULL,
      witness_id text NOT NULL,
      receipt jsonb NOT NULL CHECK (jsonb_typeof(receipt) = 'object'),
      anchored_at timestamptz NOT NULL,
      UNIQUE (tenant_id, seq)
    );
    CREATE TRIGGER audit_anchors_append_only BEFORE UPDATE OR DELETE
      ON audit_anchors FOR EACH ROW EXECUTE FUNCTION aisw_immutable_rows();
    ALTER TABLE audit_anchors ENABLE ROW LEVEL SECURITY;
    ALTER TABLE audit_anchors FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON audit_anchors
      USING (tenant_id = aisw_current_tenant()) WITH CHECK (tenant_id = aisw_current_tenant());
    GRANT SELECT, INSERT ON audit_anchors TO aisw_app;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS audit_anchors CASCADE")
