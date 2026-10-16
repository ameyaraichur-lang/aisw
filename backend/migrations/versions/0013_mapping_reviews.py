"""Policy-owner decisions on framework mappings (ADR-032).

Append-only: a change of mind is a new row, and the latest row for a mapping is its state.

Revision ID: 0013
"""

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE framework_mapping_reviews (
      review_id text PRIMARY KEY,
      seq bigint GENERATED ALWAYS AS IDENTITY,
      tenant_id text NOT NULL,
      catalog_version text NOT NULL,
      mapping_key text NOT NULL CHECK (length(mapping_key) BETWEEN 1 AND 300),
      decision text NOT NULL CHECK (decision IN ('APPROVED','REJECTED','NEEDS_REVIEW')),
      reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1000),
      decided_by text NOT NULL,
      decided_at timestamptz NOT NULL
    );
    CREATE INDEX framework_mapping_reviews_latest
      ON framework_mapping_reviews (tenant_id, catalog_version, mapping_key, seq DESC);
    CREATE TRIGGER framework_mapping_reviews_append_only BEFORE UPDATE OR DELETE
      ON framework_mapping_reviews FOR EACH ROW EXECUTE FUNCTION aisw_immutable_rows();
    ALTER TABLE framework_mapping_reviews ENABLE ROW LEVEL SECURITY;
    ALTER TABLE framework_mapping_reviews FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON framework_mapping_reviews
      USING (tenant_id = aisw_current_tenant()) WITH CHECK (tenant_id = aisw_current_tenant());
    GRANT SELECT, INSERT ON framework_mapping_reviews TO aisw_app;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS framework_mapping_reviews CASCADE")
