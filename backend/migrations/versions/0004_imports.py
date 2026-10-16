"""Uploaded import files (CMDB exports, scanner reports) and asset reconciliation columns.

Revision ID: 0004
"""

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE imports (
      tenant_id text NOT NULL,
      import_id text PRIMARY KEY,
      project_id uuid NOT NULL,
      kind text NOT NULL CHECK (kind IN ('cmdb_csv','cmdb_json','prowler_json','greenbone_xml',
        'openscap_xccdf','wazuh_json','nmap_xml','zap_json')),
      filename text NOT NULL,
      content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
      size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 1 AND 5000000),
      redacted boolean NOT NULL,
      uploaded_by text NOT NULL,
      uploaded_at timestamptz NOT NULL,
      FOREIGN KEY (project_id, tenant_id) REFERENCES projects (project_id, tenant_id)
    );
    ALTER TABLE imports ENABLE ROW LEVEL SECURITY;
    ALTER TABLE imports FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON imports
      USING (tenant_id = aisw_current_tenant()) WITH CHECK (tenant_id = aisw_current_tenant());
    GRANT SELECT, INSERT ON imports TO aisw_app;
    CREATE TRIGGER imports_immutable BEFORE UPDATE OR DELETE ON imports
      FOR EACH ROW EXECUTE FUNCTION aisw_immutable_rows();

    -- Cross-source reconciliation merges identities and provenance into existing assets.
    GRANT UPDATE (native_ids, owner, owner_source, criticality, criticality_source, environment,
                  match_confidence) ON assets TO aisw_app;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS imports CASCADE")
