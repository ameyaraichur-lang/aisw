"""Reachability graph (ADR-041): per-run edges from firewall configuration and declared-vantage
scans, and the caveats that say what was not modelled. Append-only.

Revision ID: 0022
"""

from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None

TABLES = ["reachability_edges", "reachability_caveats"]


def upgrade() -> None:
    op.execute("""
    CREATE TABLE reachability_edges (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      edge_id text NOT NULL CHECK (edge_id ~ '^re-[0-9a-f]{16}$'),
      src text NOT NULL,
      dst text NOT NULL CHECK (dst <> 'internet' AND dst <> src),
      basis text NOT NULL CHECK (basis IN ('OBSERVED','CONFIGURED')),
      body jsonb NOT NULL,
      PRIMARY KEY (run_id, edge_id),
      FOREIGN KEY (run_id, tenant_id) REFERENCES assessment_runs (run_id, tenant_id)
    );
    CREATE INDEX reachability_edges_dst ON reachability_edges (run_id, dst);

    CREATE TABLE reachability_caveats (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      code text NOT NULL CHECK (code ~ '^[A-Z_]+(:.+)?$'),
      PRIMARY KEY (run_id, code),
      FOREIGN KEY (run_id, tenant_id) REFERENCES assessment_runs (run_id, tenant_id)
    );
    """)
    for t in TABLES:
        op.execute(f"""
        CREATE TRIGGER {t}_append_only BEFORE UPDATE OR DELETE ON {t}
          FOR EACH ROW EXECUTE FUNCTION aisw_immutable_rows();
        ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;
        ALTER TABLE {t} FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation ON {t}
          USING (tenant_id = aisw_current_tenant()) WITH CHECK (tenant_id = aisw_current_tenant());
        GRANT SELECT, INSERT ON {t} TO aisw_app;
        """)


def downgrade() -> None:
    for t in reversed(TABLES):
        op.execute(f"DROP TABLE IF EXISTS {t} CASCADE")
