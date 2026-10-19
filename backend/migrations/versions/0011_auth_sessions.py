"""Revoked sign-in sessions (ADR-026).

Sessions are signed cookies; logout records the session id here so the cookie stops working before
it expires. Rows are tenant-scoped like everything else.

Revision ID: 0011
"""

from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE auth_session_revocations (
      tenant_id text NOT NULL,
      sid text NOT NULL CHECK (length(sid) BETWEEN 16 AND 128),
      actor_id text NOT NULL,
      revoked_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL,
      PRIMARY KEY (tenant_id, sid)
    );
    ALTER TABLE auth_session_revocations ENABLE ROW LEVEL SECURITY;
    ALTER TABLE auth_session_revocations FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON auth_session_revocations
      USING (tenant_id = aisw_current_tenant()) WITH CHECK (tenant_id = aisw_current_tenant());
    GRANT SELECT, INSERT ON auth_session_revocations TO aisw_app;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS auth_session_revocations CASCADE")
