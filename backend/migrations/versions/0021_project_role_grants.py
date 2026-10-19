"""Per-project role grants: an actor holds an extra work role on a single project.

Only the four per-project work roles can be granted; nobody grants a role to themselves; a grant is
never edited or deleted, only revoked once.

Revision ID: 0021
"""

from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE project_role_grants (
      grant_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id text NOT NULL,
      project_id uuid NOT NULL,
      actor_id text NOT NULL CHECK (actor_id ~ '^[A-Za-z0-9][A-Za-z0-9._@-]{0,199}$'),
      role text NOT NULL CHECK (role IN ('assessment_operator','approver','reviewer',
        'report_reader')),
      reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1000),
      granted_by text NOT NULL,
      granted_at timestamptz NOT NULL,
      revoked_by text,
      revoked_at timestamptz,
      CHECK (granted_by <> actor_id),
      CHECK ((revoked_by IS NULL) = (revoked_at IS NULL)),
      FOREIGN KEY (project_id, tenant_id) REFERENCES projects (project_id, tenant_id)
    );
    CREATE UNIQUE INDEX project_role_grants_active
      ON project_role_grants (tenant_id, project_id, actor_id, role) WHERE revoked_at IS NULL;
    CREATE INDEX project_role_grants_actor
      ON project_role_grants (tenant_id, actor_id) WHERE revoked_at IS NULL;
    CREATE FUNCTION aisw_grant_revoke_once() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP = 'DELETE' OR OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'project role grants are revoked once, never edited or deleted'
          USING ERRCODE = 'check_violation';
      END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER project_role_grants_revoke_once BEFORE UPDATE OR DELETE
      ON project_role_grants FOR EACH ROW EXECUTE FUNCTION aisw_grant_revoke_once();
    ALTER TABLE project_role_grants ENABLE ROW LEVEL SECURITY;
    ALTER TABLE project_role_grants FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON project_role_grants
      USING (tenant_id = aisw_current_tenant()) WITH CHECK (tenant_id = aisw_current_tenant());
    GRANT SELECT, INSERT ON project_role_grants TO aisw_app;
    GRANT UPDATE (revoked_by, revoked_at) ON project_role_grants TO aisw_app;
    """)


def downgrade() -> None:
    op.execute("""
    DROP TABLE IF EXISTS project_role_grants CASCADE;
    DROP FUNCTION IF EXISTS aisw_grant_revoke_once();
    """)
