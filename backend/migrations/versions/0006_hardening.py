"""Hardening: guarded permit renewal and retention (holds, append-only purge log).

Revision ID: 0006
"""

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    -- A run may be re-pointed to a newer permit ONLY if the new permit belongs to the same run,
    -- tenant, project and manifest hash and is strictly newer. Renewal can never widen scope.
    CREATE FUNCTION aisw_guard_permit_swap() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE old_p execution_permits%ROWTYPE; new_p execution_permits%ROWTYPE;
    BEGIN
      IF NEW.permit_id IS NOT DISTINCT FROM OLD.permit_id THEN RETURN NEW; END IF;
      SELECT * INTO old_p FROM execution_permits WHERE permit_id = OLD.permit_id;
      SELECT * INTO new_p FROM execution_permits WHERE permit_id = NEW.permit_id;
      IF new_p.permit_id IS NULL OR new_p.run_id <> NEW.run_id OR new_p.tenant_id <> NEW.tenant_id
         OR new_p.project_id <> NEW.project_id OR new_p.manifest_id <> NEW.manifest_id
         OR new_p.manifest_hash <> NEW.manifest_hash OR new_p.issued_at <= old_p.issued_at
         OR new_p.revoked_at IS NOT NULL
         OR NOT (new_p.allowed_task_types <@ old_p.allowed_task_types) THEN
        RAISE EXCEPTION 'permit swap refused' USING ERRCODE = '23514';
      END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER assessment_runs_permit_swap BEFORE UPDATE OF permit_id ON assessment_runs
      FOR EACH ROW EXECUTE FUNCTION aisw_guard_permit_swap();
    GRANT UPDATE (permit_id) ON assessment_runs TO aisw_app;

    -- Retention: soft purge only. Blobs are moved to a quarantine area, never deleted; every
    -- action is an append-only row (evidence rows themselves stay immutable), and a legal hold
    -- blocks purge of a run.

    CREATE TABLE retention_holds (
      tenant_id text NOT NULL,
      hold_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      run_id text NOT NULL,
      reason text NOT NULL CHECK (length(reason) BETWEEN 3 AND 1000),
      placed_by text NOT NULL,
      placed_at timestamptz NOT NULL,
      released_by text,
      released_at timestamptz,
      CHECK ((released_by IS NULL) = (released_at IS NULL))
    );
    CREATE UNIQUE INDEX retention_holds_one_active ON retention_holds (run_id) WHERE released_at IS NULL;

    CREATE TABLE retention_actions (
      tenant_id text NOT NULL,
      action_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      plan_hash text NOT NULL,
      kind text NOT NULL CHECK (kind IN ('EVIDENCE','IMPORT')),
      ref text NOT NULL,
      content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
      size_bytes bigint NOT NULL,
      quarantined boolean NOT NULL,
      executed_by text NOT NULL,
      executed_at timestamptz NOT NULL,
      reason text NOT NULL
    );
    CREATE TRIGGER retention_actions_append_only BEFORE UPDATE OR DELETE ON retention_actions
      FOR EACH ROW EXECUTE FUNCTION aisw_immutable_rows();
    DO $$ DECLARE t text; BEGIN
      FOREACH t IN ARRAY ARRAY['retention_holds','retention_actions'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = aisw_current_tenant()) '
                       'WITH CHECK (tenant_id = aisw_current_tenant())', t);
        EXECUTE format('GRANT SELECT, INSERT ON %I TO aisw_app', t);
      END LOOP;
    END $$;
    GRANT UPDATE (released_by, released_at) ON retention_holds TO aisw_app;
    """)


def downgrade() -> None:
    op.execute("""
    DROP TABLE IF EXISTS retention_actions CASCADE;
    DROP TABLE IF EXISTS retention_holds CASCADE;
    REVOKE UPDATE (permit_id) ON assessment_runs FROM aisw_app;
    DROP TRIGGER IF EXISTS assessment_runs_permit_swap ON assessment_runs;
    DROP FUNCTION IF EXISTS aisw_guard_permit_swap();
    """)
