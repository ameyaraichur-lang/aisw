"""Foundation: projects, scope manifests, permits, idempotency, audit chain, tenant RLS.

Revision ID: 0001
"""

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

TENANT_TABLES = [
    "projects",
    "scope_manifests",
    "execution_permits",
    "idempotency_records",
    "audit_events",
]


def upgrade() -> None:
    op.execute("""
    DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisw_app') THEN
        CREATE ROLE aisw_app NOLOGIN NOBYPASSRLS;
      END IF;
    END $$;
    """)
    # Fail-closed tenant accessor: unset/empty setting yields NULL, which matches no row.
    op.execute("""
    CREATE FUNCTION aisw_current_tenant() RETURNS text LANGUAGE sql STABLE AS
    $$ SELECT NULLIF(current_setting('app.tenant_id', true), '') $$;
    """)

    op.execute("""
    CREATE TABLE projects (
      project_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id text NOT NULL,
      name text NOT NULL,
      environment text NOT NULL,
      owner text,
      business_context jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_by text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, name),
      UNIQUE (project_id, tenant_id)
    );
    CREATE TABLE scope_manifests (
      manifest_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id text NOT NULL,
      project_id uuid NOT NULL,
      version int NOT NULL CHECK (version >= 1),
      status text NOT NULL CHECK (status IN
        ('DRAFT','PREFLIGHTED','APPROVED','SUPERSEDED','REVOKED')),
      body jsonb NOT NULL,
      canonical_hash text NOT NULL CHECK (canonical_hash ~ '^sha256:[0-9a-f]{64}$'),
      signature text,
      key_id text,
      created_by text NOT NULL,
      approved_by text[] NOT NULL DEFAULT '{}',
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (project_id, version),
      FOREIGN KEY (project_id, tenant_id) REFERENCES projects (project_id, tenant_id),
      CHECK (status <> 'APPROVED' OR (signature IS NOT NULL AND key_id IS NOT NULL
             AND cardinality(approved_by) > 0 AND NOT (created_by = ANY (approved_by))))
    );
    CREATE TABLE execution_permits (
      permit_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id text NOT NULL,
      project_id uuid NOT NULL,
      run_id text NOT NULL,
      manifest_id uuid NOT NULL REFERENCES scope_manifests (manifest_id),
      manifest_hash text NOT NULL,
      allowed_task_types text[] NOT NULL CHECK (cardinality(allowed_task_types) > 0),
      issued_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL,
      policy_version text NOT NULL,
      revoked_at timestamptz,
      CHECK (expires_at > issued_at),
      FOREIGN KEY (project_id, tenant_id) REFERENCES projects (project_id, tenant_id)
    );
    CREATE TABLE idempotency_records (
      tenant_id text NOT NULL,
      actor text NOT NULL,
      scope text NOT NULL,
      idem_key text NOT NULL,
      request_hash text NOT NULL,
      status_code int,
      response jsonb,
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (tenant_id, actor, scope, idem_key)
    );
    CREATE TABLE audit_events (
      event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id text NOT NULL,
      seq bigint NOT NULL CHECK (seq >= 1),
      actor text NOT NULL,
      action text NOT NULL,
      resource text NOT NULL,
      before_hash text,
      after_hash text,
      correlation_id text NOT NULL,
      result text NOT NULL CHECK (result IN ('SUCCESS','DENIED','FAILURE')),
      occurred_at timestamptz NOT NULL,
      prev_hash text NOT NULL,
      event_hash text NOT NULL,
      UNIQUE (tenant_id, seq)
    );
    """)

    # Scope manifests are immutable per version: only status/approval/signature may change.
    op.execute("""
    CREATE FUNCTION aisw_manifest_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.body IS DISTINCT FROM OLD.body
         OR NEW.canonical_hash IS DISTINCT FROM OLD.canonical_hash
         OR NEW.version IS DISTINCT FROM OLD.version
         OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
         OR NEW.project_id IS DISTINCT FROM OLD.project_id
         OR NEW.created_by IS DISTINCT FROM OLD.created_by THEN
        RAISE EXCEPTION 'scope manifest versions are immutable; create a new version';
      END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER manifest_immutable BEFORE UPDATE ON scope_manifests
      FOR EACH ROW EXECUTE FUNCTION aisw_manifest_immutable();
    """)

    # Audit log is append-only and its chain linkage is enforced by the database.
    op.execute("""
    CREATE FUNCTION aisw_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'audit_events is append-only'; END $$;
    CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE ON audit_events
      FOR EACH ROW EXECUTE FUNCTION aisw_audit_append_only();
    CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_events
      FOR EACH STATEMENT EXECUTE FUNCTION aisw_audit_append_only();

    CREATE FUNCTION aisw_audit_chain_check() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE last_seq bigint; last_hash text;
    BEGIN
      PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id, 0));
      SELECT seq, event_hash INTO last_seq, last_hash FROM audit_events
        WHERE tenant_id = NEW.tenant_id ORDER BY seq DESC LIMIT 1;
      IF last_seq IS NULL THEN
        IF NEW.seq <> 1 OR NEW.prev_hash <> 'sha256:' || repeat('0', 64) THEN
          RAISE EXCEPTION 'audit chain must start at seq 1 with the genesis hash';
        END IF;
      ELSIF NEW.seq <> last_seq + 1 OR NEW.prev_hash <> last_hash THEN
        RAISE EXCEPTION 'audit chain linkage violated';
      END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER audit_chain BEFORE INSERT ON audit_events
      FOR EACH ROW EXECUTE FUNCTION aisw_audit_chain_check();
    """)

    for t in TENANT_TABLES:
        op.execute(f"""
        ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;
        ALTER TABLE {t} FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation ON {t}
          USING (tenant_id = aisw_current_tenant())
          WITH CHECK (tenant_id = aisw_current_tenant());
        """)

    # Least privilege for the application role.
    op.execute("""
    GRANT EXECUTE ON FUNCTION aisw_current_tenant() TO aisw_app;
    GRANT SELECT, INSERT ON projects TO aisw_app;
    GRANT SELECT, INSERT ON scope_manifests TO aisw_app;
    GRANT UPDATE (status, signature, key_id, approved_by) ON scope_manifests TO aisw_app;
    GRANT SELECT, INSERT ON execution_permits TO aisw_app;
    GRANT UPDATE (revoked_at) ON execution_permits TO aisw_app;
    GRANT SELECT, INSERT ON idempotency_records TO aisw_app;
    GRANT UPDATE (status_code, response) ON idempotency_records TO aisw_app;
    GRANT SELECT, INSERT ON audit_events TO aisw_app;
    """)


def downgrade() -> None:
    for t in reversed(TENANT_TABLES):
        op.execute(f"DROP TABLE IF EXISTS {t} CASCADE")
    op.execute("""
    DROP FUNCTION IF EXISTS aisw_audit_chain_check();
    DROP FUNCTION IF EXISTS aisw_audit_append_only();
    DROP FUNCTION IF EXISTS aisw_manifest_immutable();
    DROP FUNCTION IF EXISTS aisw_current_tenant();
    """)
