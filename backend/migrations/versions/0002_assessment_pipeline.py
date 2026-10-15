"""Assessment pipeline: inventory, runs, task queue, events, evidence, results, reports.

Revision ID: 0002

Tenant isolation is forced by RLS on every table. The task queue and the run table additionally
expose NON-TERMINAL rows to the dedicated ``aisw_worker`` role (which inherits aisw_app's grants):
the worker must find work across tenants, but then performs ALL data access inside a tenant
context. The API role (aisw_app) never gets the cross-tenant policies.
"""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TENANT_TABLES = [
    "inventory_entries", "assessment_runs", "run_tasks", "run_events", "evidence_artifacts",
    "assets", "run_asset_status", "observations", "control_assessments", "findings",
    "assurance_results", "coverage_ledger", "reports",
]  # fmt: skip


def upgrade() -> None:
    op.execute("""
    DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisw_worker') THEN
        CREATE ROLE aisw_worker NOLOGIN NOBYPASSRLS;
      END IF;
    END $$;
    GRANT aisw_app TO aisw_worker;

    CREATE TABLE inventory_entries (
      entry_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id text NOT NULL,
      project_id uuid NOT NULL,
      kind text NOT NULL,
      selector text NOT NULL,
      resolved_id text NOT NULL,
      expected_assets jsonb NOT NULL DEFAULT '[]'::jsonb,
      created_by text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (project_id, kind, selector),
      FOREIGN KEY (project_id, tenant_id) REFERENCES projects (project_id, tenant_id)
    );

    CREATE TABLE assessment_runs (
      run_id text PRIMARY KEY,
      tenant_id text NOT NULL,
      project_id uuid NOT NULL,
      manifest_id uuid NOT NULL REFERENCES scope_manifests (manifest_id),
      manifest_hash text NOT NULL,
      permit_id uuid NOT NULL REFERENCES execution_permits (permit_id),
      state text NOT NULL CHECK (state IN ('DRAFT','AUTHORIZATION_PENDING','AUTHORIZED','PREFLIGHT',
        'DISCOVERY','ASSESSMENT_DISPATCH','NORMALIZATION','POLICY_EVALUATION','CORRELATION',
        'ARCHITECTURE_ANALYSIS','ASSURANCE','REPORT_READY','HUMAN_REVIEW','CLOSED','PARTIAL',
        'FAILED','CANCELLED','EXPIRED')),
      last_phase text,
      reason text,
      partial boolean NOT NULL DEFAULT false,
      cancel_requested boolean NOT NULL DEFAULT false,
      requested_by text NOT NULL,
      assessment_profile text NOT NULL,
      policy_version text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (run_id, tenant_id),
      FOREIGN KEY (project_id, tenant_id) REFERENCES projects (project_id, tenant_id)
    );

    CREATE TABLE run_tasks (
      task_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      task_type text NOT NULL,
      adapter_id text NOT NULL,
      profile text NOT NULL,
      target_kind text NOT NULL,
      target_selector text NOT NULL,
      params jsonb NOT NULL DEFAULT '{}'::jsonb,
      expected_assets jsonb NOT NULL DEFAULT '[]'::jsonb,
      status text NOT NULL DEFAULT 'QUEUED' CHECK (status IN ('QUEUED','RUNNING','SUCCEEDED',
        'PARTIAL','FAILED','REJECTED','SKIPPED','CANCELLED','TIMED_OUT','NEEDS_REVIEW')),
      attempts int NOT NULL DEFAULT 0,
      max_attempts int NOT NULL DEFAULT 3,
      available_at timestamptz NOT NULL DEFAULT now(),
      locked_by text,
      locked_until timestamptz,
      started_at timestamptz,
      completed_at timestamptz,
      warnings jsonb NOT NULL DEFAULT '[]'::jsonb,
      errors jsonb NOT NULL DEFAULT '[]'::jsonb,
      output_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
      tool_version text,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (run_id, adapter_id, target_kind, target_selector),
      FOREIGN KEY (run_id, tenant_id) REFERENCES assessment_runs (run_id, tenant_id)
    );

    CREATE TABLE run_events (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      seq bigint NOT NULL CHECK (seq >= 1),
      event_id uuid NOT NULL DEFAULT gen_random_uuid(),
      event_type text NOT NULL,
      payload jsonb NOT NULL DEFAULT '{}'::jsonb,
      occurred_at timestamptz NOT NULL,
      PRIMARY KEY (run_id, seq),
      UNIQUE (event_id),
      FOREIGN KEY (run_id, tenant_id) REFERENCES assessment_runs (run_id, tenant_id)
    );

    CREATE TABLE evidence_artifacts (
      tenant_id text NOT NULL,
      evidence_ref text NOT NULL,
      project_id uuid NOT NULL,
      run_id text NOT NULL,
      task_id uuid,
      content_hash text NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
      size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
      media_type text NOT NULL,
      source text NOT NULL,
      tool_version text NOT NULL,
      collected_at timestamptz NOT NULL,
      redacted boolean NOT NULL,
      PRIMARY KEY (tenant_id, evidence_ref),
      FOREIGN KEY (run_id, tenant_id) REFERENCES assessment_runs (run_id, tenant_id)
    );

    CREATE TABLE assets (
      tenant_id text NOT NULL,
      project_id uuid NOT NULL,
      asset_id text NOT NULL,
      run_id text NOT NULL,
      asset_type text NOT NULL,
      native_ids jsonb NOT NULL CHECK (jsonb_typeof(native_ids) = 'object'
                                       AND native_ids <> '{}'::jsonb),
      environment text,
      owner text,
      owner_source text,
      criticality text,
      criticality_source text,
      technology text,
      first_seen timestamptz NOT NULL,
      last_seen timestamptz NOT NULL,
      match_confidence text NOT NULL,
      PRIMARY KEY (tenant_id, project_id, asset_id),
      CHECK (owner IS NULL OR owner_source IS NOT NULL),
      CHECK (criticality IS NULL OR criticality_source IS NOT NULL)
    );

    CREATE TABLE run_asset_status (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      task_id uuid NOT NULL,
      segment text NOT NULL,
      asset_id text NOT NULL,
      status text NOT NULL CHECK (status IN ('SCANNED','UNREACHABLE','UNSUPPORTED')),
      reason text,
      PRIMARY KEY (run_id, task_id, asset_id)
    );

    CREATE TABLE observations (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      observation_id text NOT NULL,
      asset_id text NOT NULL,
      source text NOT NULL,
      rule_id text NOT NULL,
      observed_value jsonb,
      expected_value jsonb,
      outcome text NOT NULL,
      observed_at timestamptz NOT NULL,
      evidence_ref text NOT NULL,
      tool_version text NOT NULL,
      PRIMARY KEY (run_id, observation_id)
    );

    CREATE TABLE control_assessments (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      framework text NOT NULL,
      version text NOT NULL,
      control_id text NOT NULL,
      applicability text NOT NULL,
      outcome text NOT NULL CHECK (outcome IN ('PASS','FAIL','NOT_APPLICABLE','NOT_ASSESSED',
        'UNKNOWN','ERROR','EXCEPTION')),
      evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
      policy_version text NOT NULL,
      PRIMARY KEY (run_id, framework, version, control_id),
      CHECK (outcome <> 'PASS' OR jsonb_array_length(evidence_refs) > 0)
    );

    CREATE TABLE findings (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      finding_id text NOT NULL,
      stable_dedupe_key text NOT NULL,
      project_id uuid NOT NULL,
      severity text NOT NULL,
      outcome text NOT NULL CHECK (outcome <> 'PASS'),
      lifecycle text NOT NULL DEFAULT 'NEW',
      assurance_verdict text CHECK (assurance_verdict IN ('ACCEPT','REJECT','NEEDS_REVIEW')),
      body jsonb NOT NULL CHECK (jsonb_array_length(body->'evidence_refs') > 0),
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (run_id, finding_id),
      UNIQUE (run_id, stable_dedupe_key)
    );

    CREATE TABLE assurance_results (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      item_ref text NOT NULL,
      verdict text NOT NULL CHECK (verdict IN ('ACCEPT','REJECT','NEEDS_REVIEW')),
      defect_codes jsonb NOT NULL DEFAULT '[]'::jsonb,
      missing_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
      stale_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
      validation_version text NOT NULL,
      validated_at timestamptz NOT NULL,
      PRIMARY KEY (run_id, item_ref),
      CHECK (verdict <> 'ACCEPT' OR (jsonb_array_length(defect_codes) = 0
             AND jsonb_array_length(missing_refs) = 0 AND jsonb_array_length(stale_refs) = 0))
    );

    CREATE TABLE coverage_ledger (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      segment text NOT NULL,
      body jsonb NOT NULL,
      PRIMARY KEY (run_id, segment)
    );

    CREATE TABLE reports (
      report_id text PRIMARY KEY,
      tenant_id text NOT NULL,
      project_id uuid NOT NULL,
      run_id text NOT NULL UNIQUE,
      body jsonb NOT NULL,
      html text NOT NULL,
      report_hash text NOT NULL,
      approval_state text NOT NULL DEFAULT 'PENDING' CHECK (approval_state IN
        ('PENDING','APPROVED','REJECTED')),
      approved_by text,
      approved_at timestamptz,
      generated_at timestamptz NOT NULL,
      CHECK (approval_state <> 'APPROVED' OR approved_by IS NOT NULL)
    );
    """)

    # Append-only run events; immutable evidence metadata.
    op.execute("""
    CREATE FUNCTION aisw_immutable_rows() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION '% is append-only', TG_TABLE_NAME; END $$;
    CREATE TRIGGER events_append_only BEFORE UPDATE OR DELETE ON run_events
      FOR EACH ROW EXECUTE FUNCTION aisw_immutable_rows();
    CREATE TRIGGER evidence_immutable BEFORE UPDATE OR DELETE ON evidence_artifacts
      FOR EACH ROW EXECUTE FUNCTION aisw_immutable_rows();
    """)

    for t in TENANT_TABLES:
        op.execute(f"""
        ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;
        ALTER TABLE {t} FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation ON {t}
          USING (tenant_id = aisw_current_tenant())
          WITH CHECK (tenant_id = aisw_current_tenant());
        """)

    # Cross-tenant work discovery for the worker role ONLY, non-terminal rows only.
    op.execute("""
    CREATE POLICY worker_discover ON run_tasks FOR ALL TO aisw_worker
      USING (status IN ('QUEUED','RUNNING')) WITH CHECK (status IN ('QUEUED','RUNNING',
        'SUCCEEDED','PARTIAL','FAILED','REJECTED','SKIPPED','CANCELLED','TIMED_OUT','NEEDS_REVIEW'));
    CREATE POLICY worker_discover ON assessment_runs FOR SELECT TO aisw_worker
      USING (state NOT IN ('CLOSED','FAILED','CANCELLED','EXPIRED','PARTIAL','REPORT_READY',
        'HUMAN_REVIEW'));
    """)

    op.execute("""
    GRANT SELECT, INSERT ON inventory_entries TO aisw_app;
    GRANT SELECT, INSERT ON assessment_runs TO aisw_app;
    GRANT UPDATE (state, last_phase, reason, partial, cancel_requested, updated_at)
      ON assessment_runs TO aisw_app;
    GRANT SELECT, INSERT ON run_tasks TO aisw_app;
    GRANT UPDATE (status, attempts, available_at, locked_by, locked_until, started_at,
      completed_at, warnings, errors, output_refs, tool_version) ON run_tasks TO aisw_app;
    GRANT SELECT, INSERT ON run_events TO aisw_app;
    GRANT SELECT, INSERT ON evidence_artifacts TO aisw_app;
    GRANT SELECT, INSERT ON assets TO aisw_app;
    GRANT UPDATE (run_id, last_seen, technology) ON assets TO aisw_app;
    GRANT SELECT, INSERT ON run_asset_status TO aisw_app;
    GRANT SELECT, INSERT ON observations TO aisw_app;
    GRANT SELECT, INSERT ON control_assessments TO aisw_app;
    GRANT SELECT, INSERT ON findings TO aisw_app;
    GRANT UPDATE (assurance_verdict, lifecycle) ON findings TO aisw_app;
    GRANT SELECT, INSERT ON assurance_results TO aisw_app;
    GRANT SELECT, INSERT ON coverage_ledger TO aisw_app;
    GRANT SELECT, INSERT ON reports TO aisw_app;
    GRANT UPDATE (approval_state, approved_by, approved_at) ON reports TO aisw_app;
    """)


def downgrade() -> None:
    for t in reversed(TENANT_TABLES):
        op.execute(f"DROP TABLE IF EXISTS {t} CASCADE")
    op.execute("DROP FUNCTION IF EXISTS aisw_immutable_rows()")
