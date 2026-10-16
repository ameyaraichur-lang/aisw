"""Analysis layer: risk assessments, correlation scenarios, recommendations, AI narratives and
provenance, ticket outbox, and the per-run AI mode.

Revision ID: 0005
"""

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

TABLES = [
    "risk_assessments",
    "correlation_scenarios",
    "recommendations",
    "narratives",
    "llm_calls",
    "ticket_outbox",
]


def upgrade() -> None:
    op.execute("""
    ALTER TABLE assessment_runs ADD COLUMN ai_mode text NOT NULL DEFAULT 'disabled'
      CHECK (ai_mode IN ('disabled','enabled'));

    CREATE TABLE risk_assessments (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      finding_id text NOT NULL,
      rubric_version text NOT NULL,
      tier text CHECK (tier IN ('P0','P1','P2','P3')),
      provisional_tier text NOT NULL CHECK (provisional_tier IN ('P0','P1','P2','P3')),
      basis text NOT NULL CHECK (basis IN ('COMPLETE','NEEDS_POLICY_REVIEW')),
      factors jsonb NOT NULL,
      missing_evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
      rationale text NOT NULL,
      PRIMARY KEY (run_id, finding_id),
      -- a business-risk tier exists only when the rubric inputs were complete: never fabricated
      CHECK ((basis = 'COMPLETE') = (tier IS NOT NULL))
    );

    CREATE TABLE correlation_scenarios (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      scenario_id text NOT NULL,
      asset_id text NOT NULL,
      body jsonb NOT NULL,
      assurance_verdict text CHECK (assurance_verdict IN ('ACCEPT','REJECT','NEEDS_REVIEW')),
      PRIMARY KEY (run_id, scenario_id)
    );

    CREATE TABLE recommendations (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      recommendation_id text NOT NULL,
      project_id uuid NOT NULL,
      status text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','NEEDS_REVIEW',
        'APPROVED_FOR_PLANNING','REJECTED','IMPLEMENTED_PENDING_VALIDATION')),
      assurance_verdict text CHECK (assurance_verdict IN ('ACCEPT','REJECT','NEEDS_REVIEW')),
      body jsonb NOT NULL,
      decided_by text,
      decided_at timestamptz,
      decision_reason text,
      PRIMARY KEY (run_id, recommendation_id),
      -- acceptance is a recorded human decision on an assurance-accepted recommendation
      CHECK (status <> 'APPROVED_FOR_PLANNING' OR (decided_by IS NOT NULL AND decision_reason IS NOT NULL
             AND assurance_verdict = 'ACCEPT'))
    );

    CREATE TABLE narratives (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      narrative_id text NOT NULL,
      purpose text NOT NULL CHECK (purpose IN ('scenario','recommendation')),
      subject_ref text NOT NULL,
      status text NOT NULL CHECK (status IN ('VALIDATED','REJECTED','UNAVAILABLE')),
      body jsonb,
      defects jsonb NOT NULL DEFAULT '[]'::jsonb,
      model_id text,
      prompt_version text,
      input_hash text,
      output_hash text,
      assurance_verdict text CHECK (assurance_verdict IN ('ACCEPT','REJECT','NEEDS_REVIEW')),
      created_at timestamptz NOT NULL,
      PRIMARY KEY (run_id, narrative_id),
      UNIQUE (run_id, purpose, subject_ref)
    );

    CREATE TABLE llm_calls (
      tenant_id text NOT NULL,
      call_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      run_id text NOT NULL,
      purpose text NOT NULL,
      subject_ref text NOT NULL,
      model_id text,
      prompt_version text NOT NULL,
      input_hash text NOT NULL,
      output_hash text,
      status text NOT NULL,
      attempts int NOT NULL,
      defects jsonb NOT NULL DEFAULT '[]'::jsonb,
      created_at timestamptz NOT NULL
    );
    CREATE TRIGGER llm_calls_append_only BEFORE UPDATE OR DELETE ON llm_calls
      FOR EACH ROW EXECUTE FUNCTION aisw_immutable_rows();

    CREATE TABLE ticket_outbox (
      tenant_id text NOT NULL,
      outbox_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      run_id text NOT NULL,
      recommendation_id text NOT NULL,
      project_id uuid NOT NULL,
      status text NOT NULL DEFAULT 'DRAFT' CHECK (status = 'DRAFT'),  -- nothing is ever sent in the MVP
      payload jsonb NOT NULL,
      created_by text NOT NULL,
      created_at timestamptz NOT NULL,
      UNIQUE (tenant_id, run_id, recommendation_id)
    );
    """)
    for t in TABLES:
        op.execute(f"""
        ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;
        ALTER TABLE {t} FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation ON {t}
          USING (tenant_id = aisw_current_tenant()) WITH CHECK (tenant_id = aisw_current_tenant());
        GRANT SELECT, INSERT ON {t} TO aisw_app;
        """)
    op.execute("""
    GRANT UPDATE (assurance_verdict) ON correlation_scenarios TO aisw_app;
    GRANT UPDATE (assurance_verdict) ON narratives TO aisw_app;
    GRANT UPDATE (status, assurance_verdict, decided_by, decided_at, decision_reason) ON recommendations TO aisw_app;
    """)


def downgrade() -> None:
    for t in reversed(TABLES):
        op.execute(f"DROP TABLE IF EXISTS {t} CASCADE")
    op.execute("ALTER TABLE assessment_runs DROP COLUMN ai_mode")
