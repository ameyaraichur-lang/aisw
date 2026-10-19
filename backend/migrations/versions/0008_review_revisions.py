"""Human resolution of AI dissents, with assurance and report revisions (ADR-022).

An overruled dissent re-runs assurance as a new revision and produces a new report revision that
supersedes the unapproved one. Earlier assurance results and reports are kept, never rewritten.

Revision ID: 0008
"""

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    ALTER TABLE assessment_runs ADD COLUMN assurance_revision int NOT NULL DEFAULT 1
      CHECK (assurance_revision >= 1);
    GRANT UPDATE (assurance_revision) ON assessment_runs TO aisw_app;

    ALTER TABLE assurance_results ADD COLUMN revision int NOT NULL DEFAULT 1 CHECK (revision >= 1);
    ALTER TABLE assurance_results DROP CONSTRAINT assurance_results_pkey;
    ALTER TABLE assurance_results ADD PRIMARY KEY (run_id, item_ref, revision);

    ALTER TABLE reports ADD COLUMN revision int NOT NULL DEFAULT 1 CHECK (revision >= 1);
    ALTER TABLE reports ADD COLUMN supersedes text REFERENCES reports (report_id);
    ALTER TABLE reports DROP CONSTRAINT reports_run_id_key;
    ALTER TABLE reports ADD CONSTRAINT reports_run_revision_key UNIQUE (run_id, revision);
    ALTER TABLE reports DROP CONSTRAINT reports_approval_state_check;
    ALTER TABLE reports ADD CONSTRAINT reports_approval_state_check
      CHECK (approval_state IN ('PENDING','APPROVED','REJECTED','SUPERSEDED'));

    CREATE TABLE ai_validation_resolutions (
      tenant_id text NOT NULL,
      run_id text NOT NULL,
      target_ref text NOT NULL,
      decision text NOT NULL CHECK (decision IN ('OVERRULE','UPHOLD')),
      reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1000),
      decided_by text NOT NULL,
      decided_at timestamptz NOT NULL,
      assurance_revision int NOT NULL,
      PRIMARY KEY (run_id, target_ref),
      FOREIGN KEY (run_id, target_ref) REFERENCES ai_validations (run_id, target_ref),
      FOREIGN KEY (run_id, tenant_id) REFERENCES assessment_runs (run_id, tenant_id)
    );
    CREATE TRIGGER ai_validation_resolutions_append_only BEFORE UPDATE OR DELETE
      ON ai_validation_resolutions FOR EACH ROW EXECUTE FUNCTION aisw_immutable_rows();
    ALTER TABLE ai_validation_resolutions ENABLE ROW LEVEL SECURITY;
    ALTER TABLE ai_validation_resolutions FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON ai_validation_resolutions
      USING (tenant_id = aisw_current_tenant()) WITH CHECK (tenant_id = aisw_current_tenant());
    GRANT SELECT, INSERT ON ai_validation_resolutions TO aisw_app;
    """)


def downgrade() -> None:
    op.execute("""
    DROP TABLE IF EXISTS ai_validation_resolutions CASCADE;
    DELETE FROM reports WHERE revision > 1;
    ALTER TABLE reports DROP CONSTRAINT reports_approval_state_check;
    UPDATE reports SET approval_state='PENDING' WHERE approval_state='SUPERSEDED';
    ALTER TABLE reports ADD CONSTRAINT reports_approval_state_check
      CHECK (approval_state IN ('PENDING','APPROVED','REJECTED'));
    ALTER TABLE reports DROP CONSTRAINT reports_run_revision_key;
    ALTER TABLE reports ADD CONSTRAINT reports_run_id_key UNIQUE (run_id);
    ALTER TABLE reports DROP COLUMN supersedes;
    ALTER TABLE reports DROP COLUMN revision;
    DELETE FROM assurance_results WHERE revision > 1;
    ALTER TABLE assurance_results DROP CONSTRAINT assurance_results_pkey;
    ALTER TABLE assurance_results ADD PRIMARY KEY (run_id, item_ref);
    ALTER TABLE assurance_results DROP COLUMN revision;
    ALTER TABLE assessment_runs DROP COLUMN assurance_revision;
    """)
