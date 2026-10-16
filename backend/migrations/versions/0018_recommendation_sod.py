"""Separation of duties for recommendation decisions.

Whoever launched a run may not accept or reject its recommendations; deferring stays open to them.
The API refuses first; this trigger makes the rule hold for any writer.

Revision ID: 0018
"""

from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE FUNCTION aisw_recommendation_sod() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.status IN ('APPROVED_FOR_PLANNING','REJECTED') AND NEW.decided_by = (
           SELECT requested_by FROM assessment_runs WHERE run_id = NEW.run_id) THEN
        RAISE EXCEPTION 'separation of duties: the run requester cannot decide its recommendations'
          USING ERRCODE = 'check_violation';
      END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER recommendations_sod BEFORE INSERT OR UPDATE ON recommendations
      FOR EACH ROW EXECUTE FUNCTION aisw_recommendation_sod();
    """)


def downgrade() -> None:
    op.execute("""
    DROP TRIGGER recommendations_sod ON recommendations;
    DROP FUNCTION aisw_recommendation_sod();
    """)
