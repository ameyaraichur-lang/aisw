"""Agent 4 verification questions, Agent 8 executive summary, Agent 0 scope review (ADR-024).

Narratives gain the purposes 'verification' and 'executive'. A validator dissent about the scope
(target_ref 'scope:...') is a review note, never a hold: the scope gate is enforced in code.

Revision ID: 0010
"""

from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

_DROP_DISSENT_CHECK = """
DO $$
DECLARE c text;
BEGIN
  SELECT conname INTO c FROM pg_constraint
   WHERE conrelid = 'ai_validations'::regclass AND contype = 'c'
     AND pg_get_constraintdef(oid) LIKE '%''DISSENT''::text) = (effect = ''HOLD_FOR_REVIEW''%';
  IF c IS NOT NULL THEN EXECUTE format('ALTER TABLE ai_validations DROP CONSTRAINT %I', c); END IF;
END $$;
"""


def upgrade() -> None:
    op.execute(_DROP_DISSENT_CHECK)
    op.execute("""
    ALTER TABLE ai_validations ADD CONSTRAINT ai_validations_dissent_effect CHECK (
      CASE WHEN target_ref LIKE 'scope:%'
           THEN effect <> 'HOLD_FOR_REVIEW' AND (verdict <> 'DISSENT' OR effect = 'REVIEW_ITEM')
           ELSE (verdict = 'DISSENT') = (effect = 'HOLD_FOR_REVIEW') END);
    ALTER TABLE narratives DROP CONSTRAINT narratives_purpose_check;
    ALTER TABLE narratives ADD CONSTRAINT narratives_purpose_check
      CHECK (purpose IN ('scenario','recommendation','verification','executive'));
    """)


def downgrade() -> None:
    op.execute("""
    DELETE FROM narratives WHERE purpose IN ('verification','executive');
    ALTER TABLE narratives DROP CONSTRAINT narratives_purpose_check;
    ALTER TABLE narratives ADD CONSTRAINT narratives_purpose_check
      CHECK (purpose IN ('scenario','recommendation'));
    ALTER TABLE ai_validations DROP CONSTRAINT ai_validations_dissent_effect;
    """)
    # Scope rows cannot satisfy the stricter 0007 rule; they are review notes only, so drop them.
    op.execute("""
    ALTER TABLE ai_validations DISABLE TRIGGER ai_validations_append_only;
    ALTER TABLE ai_validation_resolutions DISABLE TRIGGER ai_validation_resolutions_append_only;
    DELETE FROM ai_validation_resolutions WHERE target_ref LIKE 'scope:%';
    DELETE FROM ai_validations WHERE target_ref LIKE 'scope:%';
    ALTER TABLE ai_validation_resolutions ENABLE TRIGGER ai_validation_resolutions_append_only;
    ALTER TABLE ai_validations ENABLE TRIGGER ai_validations_append_only;
    """)
    op.execute("""
    ALTER TABLE ai_validations ADD CONSTRAINT ai_validations_check
      CHECK ((verdict = 'DISSENT') = (effect = 'HOLD_FOR_REVIEW'));
    """)
