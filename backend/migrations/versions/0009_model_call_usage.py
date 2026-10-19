"""Model-call usage and latency provenance (ADR-023).

Each llm_calls row records the tokens the provider reported, the wall-clock latency over all
attempts, and whether the reply came from a recorded replay instead of a live model. The deployment
that actually served the call is the existing model_id column.

Revision ID: 0009
"""

from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    ALTER TABLE llm_calls
      ADD COLUMN input_tokens int CHECK (input_tokens >= 0),
      ADD COLUMN output_tokens int CHECK (output_tokens >= 0),
      ADD COLUMN latency_ms int NOT NULL DEFAULT 0 CHECK (latency_ms >= 0),
      ADD COLUMN replayed boolean NOT NULL DEFAULT false;
    """)


def downgrade() -> None:
    op.execute("""
    ALTER TABLE llm_calls
      DROP COLUMN replayed, DROP COLUMN latency_ms, DROP COLUMN output_tokens,
      DROP COLUMN input_tokens;
    """)
