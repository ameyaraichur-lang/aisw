"""Generic asset attributes (policy applicability) instead of a single technology column.

Revision ID: 0003
"""

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    ALTER TABLE assets ADD COLUMN attrs jsonb NOT NULL DEFAULT '{}'::jsonb
      CHECK (jsonb_typeof(attrs) = 'object');
    GRANT UPDATE (attrs) ON assets TO aisw_app;
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE assets DROP COLUMN attrs")
