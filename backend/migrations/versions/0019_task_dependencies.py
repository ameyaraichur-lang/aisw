"""Task dependencies within a run.

Inventory imports (CMDB, NetBox, ServiceNow) must finish before scanner and configuration imports
resolve hosts against the canonical assets. `depends_on` lists the task ids a task waits for.

Revision ID: 0019
"""

from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE run_tasks ADD COLUMN depends_on jsonb NOT NULL DEFAULT '[]'::jsonb")


def downgrade() -> None:
    op.execute("ALTER TABLE run_tasks DROP COLUMN depends_on")
