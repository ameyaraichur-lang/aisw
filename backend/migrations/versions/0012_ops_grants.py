"""Let the service roles read the migration head, for the deployment doctor (ADR-029).

Revision ID: 0012
"""

from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("GRANT SELECT ON alembic_version TO aisw_app")


def downgrade() -> None:
    op.execute("REVOKE SELECT ON alembic_version FROM aisw_app")
