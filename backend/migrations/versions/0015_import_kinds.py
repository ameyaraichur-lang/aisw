"""Import kinds for the configuration, inventory and vulnerability importers (ADR-034).

Revision ID: 0015
"""

from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

BEFORE = ("cmdb_csv", "cmdb_json", "prowler_json", "greenbone_xml", "openscap_xccdf", "wazuh_json",
          "nmap_xml", "zap_json")  # fmt: skip
AFTER = (*BEFORE, "aws_security_groups_json", "iptables_save", "kubescape_json", "k8s_rbac_json",
         "ad_users_csv", "ldif", "aws_credential_report_csv", "netbox_json", "servicenow_json",
         "nessus_xml", "tenable_json", "qualys_xml", "trivy_json")  # fmt: skip


def _check(kinds: tuple[str, ...], suffix: str = "") -> None:
    listed = ",".join(f"'{k}'" for k in kinds)
    op.execute(f"""
    ALTER TABLE imports DROP CONSTRAINT imports_kind_check;
    ALTER TABLE imports ADD CONSTRAINT imports_kind_check CHECK (kind IN ({listed})){suffix};
    """)  # noqa: S608


def upgrade() -> None:
    _check(AFTER)


def downgrade() -> None:
    _check(BEFORE, " NOT VALID")  # uploads of the newer kinds are evidence and stay readable
