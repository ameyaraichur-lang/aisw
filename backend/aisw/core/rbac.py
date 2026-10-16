"""Roles, permissions and separation of duties. Server-side authority; UI hiding is not security."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Role(StrEnum):
    PROJECT_ADMIN = "project_admin"
    CONNECTOR_ADMIN = "connector_admin"
    ASSESSMENT_OPERATOR = "assessment_operator"
    APPROVER = "approver"
    REVIEWER = "reviewer"
    REPORT_READER = "report_reader"
    AUDITOR = "auditor"
    POLICY_OWNER = "policy_owner"


class Permission(StrEnum):
    PROJECT_CREATE = "project:create"
    PROJECT_READ = "project:read"
    CONNECTOR_MANAGE = "connector:manage"
    INVENTORY_MANAGE = "inventory:manage"
    IMPORT_CREATE = "import:create"
    MANIFEST_CREATE = "manifest:create"
    MANIFEST_APPROVE = "manifest:approve"
    ASSESSMENT_LAUNCH = "assessment:launch"
    ASSESSMENT_CANCEL = "assessment:cancel"
    FINDING_READ = "finding:read"
    REPORT_READ = "report:read"
    REPORT_APPROVE = "report:approve"
    RECOMMENDATION_DECIDE = "recommendation:decide"
    AUDIT_READ = "audit:read"
    POLICY_APPROVE = "policy:approve"


_ALL_READ = {Permission.PROJECT_READ}

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.PROJECT_ADMIN: frozenset(
        {Permission.PROJECT_CREATE, Permission.PROJECT_READ, Permission.INVENTORY_MANAGE}
    ),
    Role.CONNECTOR_ADMIN: frozenset(
        {
            Permission.PROJECT_READ,
            Permission.CONNECTOR_MANAGE,
            Permission.INVENTORY_MANAGE,
            Permission.IMPORT_CREATE,
        }
    ),
    Role.ASSESSMENT_OPERATOR: frozenset(
        {
            Permission.PROJECT_READ,
            Permission.MANIFEST_CREATE,
            Permission.ASSESSMENT_LAUNCH,
            Permission.ASSESSMENT_CANCEL,
            Permission.FINDING_READ,
            Permission.IMPORT_CREATE,
        }
    ),
    Role.APPROVER: frozenset(
        {
            Permission.PROJECT_READ,
            Permission.MANIFEST_APPROVE,
            Permission.RECOMMENDATION_DECIDE,
            Permission.FINDING_READ,
        }
    ),
    Role.REVIEWER: frozenset(
        {
            Permission.PROJECT_READ,
            Permission.FINDING_READ,
            Permission.REPORT_READ,
            Permission.REPORT_APPROVE,
        }
    ),
    Role.REPORT_READER: frozenset(
        {Permission.PROJECT_READ, Permission.FINDING_READ, Permission.REPORT_READ}
    ),
    Role.AUDITOR: frozenset(
        {
            Permission.PROJECT_READ,
            Permission.FINDING_READ,
            Permission.REPORT_READ,
            Permission.AUDIT_READ,
        }
    ),
    Role.POLICY_OWNER: frozenset({Permission.PROJECT_READ, Permission.POLICY_APPROVE}),
}


class Forbidden(PermissionError):
    pass


@dataclass(frozen=True, slots=True)
class ActorContext:
    """Built only from validated server-side identity, never from request bodies or models."""

    tenant_id: str
    actor_id: str
    roles: frozenset[Role]

    def can(self, permission: Permission) -> bool:
        return any(permission in ROLE_PERMISSIONS[r] for r in self.roles)


def authorize(actor: ActorContext, permission: Permission) -> None:
    if not actor.can(permission):
        raise Forbidden(f"missing permission {permission.value}")


def require_separation_of_duties(requester: str, approver: str) -> None:
    if requester == approver:
        raise Forbidden("requester cannot approve their own request")
