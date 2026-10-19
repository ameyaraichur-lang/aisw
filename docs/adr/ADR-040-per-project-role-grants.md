# ADR-040: Per-project role grants on top of tenant-wide roles

**Status:** Accepted

## Context
Roles were tenant-wide: an external auditor or a contractor who should see one project could only be given a role over the whole tenant (threat model T2, "roles are coarse").

## Decision
1. **Grants only add.** A project role grant gives one person one role on one project. The effective permissions on that project are the tenant roles plus the grants for it; a grant never removes a tenant role and never applies to any other project. With no grants, behaviour is exactly as before.
2. **Grantable roles are limited** to assessment operator, approver, reviewer and report reader. Project admin, auditor, policy owner and tenant admin stay tenant-wide, so a project grant cannot hand out grant rights, audit-chain access or policy ownership.
3. **Who grants.** Only a tenant-wide holder of `project:members` (project admin) may grant or revoke; nobody may grant to themselves (API 403 and a database `CHECK`). Every grant needs a reason and is audited (`project.role.grant`, `project.role.revoke`).
4. **The database holds the record.** Migration 0021 adds `project_role_grants` (forced RLS by tenant). Rows cannot be deleted; a grant can be revoked once (`revoked_by`, `revoked_at` set together, never changed again) and a partial unique index allows one active grant per person, project and role.
5. **Where it is enforced.** `get_actor` loads the caller's active grants. Every route that acts on one project resolves the project first (directly, or from the run, manifest, permit, report, exception or outbox item) and authorises with `actor.on(project_id)`. Separation of duties is unchanged: an approver grant still cannot approve a manifest the same person requested.
6. **The console follows the server.** `/me` returns `project_roles` and `project_permissions`; `can(permission, projectId)` checks the project when one is known. Project-only members see only their projects on the Projects page. The page shows a Roles panel per project with the grant form for project admins.

## Known limitations
- Tenant-wide lists and dashboards (Findings, Assets, Roadmap, Assurance, Audit, Coverage, Tickets, Retention) still need a tenant role; a project-only member reaches their project from the Projects page and the run links.
- Retention holds and execution remain tenant-wide (`retention:manage`).
- Grants have no expiry; revocation is manual.
- OIDC group claims are not mapped to project grants; grants are made in the console.
