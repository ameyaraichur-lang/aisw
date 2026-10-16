"""Per-project role grants (migration 0021): extra roles an actor holds on single projects."""

from __future__ import annotations

from dataclasses import replace

from sqlalchemy import Engine, text

from aisw.core.db import tenant_connection
from aisw.core.rbac import ActorContext, Role


def with_project_roles(engine: Engine, actor: ActorContext) -> ActorContext:
    with tenant_connection(engine, actor.tenant_id) as conn:
        rows = conn.execute(
            text(
                "SELECT project_id::text, role FROM project_role_grants "
                "WHERE actor_id=:a AND revoked_at IS NULL ORDER BY project_id, role"
            ),
            {"a": actor.actor_id},
        ).all()
    by_project: dict[str, set[Role]] = {}
    for project_id, role in rows:
        by_project.setdefault(project_id, set()).add(Role(role))
    return replace(
        actor, project_roles=tuple((p, frozenset(r)) for p, r in sorted(by_project.items()))
    )


def project_of_run(engine: Engine, actor: ActorContext, run_id: str) -> ActorContext:
    """The actor scoped to the run's project (unchanged if the run is not visible)."""
    return actor.on(_lookup(engine, actor, "SELECT project_id::text FROM assessment_runs "
                                           "WHERE run_id=:k", run_id))  # fmt: skip


def project_of_manifest(engine: Engine, actor: ActorContext, manifest_id: str) -> ActorContext:
    return actor.on(_lookup(engine, actor, "SELECT project_id::text FROM scope_manifests "
                                           "WHERE manifest_id::text=:k", manifest_id))  # fmt: skip


def project_of_permit(engine: Engine, actor: ActorContext, permit_id: str) -> ActorContext:
    return actor.on(_lookup(engine, actor, "SELECT project_id::text FROM execution_permits "
                                           "WHERE permit_id::text=:k", permit_id))  # fmt: skip


def project_of_report(engine: Engine, actor: ActorContext, report_id: str) -> ActorContext:
    return actor.on(_lookup(engine, actor, "SELECT project_id::text FROM reports "
                                           "WHERE report_id::text=:k", report_id))  # fmt: skip


def project_of_exception(engine: Engine, actor: ActorContext, exception_id: str) -> ActorContext:
    return actor.on(_lookup(engine, actor, "SELECT project_id::text FROM finding_exceptions "
                                           "WHERE exception_id::text=:k", exception_id))  # fmt: skip


def project_of_outbox(engine: Engine, actor: ActorContext, outbox_id: str) -> ActorContext:
    return actor.on(_lookup(engine, actor, "SELECT project_id::text FROM ticket_outbox "
                                           "WHERE outbox_id::text=:k", outbox_id))  # fmt: skip


def _lookup(engine: Engine, actor: ActorContext, sql: str, key: str) -> str | None:
    if not actor.project_roles:
        return None
    with tenant_connection(engine, actor.tenant_id) as conn:
        value = conn.execute(text(sql), {"k": key}).scalar()
    return str(value) if value is not None else None
