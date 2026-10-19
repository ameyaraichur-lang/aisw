"""Projects API: first endpoints exercising auth, RBAC, tenant RLS, idempotency and audit."""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import Field
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError

from aisw.api.container import Container
from aisw.api.deps import correlation_id, get_actor, get_engine
from aisw.api.views import _c as views_container
from aisw.contracts.base import NonEmpty, StrictModel, canonical_hash
from aisw.core.anchor import verify_anchors
from aisw.core.audit import append_audit, verify_chain
from aisw.core.db import tenant_connection
from aisw.core.idempotency import run_idempotent
from aisw.core.rbac import PROJECT_GRANTABLE, ActorContext, Forbidden, Permission, Role, authorize
from aisw.core.redaction import redact_text

router = APIRouter(prefix="/api/v1")


class ProjectCreate(StrictModel):
    name: NonEmpty
    environment: NonEmpty
    owner: NonEmpty | None = None
    business_context: dict[str, Any] = Field(default_factory=dict)


def _deny(engine: Engine, actor: ActorContext, action: str, cid: str, exc: Forbidden) -> None:
    with tenant_connection(engine, actor.tenant_id) as conn:
        append_audit(
            conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action=action,
            resource="projects", result="DENIED", correlation_id=cid,
        )  # fmt: skip
    raise exc


def _row(r: Any) -> dict[str, Any]:
    return {
        "project_id": str(r["project_id"]),
        "name": r["name"],
        "environment": r["environment"],
        "owner": r["owner"],
        "business_context": r["business_context"],
        "created_by": r["created_by"],
    }


@router.post("/projects", status_code=201)
def create_project(
    body: ProjectCreate,
    request: Request,
    response: Response,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    cid: str = Depends(correlation_id),
    idempotency_key: str | None = Header(default=None),
) -> dict[str, Any]:
    try:
        authorize(actor, Permission.PROJECT_CREATE)
    except Forbidden as exc:
        _deny(engine, actor, "project.create", cid, exc)
    if not idempotency_key or len(idempotency_key) > 200:
        raise HTTPException(status_code=400, detail="Idempotency-Key header is required")

    payload = body.model_dump(mode="json")
    with tenant_connection(engine, actor.tenant_id) as conn:

        def handler() -> tuple[int, dict[str, Any]]:
            try:
                with conn.begin_nested():
                    row = (
                        conn.execute(
                            text(
                                "INSERT INTO projects (tenant_id, name, environment, owner, "
                                "business_context, created_by) VALUES (:t, :n, :e, :o, "
                                "CAST(:c AS jsonb), :by) RETURNING *"
                            ),
                            {
                                "t": actor.tenant_id,
                                "n": body.name,
                                "e": body.environment,
                                "o": body.owner,
                                "c": json.dumps(body.business_context),
                                "by": actor.actor_id,
                            },
                        )
                        .mappings()
                        .one()
                    )
            except IntegrityError as exc:
                raise HTTPException(status_code=409, detail="project name already exists") from exc
            out = _row(row)
            append_audit(
                conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="project.create",
                resource=f"project:{out['project_id']}", result="SUCCESS", correlation_id=cid,
                after_hash=canonical_hash(out),
            )  # fmt: skip
            return 201, out

        result = run_idempotent(
            conn, tenant_id=actor.tenant_id, actor=actor.actor_id, scope="POST /projects",
            key=idempotency_key, request_body=payload, handler=handler,
        )  # fmt: skip
    response.status_code = result.status_code
    if result.replayed:
        response.headers["Idempotent-Replay"] = "true"
    return result.body


@router.get("/projects")
def list_projects(
    actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> list[dict[str, Any]]:
    if actor.can(Permission.PROJECT_READ):
        mine = None
    else:  # project-only members see the projects they hold a role on
        mine = sorted(p for p, _ in actor.project_roles if actor.on(p).can(Permission.PROJECT_READ))
        if not mine:
            authorize(actor, Permission.PROJECT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT * FROM projects WHERE CAST(:m AS text[]) IS NULL "
                    "OR project_id::text = ANY(CAST(:m AS text[])) ORDER BY created_at"
                ),
                {"m": mine},
            )
            .mappings()
            .all()
        )
    return [_row(r) for r in rows]


@router.get("/projects/{project_id}")
def get_project(
    project_id: uuid.UUID,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> dict[str, Any]:
    actor = actor.on(str(project_id))
    authorize(actor, Permission.PROJECT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        row = (
            conn.execute(
                text("SELECT * FROM projects WHERE project_id = :p"), {"p": str(project_id)}
            )
            .mappings()
            .first()
        )
    if row is None:  # also the answer for another tenant's project: no existence oracle
        raise HTTPException(status_code=404, detail="not found")
    return _row(row)


@router.get("/audit/verify")
def audit_verify(
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(views_container),
) -> dict[str, Any]:
    authorize(actor, Permission.AUDIT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        rep = verify_chain(conn, actor.tenant_id)
        anchors = verify_anchors(conn, actor.tenant_id, c.keyring, c.witness)
    return {"ok": rep.ok, "checked": rep.checked, "broken_at_seq": rep.broken_at_seq,
            "reason": rep.reason,
            "anchors": {"ok": anchors.ok, "checked": anchors.checked,
                        "latest_seq": anchors.latest_seq, "latest_at": anchors.latest_at,
                        "witness_id": anchors.witness_id, "problems": anchors.problems,
                        "witness_configured": c.witness is not None}}  # fmt: skip


class RoleGrant(StrictModel):
    actor_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,199}$")
    role: Role
    reason: NonEmpty = Field(max_length=1000)


def _grants(conn: Any, project_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        text("SELECT grant_id::text, actor_id, role, reason, granted_by, granted_at FROM "
             "project_role_grants WHERE project_id::text=:p AND revoked_at IS NULL "
             "ORDER BY actor_id, role"),
        {"p": project_id},
    ).all()  # fmt: skip
    return [
        {"grant_id": r[0], "actor_id": r[1], "role": r[2], "reason": r[3], "granted_by": r[4],
         "granted_at": r[5].isoformat()}
        for r in rows
    ]  # fmt: skip


def _project_or_404(conn: Any, project_id: str) -> None:
    found = conn.execute(
        text("SELECT 1 FROM projects WHERE project_id::text=:p"), {"p": project_id}
    ).first()
    if found is None:
        raise HTTPException(status_code=404, detail="project not found")


@router.get("/projects/{project_id}/roles")
def list_project_roles(
    project_id: str, actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> list[dict[str, Any]]:
    authorize(actor.on(project_id), Permission.PROJECT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        _project_or_404(conn, project_id)
        return _grants(conn, project_id)


@router.post("/projects/{project_id}/roles", status_code=201)
def grant_project_role(
    project_id: str,
    body: RoleGrant,
    request: Request,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    try:
        authorize(actor, Permission.PROJECT_MEMBERS_MANAGE)  # tenant-wide only, never via a grant
    except Forbidden as exc:
        _deny(engine, actor, "project.role.grant", cid, exc)
    if body.role not in PROJECT_GRANTABLE:
        raise HTTPException(
            status_code=422, detail="this role is tenant-wide and cannot be granted per project"
        )
    if body.actor_id == actor.actor_id:
        raise HTTPException(status_code=403, detail="you cannot grant a role to yourself")
    now = request.app.state.container.clock() if request.app.state.container else None
    try:
        with tenant_connection(engine, actor.tenant_id) as conn:
            _project_or_404(conn, project_id)
            grant_id = conn.execute(
                text("INSERT INTO project_role_grants (tenant_id, project_id, actor_id, role, reason, "
                     "granted_by, granted_at) VALUES (:t, CAST(:p AS uuid), :a, :r, :why, :by, "
                     "COALESCE(:n, now())) RETURNING grant_id::text"),
                {"t": actor.tenant_id, "p": project_id, "a": body.actor_id, "r": body.role.value,
                 "why": redact_text(body.reason)[:1000], "by": actor.actor_id, "n": now},
            ).scalar_one()  # fmt: skip
            append_audit(
                conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="project.role.grant",
                resource=f"project:{project_id}", result="SUCCESS", correlation_id=cid,
                after_hash=canonical_hash({"grant": grant_id, "actor": body.actor_id,
                                           "role": body.role.value}),
            )  # fmt: skip
    except IntegrityError as exc:
        raise HTTPException(
            status_code=409, detail="this person already holds that role here"
        ) from exc
    return {"grant_id": grant_id, "actor_id": body.actor_id, "role": body.role.value}


@router.post("/projects/{project_id}/roles/{grant_id}/revoke")
def revoke_project_role(
    project_id: str,
    grant_id: str,
    request: Request,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    try:
        authorize(actor, Permission.PROJECT_MEMBERS_MANAGE)
    except Forbidden as exc:
        _deny(engine, actor, "project.role.revoke", cid, exc)
    now = request.app.state.container.clock() if request.app.state.container else None
    with tenant_connection(engine, actor.tenant_id) as conn:
        n = conn.execute(
            text("UPDATE project_role_grants SET revoked_by=:by, revoked_at=COALESCE(:n, now()) "
                 "WHERE grant_id::text=:g AND project_id::text=:p AND revoked_at IS NULL"),
            {"by": actor.actor_id, "n": now, "g": grant_id, "p": project_id},
        ).rowcount  # fmt: skip
        if not n:
            raise HTTPException(status_code=404, detail="no active grant")
        append_audit(
            conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="project.role.revoke",
            resource=f"project:{project_id}", result="SUCCESS", correlation_id=cid,
            after_hash=canonical_hash({"grant": grant_id}),
        )  # fmt: skip
    return {"grant_id": grant_id, "revoked": True}
