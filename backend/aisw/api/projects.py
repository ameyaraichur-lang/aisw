"""Projects API: first endpoints exercising auth, RBAC, tenant RLS, idempotency and audit."""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import Field
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError

from aisw.api.deps import correlation_id, get_actor, get_engine
from aisw.contracts.base import NonEmpty, StrictModel, canonical_hash
from aisw.core.audit import append_audit, verify_chain
from aisw.core.db import tenant_connection
from aisw.core.idempotency import run_idempotent
from aisw.core.rbac import ActorContext, Forbidden, Permission, authorize

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
    authorize(actor, Permission.PROJECT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        rows = conn.execute(text("SELECT * FROM projects ORDER BY created_at")).mappings().all()
    return [_row(r) for r in rows]


@router.get("/projects/{project_id}")
def get_project(
    project_id: uuid.UUID,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> dict[str, Any]:
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
    actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> dict[str, Any]:
    authorize(actor, Permission.AUDIT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        rep = verify_chain(conn, actor.tenant_id)
    return {"ok": rep.ok, "checked": rep.checked, "broken_at_seq": rep.broken_at_seq,
            "reason": rep.reason}  # fmt: skip
