"""Upload and list import files. Uploads are data only: nothing runs until an approved manifest
and a launched run feed the file to an allow-listed import adapter through the gateway."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field
from sqlalchemy import Engine, text

from aisw.api.container import Container
from aisw.api.deps import correlation_id, get_actor, get_engine
from aisw.contracts.base import NonEmpty, Slug, StrictModel
from aisw.core.audit import append_audit
from aisw.core.db import tenant_connection
from aisw.core.rbac import ActorContext, Permission, authorize
from aisw.evidence.imports import IMPORT_KINDS, MAX_IMPORT_BYTES, ImportRejected, ImportStore

router = APIRouter(prefix="/api/v1")


class ImportUpload(StrictModel):
    project_id: Slug
    kind: NonEmpty
    filename: NonEmpty
    content: str = Field(min_length=1, max_length=MAX_IMPORT_BYTES)


def _store(request: Request) -> ImportStore:
    c: Container | None = request.app.state.container
    if c is None or c.imports is None:
        raise HTTPException(status_code=503, detail="evidence storage is not configured")
    return c.imports


def _clock(request: Request) -> datetime:
    c: Container = request.app.state.container
    return c.clock()


@router.post("/imports", status_code=201)
def upload_import(
    body: ImportUpload,
    actor: ActorContext = Depends(get_actor),
    store: ImportStore = Depends(_store),
    now: datetime = Depends(_clock),
    engine: Engine = Depends(get_engine),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    authorize(actor, Permission.IMPORT_CREATE)
    if body.kind not in IMPORT_KINDS:
        raise HTTPException(status_code=422, detail="unknown import kind")
    with tenant_connection(engine, actor.tenant_id) as conn:  # project must be this tenant's
        if (
            conn.execute(
                text("SELECT 1 FROM projects WHERE project_id::text=:p"), {"p": body.project_id}
            ).first()
            is None
        ):
            raise HTTPException(status_code=404, detail="project not found")
    try:
        meta = store.upload(
            tenant_id=actor.tenant_id, project_id=body.project_id, actor=actor.actor_id,
            kind=body.kind, filename=body.filename, content=body.content, now=now,
        )  # fmt: skip
    except ImportRejected as exc:
        raise HTTPException(status_code=422, detail=exc.code) from exc
    with tenant_connection(engine, actor.tenant_id) as conn:
        append_audit(
            conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="import.upload",
            resource=f"import:{meta.import_id}", result="SUCCESS", correlation_id=cid,
            after_hash=meta.content_hash,
        )  # fmt: skip
    return {"import_id": meta.import_id, "kind": meta.kind, "filename": meta.filename,
            "content_hash": meta.content_hash, "size_bytes": meta.size_bytes, "redacted": meta.redacted}  # fmt: skip


@router.get("/imports")
def list_imports(
    project_id: str, actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> list[dict[str, Any]]:
    authorize(actor, Permission.PROJECT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        rows = conn.execute(
            text(
                "SELECT import_id, kind, filename, content_hash, size_bytes, redacted, uploaded_by, "
                "uploaded_at FROM imports WHERE project_id::text=:p ORDER BY uploaded_at DESC LIMIT 100"
            ),
            {"p": project_id},
        ).all()
    return [
        {"import_id": r[0], "kind": r[1], "filename": r[2], "content_hash": r[3], "size_bytes": r[4],
         "redacted": r[5], "uploaded_by": r[6], "uploaded_at": r[7].isoformat()}
        for r in rows
    ]  # fmt: skip
