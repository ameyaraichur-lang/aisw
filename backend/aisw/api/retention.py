"""Retention API: dry-run plan, hash-pinned execution, legal holds. Soft purge only (ADR-019)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError

from aisw.api.assessments import _run_or_404
from aisw.api.container import Container
from aisw.api.deps import correlation_id, get_actor, get_engine
from aisw.contracts.base import NonEmpty, Sha256, StrictModel, canonical_hash
from aisw.core.audit import append_audit
from aisw.core.db import tenant_connection
from aisw.core.rbac import ActorContext, Permission, authorize
from aisw.core.redaction import redact_text
from aisw.evidence import retention

router = APIRouter(prefix="/api/v1")


def _c(request: Request) -> Container:
    c: Container | None = request.app.state.container
    if c is None or c.evidence is None:
        raise HTTPException(status_code=503, detail="not configured")
    return c


class ExecuteRequest(StrictModel):
    plan_hash: Sha256
    reason: NonEmpty


class HoldRequest(StrictModel):
    reason: NonEmpty


@router.get("/retention/plan")
def plan(
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
) -> dict[str, Any]:
    authorize(actor, Permission.RETENTION_MANAGE)
    p = retention.build_plan(
        engine, actor.tenant_id, c.clock(), import_retention_days=c.settings.evidence_retention_days
    )
    return p.summary()


@router.post("/retention/execute")
def execute(
    body: ExecuteRequest,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    authorize(actor, Permission.RETENTION_MANAGE)
    store = c.evidence
    if store is None:
        raise HTTPException(status_code=503, detail="evidence storage not configured")
    now = c.clock()
    days = c.settings.evidence_retention_days
    current = retention.build_plan(engine, actor.tenant_id, now, import_retention_days=days)
    if current.plan_hash != body.plan_hash:
        raise HTTPException(
            status_code=409, detail="the plan changed since you reviewed it; fetch it again"
        )
    reason = redact_text(body.reason)[:1000]
    try:
        out = retention.execute(
            engine, store, current, actor=actor.actor_id, reason=reason, now=now,
            import_retention_days=days,
        )  # fmt: skip
    except retention.PlanChanged as exc:
        raise HTTPException(status_code=409, detail="the plan changed during execution") from exc
    with tenant_connection(engine, actor.tenant_id) as conn:
        append_audit(
            conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="retention.purge",
            resource=f"plan:{current.plan_hash}", result="SUCCESS", correlation_id=cid,
            after_hash=canonical_hash({"items": out.items, "moved": out.moved_blobs}),
        )  # fmt: skip
    return {"plan_hash": current.plan_hash, "items": out.items, "blobs_moved_to_quarantine": out.moved_blobs,
            "blobs_not_found": out.missing_blobs, "deleted": 0}  # fmt: skip


@router.get("/retention/actions")
def actions(
    actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> list[dict[str, Any]]:
    authorize(actor, Permission.AUDIT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        rows = conn.execute(
            text("SELECT kind, ref, content_hash, size_bytes, quarantined, executed_by, executed_at, "
                 "reason, plan_hash FROM retention_actions ORDER BY executed_at DESC, ref LIMIT 500")
        ).all()  # fmt: skip
    return [
        {"kind": r[0], "ref": r[1], "content_hash": r[2], "size_bytes": r[3], "quarantined": r[4],
         "executed_by": r[5], "executed_at": r[6].isoformat(), "reason": r[7], "plan_hash": r[8]}
        for r in rows
    ]  # fmt: skip


@router.post("/assessments/{run_id}/retention-hold", status_code=201)
def place_hold(
    run_id: str,
    body: HoldRequest,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    authorize(actor, Permission.RETENTION_MANAGE)
    try:
        with tenant_connection(engine, actor.tenant_id) as conn:
            _run_or_404(conn, run_id)
            conn.execute(
                text("INSERT INTO retention_holds (tenant_id, run_id, reason, placed_by, placed_at) "
                     "VALUES (:t, :r, :why, :by, :n)"),
                {"t": actor.tenant_id, "r": run_id, "why": redact_text(body.reason)[:1000],
                 "by": actor.actor_id, "n": c.clock()},
            )  # fmt: skip
            append_audit(
                conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="retention.hold",
                resource=f"run:{run_id}", result="SUCCESS", correlation_id=cid,
            )  # fmt: skip
    except IntegrityError as exc:
        raise HTTPException(
            status_code=409, detail="a hold is already active for this run"
        ) from exc
    return {"run_id": run_id, "hold": "ACTIVE"}


@router.post("/assessments/{run_id}/retention-hold/release")
def release_hold(
    run_id: str,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    authorize(actor, Permission.RETENTION_MANAGE)
    with tenant_connection(engine, actor.tenant_id) as conn:
        _run_or_404(conn, run_id)
        n = conn.execute(
            text("UPDATE retention_holds SET released_by=:by, released_at=:n "
                 "WHERE run_id=:r AND released_at IS NULL"),
            {"by": actor.actor_id, "n": c.clock(), "r": run_id},
        ).rowcount  # fmt: skip
        if not n:
            raise HTTPException(status_code=409, detail="no active hold")
        append_audit(
            conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="retention.release",
            resource=f"run:{run_id}", result="SUCCESS", correlation_id=cid,
        )  # fmt: skip
    return {"run_id": run_id, "hold": "RELEASED"}
