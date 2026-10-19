"""Ticket rendering and delivery (ADR-037).

Rendering is a preview and never sends. Delivery is off unless ``enable_itsm_ticket_delivery`` is
set, and a draft is sent by an approver other than the one who drafted it. Each attempt claims the
row first (DRAFT/FAILED -> SENDING) so two requests cannot send at once; the ITSM call runs outside
the transaction; a retry looks the correlation key up before creating, so it never duplicates.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import Engine, text

from aisw.api.analysis import _c
from aisw.api.container import Container
from aisw.api.deps import correlation_id, get_actor, get_engine
from aisw.contracts.base import canonical_hash
from aisw.core.audit import append_audit
from aisw.core.db import tenant_connection
from aisw.core.project_roles import project_of_outbox
from aisw.core.rbac import ActorContext, Permission, authorize
from aisw.itsm import render as itsm
from aisw.itsm.delivery import DeliveryError, client_from_settings

router = APIRouter(prefix="/api/v1")
MAX_ATTEMPTS = 5
DRAFT_SQL = (
    "SELECT payload, status, target, attempts, attempted_at, created_by, external_ref, "
    "external_url, last_error FROM ticket_outbox WHERE outbox_id=CAST(:o AS uuid)"
)


def _draft(conn: Any, outbox_id: str, *, lock: bool = False) -> Any:
    try:
        return conn.execute(
            text(DRAFT_SQL + (" FOR UPDATE" if lock else "")),  # noqa: S608
            {"o": outbox_id},
        ).first()  # fmt: skip
    except Exception:  # a malformed uuid is simply not found
        return None


@router.get("/tickets/drafts/{outbox_id}/render")
def render_draft(
    outbox_id: str,
    target: itsm.Target | None = Query(default=None),
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
) -> dict[str, Any]:
    actor = project_of_outbox(engine, actor, outbox_id)
    authorize(actor, Permission.FINDING_READ)
    s = c.settings
    with tenant_connection(engine, actor.tenant_id) as conn:
        row = _draft(conn, outbox_id)
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    chosen = target or row[2] or s.itsm_target or "jira"
    return {
        "outbox_id": outbox_id,
        "target": chosen,
        "correlation_key": itsm.correlation_key(outbox_id),
        "payload": itsm.render(
            chosen,
            row[0],
            outbox_id,
            jira_project_key=s.itsm_jira_project_key,
            jira_issue_type=s.itsm_jira_issue_type,
        ),  # fmt: skip
        "delivery_enabled": s.enable_itsm_ticket_delivery,
        "configured_target": s.itsm_target if s.enable_itsm_ticket_delivery else None,
        "sent": row[1] == "SENT",
    }


def _view(outbox_id: str, row: Any) -> dict[str, Any]:
    return {"outbox_id": outbox_id, "status": row[1], "target": row[2], "attempts": row[3],
            "external_ref": row[6], "external_url": row[7], "last_error": row[8]}  # fmt: skip


@router.post("/tickets/drafts/{outbox_id}/send")
def send_draft(
    outbox_id: str,
    response: Response,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    actor = project_of_outbox(engine, actor, outbox_id)
    authorize(actor, Permission.RECOMMENDATION_DECIDE)
    s = c.settings
    if not s.enable_itsm_ticket_delivery:
        raise HTTPException(
            status_code=403, detail="ticket delivery is disabled (enable_itsm_ticket_delivery)"
        )
    client = client_from_settings(s)
    now = c.clock()
    stale = timedelta(seconds=2 * s.itsm_timeout_seconds + 30)
    with tenant_connection(engine, actor.tenant_id) as conn:
        row = _draft(conn, outbox_id, lock=True)
        if row is None:
            raise HTTPException(status_code=404, detail="not found")
        payload, status, target, attempts, attempted_at, created_by = row[:6]
        if status == "SENT":
            response.headers["Idempotent-Replay"] = "true"
            return {**_view(outbox_id, row), "created": False}
        if created_by == actor.actor_id:
            raise HTTPException(
                status_code=403, detail="a draft is sent by an approver other than its author"
            )
        if target is not None and target != client.target:
            raise HTTPException(status_code=409, detail=f"this draft was already sent to {target}")
        if status == "SENDING" and attempted_at is not None and now - attempted_at < stale:
            raise HTTPException(status_code=409, detail="a delivery attempt is in progress")
        if attempts >= MAX_ATTEMPTS:
            raise HTTPException(status_code=409, detail="delivery attempt limit reached")
        conn.execute(
            text("UPDATE ticket_outbox SET status='SENDING', target=:g, attempts=attempts+1, "
                 "attempted_at=:n, last_error=NULL WHERE outbox_id=CAST(:o AS uuid)"),
            {"g": client.target, "n": now, "o": outbox_id},
        )  # fmt: skip
    rendered = itsm.render(client.target, payload, outbox_id,
                           jira_project_key=s.itsm_jira_project_key,
                           jira_issue_type=s.itsm_jira_issue_type)  # fmt: skip
    error: DeliveryError | None = None
    try:
        done = client.deliver(outbox_id, rendered)
    except DeliveryError as exc:
        error = exc
    with tenant_connection(engine, actor.tenant_id) as conn:
        if error is None:
            conn.execute(
                text("UPDATE ticket_outbox SET status='SENT', external_ref=:x, external_url=:u, "
                     "sent_by=:by, sent_at=:n WHERE outbox_id=CAST(:o AS uuid)"),
                {"x": done.external_ref, "u": done.url, "by": actor.actor_id, "n": c.clock(),
                 "o": outbox_id},
            )  # fmt: skip
        else:
            conn.execute(
                text("UPDATE ticket_outbox SET status='FAILED', last_error=:e "
                     "WHERE outbox_id=CAST(:o AS uuid)"),
                {"e": error.code, "o": outbox_id},
            )  # fmt: skip
        append_audit(
            conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="ticket.send",
            resource=f"ticket:{outbox_id}", result="SUCCESS" if error is None else "FAILURE",
            correlation_id=cid, after_hash=canonical_hash(
                {"target": client.target, "external_ref": done.external_ref} if error is None
                else {"target": client.target, "error": error.code}),
        )  # fmt: skip
        row = _draft(conn, outbox_id)
    if error is not None:
        raise HTTPException(
            status_code=502, detail={"code": error.code, "retryable": error.retryable}
        )
    response.status_code = 201 if done.created else 200
    return {**_view(outbox_id, row), "created": done.created}
