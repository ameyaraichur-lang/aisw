"""Assessment routes: launch, status, events (cursor replay), cancel, coverage, findings, reports."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pydantic import Field
from sqlalchemy import Engine, text

from aisw.api.container import Container
from aisw.api.deps import correlation_id, get_actor, get_engine
from aisw.api.scope import service
from aisw.authz.service import ScopeDenied, ScopeService
from aisw.contracts.base import NonEmpty, Sha256, Slug, StrictModel
from aisw.core.audit import append_audit
from aisw.core.db import tenant_connection
from aisw.core.rbac import ActorContext, Forbidden, Permission, authorize
from aisw.orchestrator.events import append_event
from aisw.orchestrator.runs import create_run

router = APIRouter(prefix="/api/v1")
TERMINAL_RUN = {"CLOSED", "FAILED", "CANCELLED", "EXPIRED"}


class LaunchRequest(StrictModel):
    project_id: Slug
    scope_manifest_id: Slug
    scope_manifest_hash: Sha256
    assessment_profile: NonEmpty
    requested_domains: list[Slug] = Field(default_factory=list)
    report_profile: NonEmpty | None = None
    adapter_params: dict[Slug, dict[str, Any]] = Field(default_factory=dict)
    client_context: dict[str, str] = Field(default_factory=dict)
    ai_assist: bool = False  # opt-in per run; honoured only when AI is enabled in settings


class ReportApprove(StrictModel):
    report_hash: Sha256


def _container(request: Request) -> Container:
    c: Container | None = request.app.state.container
    if c is None or c.service is None or c.evidence is None:
        raise HTTPException(
            status_code=503, detail="signing and evidence storage are not configured"
        )
    return c


def _run_or_404(conn: Any, run_id: str) -> dict[str, Any]:
    row = (
        conn.execute(text("SELECT * FROM assessment_runs WHERE run_id=:r"), {"r": run_id})
        .mappings()
        .first()
    )
    if row is None:  # also another tenant's run (RLS): no existence oracle
        raise HTTPException(status_code=404, detail="not found")
    return dict(row)


@router.post("/assessments", status_code=202)
def launch(
    body: LaunchRequest,
    response: Response,
    actor: ActorContext = Depends(get_actor),
    c: Container = Depends(_container),
    svc: ScopeService = Depends(service),
    cid: str = Depends(correlation_id),
    idempotency_key: str | None = Header(default=None),
) -> dict[str, Any]:
    try:
        authorize(actor, Permission.ASSESSMENT_LAUNCH)
    except Forbidden:
        svc._audit_denied(actor, "assessment.launch", "authz", cid, ["ROLE_NOT_PERMITTED"])
        raise
    if not idempotency_key or len(idempotency_key) > 200:
        raise HTTPException(status_code=400, detail="Idempotency-Key header is required")

    def hook(conn: Any, run_id: str, permit: Any, manifest: Any) -> None:
        if c.packs.get(manifest.body.policy_version) is None:
            raise ScopeDenied(["POLICY_PACK_UNKNOWN"])
        if body.requested_domains and not set(body.requested_domains) <= set(manifest.body.domains):
            raise ScopeDenied(["DOMAIN_NOT_IN_MANIFEST"])
        if not set(body.adapter_params) <= set(manifest.body.allowed_adapters):
            raise ScopeDenied(["ADAPTER_PARAMS_FOR_UNLISTED_ADAPTER"])
        if body.ai_assist and not c.settings.ai_enabled:
            raise ScopeDenied(["AI_NOT_ENABLED"])
        create_run(
            conn, run_id=run_id, manifest=manifest, permit=permit, requested_by=actor.actor_id,
            assessment_profile=body.assessment_profile, adapter_params=body.adapter_params,
            registry=c.registry, now=c.clock(),
            ai_mode="enabled" if body.ai_assist else "disabled",
        )  # fmt: skip

    auth = svc.authorize_launch(
        actor, project_id=body.project_id, manifest_id=body.scope_manifest_id,
        manifest_hash=body.scope_manifest_hash, task_types=None, idempotency_key=idempotency_key,
        cid=cid, on_authorized=hook,
        request_extra={"profile": body.assessment_profile, "domains": sorted(body.requested_domains),
                       "params": body.adapter_params, "report": body.report_profile,
                       "ai": body.ai_assist},
    )  # fmt: skip
    if auth.replayed:
        response.headers["Idempotent-Replay"] = "true"
    return {
        "run_id": auth.run_id,
        "status": "ACCEPTED",
        "manifest_hash": auth.permit.manifest_hash,
        "created_at": auth.permit.issued_at.isoformat(),
        "status_url": f"/api/v1/assessments/{auth.run_id}",
    }


@router.get("/assessments/{run_id}")
def status(
    run_id: str, actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> dict[str, Any]:
    authorize(actor, Permission.PROJECT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        run = _run_or_404(conn, run_id)
        tasks = conn.execute(
            text("SELECT status, count(*) FROM run_tasks WHERE run_id=:r GROUP BY status"),
            {"r": run_id},
        ).all()
        cursor = conn.execute(
            text("SELECT COALESCE(MAX(seq),0) FROM run_events WHERE run_id=:r"), {"r": run_id}
        ).scalar_one()
        report = conn.execute(
            text("SELECT report_id, approval_state FROM reports WHERE run_id=:r"), {"r": run_id}
        ).first()
    counts = {s: n for s, n in tasks}
    return {
        "run_id": run_id,
        "state": run["state"],
        "last_phase": run["last_phase"],
        "reason": run["reason"],
        "partial": run["partial"],
        "cancel_requested": run["cancel_requested"],
        "manifest_hash": run["manifest_hash"],
        "policy_version": run["policy_version"],
        "created_at": run["created_at"].isoformat(),
        "tasks": counts,
        "event_cursor": cursor,
        "report": {"report_id": report[0], "approval_state": report[1]} if report else None,
        # no percentage: progress is only reported when measurable, and here it is task counts
    }


@router.get("/assessments/{run_id}/events")
def events(
    run_id: str,
    cursor: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> dict[str, Any]:
    authorize(actor, Permission.PROJECT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        _run_or_404(conn, run_id)
        rows = conn.execute(
            text(
                "SELECT seq, event_id::text, event_type, payload, occurred_at FROM run_events "
                "WHERE run_id=:r AND seq > :c ORDER BY seq LIMIT :l"
            ),
            {"r": run_id, "c": cursor, "l": limit},
        ).all()
    items = [
        {
            "seq": r[0],
            "event_id": r[1],
            "type": r[2],
            "payload": r[3],
            "occurred_at": r[4].isoformat(),
        }
        for r in rows
    ]
    return {"events": items, "next_cursor": items[-1]["seq"] if items else cursor}


@router.post("/assessments/{run_id}/cancel")
def cancel(
    run_id: str,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_container),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    authorize(actor, Permission.ASSESSMENT_CANCEL)
    now = c.clock()
    with tenant_connection(engine, actor.tenant_id) as conn:
        run = _run_or_404(conn, run_id)
        if run["state"] in TERMINAL_RUN | {"PARTIAL", "REPORT_READY"}:
            raise HTTPException(status_code=409, detail=f"run is already {run['state']}")
        conn.execute(
            text("UPDATE assessment_runs SET cancel_requested=true, updated_at=:n WHERE run_id=:r"),
            {"n": now, "r": run_id},
        )
        queued = conn.execute(
            text(
                "UPDATE run_tasks SET status='CANCELLED', completed_at=:n WHERE run_id=:r "
                "AND status='QUEUED' RETURNING task_id::text"
            ),
            {"n": now, "r": run_id},
        ).all()
        for (tid,) in queued:
            append_event(
                conn, tenant_id=actor.tenant_id, run_id=run_id, now=now, event_type="task.failed",
                payload={"task_id": tid, "status": "CANCELLED", "error_codes": ["CANCEL_REQUESTED"]},
            )  # fmt: skip
        append_audit(
            conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="assessment.cancel",
            resource=f"run:{run_id}", result="SUCCESS", correlation_id=cid,
        )  # fmt: skip
    return {"run_id": run_id, "cancel_requested": True, "queued_tasks_cancelled": len(queued)}


@router.get("/assessments/{run_id}/coverage")
def coverage(
    run_id: str, actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> dict[str, Any]:
    authorize(actor, Permission.PROJECT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        run = _run_or_404(conn, run_id)
        rows = conn.execute(
            text("SELECT body FROM coverage_ledger WHERE run_id=:r ORDER BY segment"), {"r": run_id}
        ).all()
    segments = [r[0] for r in rows]
    final = run["state"] in TERMINAL_RUN | {"PARTIAL", "REPORT_READY"}
    return {
        "run_id": run_id,
        "segments": segments,
        "final": final,  # incomplete totals are not final
        "complete": final and bool(segments) and all(_is_complete(s) for s in segments),
    }


def _is_complete(s: dict[str, Any]) -> bool:
    return bool(
        s["source_ok"]
        and s["unknown_count"] == 0
        and s["unsupported_count"] == 0
        and s["reconciled_count"] + s["excluded_count"] >= s["expected_count"]
    )


@router.get("/assessments/{run_id}/findings")
def findings(
    run_id: str,
    verdict: list[str] = Query(default_factory=lambda: ["ACCEPT", "NEEDS_REVIEW"]),
    severity: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> dict[str, Any]:
    authorize(actor, Permission.FINDING_READ)
    if not set(verdict) <= {"ACCEPT", "NEEDS_REVIEW", "REJECT"}:
        raise HTTPException(status_code=422, detail="unknown verdict filter")
    if "REJECT" in verdict:
        authorize(actor, Permission.AUDIT_READ)  # rejected candidates are for auditors only
    with tenant_connection(engine, actor.tenant_id) as conn:
        _run_or_404(conn, run_id)
        rows = conn.execute(
            text(
                "SELECT body, assurance_verdict, count(*) OVER () FROM findings WHERE run_id=:r "
                "AND assurance_verdict = ANY(:v) AND (CAST(:s AS text) IS NULL OR severity=:s) "
                "ORDER BY finding_id LIMIT :l OFFSET :o"
            ),
            {"r": run_id, "v": verdict, "s": severity, "l": limit, "o": offset},
        ).all()
    return {
        "items": [
            {**r[0], "assurance_verdict": r[1], "authoritative": r[1] == "ACCEPT"} for r in rows
        ],
        "total": rows[0][2] if rows else 0,
    }


@router.get("/assessments/{run_id}/reports")
def list_reports(
    run_id: str, actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> list[dict[str, Any]]:
    authorize(actor, Permission.REPORT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        _run_or_404(conn, run_id)
        rows = conn.execute(
            text(
                "SELECT report_id, approval_state, report_hash, generated_at, "
                "(body->>'coverage_complete')::boolean FROM reports WHERE run_id=:r"
            ),
            {"r": run_id},
        ).all()
    return [
        {"report_id": r[0], "approval_state": r[1], "report_hash": r[2],
         "generated_at": r[3].isoformat(), "coverage_complete": r[4]}
        for r in rows
    ]  # fmt: skip


@router.get("/reports/{report_id}")
def get_report(
    report_id: str,
    format: str = Query(default="json", pattern="^(json|html)$"),  # noqa: A002
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> Response:
    authorize(actor, Permission.REPORT_READ)  # checked again at download time
    with tenant_connection(engine, actor.tenant_id) as conn:
        row = conn.execute(
            text("SELECT body, html, report_hash FROM reports WHERE report_id=:i"), {"i": report_id}
        ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    headers = {"X-Report-Hash": row[2], "X-Content-Type-Options": "nosniff",
               "Content-Security-Policy": "default-src 'none'"}  # fmt: skip
    if format == "html":
        return Response(row[1], media_type="text/html", headers=headers)
    return Response(json.dumps(row[0]), media_type="application/json", headers=headers)


@router.post("/reports/{report_id}/approve")
def approve_report(
    report_id: str,
    body: ReportApprove,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_container),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    authorize(actor, Permission.REPORT_APPROVE)
    now = c.clock()
    with tenant_connection(engine, actor.tenant_id) as conn:
        row = conn.execute(
            text(
                "SELECT r.run_id, r.report_hash, r.approval_state, a.requested_by, a.state "
                "FROM reports r JOIN assessment_runs a ON a.run_id = r.run_id "
                "WHERE r.report_id=:i FOR UPDATE OF r"
            ),
            {"i": report_id},
        ).first()
        if row is None:
            raise HTTPException(status_code=404, detail="not found")
        run_id, current_hash, state, requested_by, run_state = row
        if body.report_hash != current_hash:
            raise HTTPException(status_code=409, detail="report hash does not match current report")
        if state != "PENDING" or run_state not in {"REPORT_READY", "PARTIAL"}:
            raise HTTPException(status_code=409, detail="report is not awaiting approval")
        if requested_by == actor.actor_id:
            raise Forbidden("requester cannot approve their own report")
        conn.execute(
            text(
                "UPDATE reports SET approval_state='APPROVED', approved_by=:a, approved_at=:n "
                "WHERE report_id=:i"
            ),
            {"a": actor.actor_id, "n": now, "i": report_id},
        )
        conn.execute(
            text("UPDATE assessment_runs SET state='CLOSED', updated_at=:n WHERE run_id=:r"),
            {"n": now, "r": run_id},
        )
        append_event(
            conn, tenant_id=actor.tenant_id, run_id=run_id, now=now, event_type="assessment.closed",
            payload={"final_status": "CLOSED", "remaining_tasks": 0, "reason": "REPORT_APPROVED",
                     "time": now.isoformat()},
        )  # fmt: skip
        append_audit(
            conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="report.approve",
            resource=f"report:{report_id}", result="SUCCESS", correlation_id=cid,
            after_hash=current_hash,
        )  # fmt: skip
    return {"report_id": report_id, "approval_state": "APPROVED", "run_state": "CLOSED"}
