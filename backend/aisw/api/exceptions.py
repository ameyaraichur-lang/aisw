"""Finding review actions and exceptions with expiry (ADR-033).

A review changes a finding's lifecycle and nothing else: never its outcome, severity or assurance
verdict. An exception is a time-boxed risk acceptance for one rule on one asset, approved by someone
other than the requester. It changes later runs only, and only while it is in force.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import Engine, text
from sqlalchemy.engine import Connection

from aisw.api.assessments import _run_or_404
from aisw.api.container import Container
from aisw.api.deps import correlation_id, get_actor, get_engine
from aisw.contracts.base import NonEmpty, StrictModel, canonical_hash
from aisw.core.audit import append_audit
from aisw.core.db import tenant_connection
from aisw.core.project_roles import project_of_exception, project_of_run
from aisw.core.rbac import ActorContext, Permission, authorize, require_separation_of_duties
from aisw.core.redaction import redact_text
from aisw.policy import exceptions as exc_rules
from aisw.policy.results import finding_id as make_finding_id

router = APIRouter(prefix="/api/v1")
FINAL_RUN = {"REPORT_READY", "PARTIAL", "CLOSED"}
Action = Literal["CONFIRM", "REJECT", "REOPEN", "REQUEST_EXCEPTION"]
OPEN = {"NEW", "TRIAGED", "REOPENED"}
TRANSITIONS: dict[str, tuple[set[str], str]] = {
    "CONFIRM": ({"NEW", "REOPENED"}, "TRIAGED"),
    "REJECT": (OPEN, "FALSE_POSITIVE"),
    "REOPEN": ({"FALSE_POSITIVE"}, "REOPENED"),
    "REQUEST_EXCEPTION": (OPEN, "EXCEPTION_PENDING"),
}
EXCEPTION_COLS = (
    "exception_id, project_id::text, stable_dedupe_key, rule_id, asset_id, title, source_run_id, "
    "source_finding_id, reason, requested_by, requested_at, expires_at, status, decided_by, "
    "decided_at, decision_reason, revoked_by, revoked_at, revoke_reason"
)


def _c(request: Request) -> Container:
    c: Container | None = request.app.state.container
    if c is None:
        raise HTTPException(status_code=503, detail="not configured")
    return c


def _iso(v: datetime | None) -> str | None:
    return v.isoformat() if v else None


def exception_json(r: Any, now: datetime) -> dict[str, Any]:
    st = exc_rules.state(r[12], r[11], now)
    return {
        "exception_id": r[0], "project_id": r[1], "rule_id": r[3], "asset_id": r[4],
        "title": r[5], "source_run_id": r[6], "source_finding_id": r[7], "reason": r[8],
        "requested_by": r[9], "requested_at": r[10].isoformat(), "expires_at": r[11].isoformat(),
        "status": r[12], "state": st,
        "days_left": max(0, (r[11] - now).days) if st in ("PENDING", "ACTIVE") else None,
        "decided_by": r[13], "decided_at": _iso(r[14]), "decision_reason": r[15],
        "revoked_by": r[16], "revoked_at": _iso(r[17]), "revoke_reason": r[18],
    }  # fmt: skip


def current_exception(conn: Connection, project_id: str, dedupe_key: str) -> Any:
    return conn.execute(
        text(f"SELECT {EXCEPTION_COLS} FROM finding_exceptions WHERE project_id=:p "  # noqa: S608
             "AND stable_dedupe_key=:k ORDER BY requested_at DESC, exception_id DESC LIMIT 1"),
        {"p": project_id, "k": dedupe_key},
    ).first()  # fmt: skip


def review_history(conn: Connection, run_id: str, finding_id: str) -> list[dict[str, Any]]:
    return [
        {"action": r[0], "from": r[1], "to": r[2], "reason": r[3], "actor": r[4],
         "at": r[5].isoformat(), "exception_id": r[6]}
        for r in conn.execute(
            text("SELECT action, from_lifecycle, to_lifecycle, reason, actor, at, exception_id "
                 "FROM finding_reviews WHERE run_id=:r AND finding_id=:f ORDER BY seq"),
            {"r": run_id, "f": finding_id},
        )
    ]  # fmt: skip


def allowed_actions(
    actor: ActorContext, lifecycle: str, verdict: str | None, final: bool
) -> list[str]:
    if not (final and verdict != "REJECT" and actor.can(Permission.FINDING_TRIAGE)):
        return []
    return [a for a, (src, _) in TRANSITIONS.items() if lifecycle in src]


def _record(conn: Connection, actor: ActorContext, *, run_id: str, finding_id: str, action: str,
            before: str, after: str, reason: str, now: datetime,
            exception_id: str | None = None) -> None:  # fmt: skip
    if before != after:
        conn.execute(
            text("UPDATE findings SET lifecycle=:l WHERE run_id=:r AND finding_id=:f"),
            {"l": after, "r": run_id, "f": finding_id},
        )
    conn.execute(
        text("INSERT INTO finding_reviews (review_id, tenant_id, run_id, finding_id, action, "
             "from_lifecycle, to_lifecycle, reason, actor, at, exception_id) VALUES "
             "(:i, :t, :r, :f, :a, :b, :to, :why, :who, :n, :e)"),
        {"i": str(uuid.uuid4()), "t": actor.tenant_id, "r": run_id, "f": finding_id, "a": action,
         "b": before, "to": after, "why": reason, "who": actor.actor_id, "n": now,
         "e": exception_id},
    )  # fmt: skip


class ReviewRequest(StrictModel):
    action: Action
    reason: NonEmpty
    expires_at: datetime | None = None  # REQUEST_EXCEPTION only


@router.post("/assessments/{run_id}/findings/{finding_id}/review")
def review_finding(
    run_id: str,
    finding_id: str,
    body: ReviewRequest,
    response: Response,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    actor = project_of_run(engine, actor, run_id)
    authorize(actor, Permission.FINDING_TRIAGE)
    wants_expiry = body.action == "REQUEST_EXCEPTION"
    if wants_expiry != (body.expires_at is not None):
        raise HTTPException(status_code=422, detail="expires_at is required for, and only for, "
                                                    "an exception request")  # fmt: skip
    reason = redact_text(body.reason)[:1000]
    now = c.clock()
    with tenant_connection(engine, actor.tenant_id) as conn:
        run = _run_or_404(conn, run_id)
        row = conn.execute(
            text("SELECT lifecycle, assurance_verdict, body, stable_dedupe_key, project_id::text "
                 "FROM findings WHERE run_id=:r AND finding_id=:f FOR UPDATE"),
            {"r": run_id, "f": finding_id},
        ).first()  # fmt: skip
        if row is None or (row[1] == "REJECT" and not actor.can(Permission.AUDIT_READ)):
            raise HTTPException(status_code=404, detail="not found")
        lifecycle, verdict, fbody, dkey, project = row
        if verdict == "REJECT":
            raise HTTPException(
                status_code=409, detail="a finding rejected by assurance is not reviewed"
            )
        if run["state"] not in FINAL_RUN:
            raise HTTPException(
                status_code=409, detail="findings are reviewed once the run has finished"
            )
        sources, target = TRANSITIONS[body.action]
        history = review_history(conn, run_id, finding_id)
        last = history[-1] if history else None
        if (
            lifecycle == target
            and last
            and (last["action"], last["reason"]) == (body.action, reason)
        ):
            response.headers["Idempotent-Replay"] = "true"
            return {"finding_id": finding_id, "lifecycle": lifecycle, "replayed": True,
                    "exception_id": last["exception_id"]}  # fmt: skip
        if lifecycle not in sources:
            raise HTTPException(status_code=409,
                                detail=f"cannot {body.action} a finding that is {lifecycle}")  # fmt: skip
        exception_id = None
        if body.expires_at is not None:
            exception_id = _request_exception(
                conn, c, actor, run_id=run_id, finding_id=finding_id, fbody=fbody, dkey=dkey,
                project=project, reason=reason, expires_at=body.expires_at, now=now, cid=cid,
            )  # fmt: skip
        _record(conn, actor, run_id=run_id, finding_id=finding_id, action=body.action,
                before=lifecycle, after=target, reason=reason, now=now, exception_id=exception_id)  # fmt: skip
        append_audit(
            conn, tenant_id=actor.tenant_id, actor=actor.actor_id,
            action=f"finding.{body.action.lower()}", resource=f"finding:{run_id}/{finding_id}",
            result="SUCCESS", correlation_id=cid, before_hash=canonical_hash({"lifecycle": lifecycle}),
            after_hash=canonical_hash({"lifecycle": target, "reason": reason,
                                       "exception_id": exception_id}),
        )  # fmt: skip
    return {"finding_id": finding_id, "lifecycle": target, "exception_id": exception_id}


def _request_exception(conn: Connection, c: Container, actor: ActorContext, *, run_id: str,
                       finding_id: str, fbody: dict[str, Any], dkey: str, project: str, reason: str,
                       expires_at: datetime, now: datetime, cid: str) -> str:  # fmt: skip
    if expires_at.tzinfo is None:
        raise HTTPException(status_code=422, detail="expires_at must include a time zone")
    longest = timedelta(days=c.settings.exception_max_days)
    if not now < expires_at <= now + longest:
        raise HTTPException(status_code=422, detail="an exception must expire in the future and "
                            f"within {c.settings.exception_max_days} days")  # fmt: skip
    pack = c.packs.get(fbody["policy_version"])
    asset = fbody["affected_assets"][0]
    rule = next((r for r in pack.rules if make_finding_id(pack, r.rule_id, asset) == finding_id),
                None) if pack else None  # fmt: skip
    if pack is None or rule is None:
        raise HTTPException(status_code=409, detail="the finding's policy rule cannot be resolved")
    conn.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"exception:{dkey}"})
    prior = current_exception(conn, project, dkey)
    if prior is not None and exc_rules.state(prior[12], prior[11], now) in ("PENDING", "ACTIVE"):
        raise HTTPException(status_code=409, detail="an exception is already pending or in force "
                                                    f"for this rule and asset ({prior[0]})")  # fmt: skip
    exception_id = f"exc-{uuid.uuid4().hex[:16]}"
    conn.execute(
        text("INSERT INTO finding_exceptions (exception_id, tenant_id, project_id, "
             "stable_dedupe_key, pack_id, rule_id, asset_id, title, source_run_id, "
             "source_finding_id, reason, requested_by, requested_at, expires_at) VALUES "
             "(:i, :t, CAST(:p AS uuid), :k, :pk, :rule, :a, :title, :r, :f, :why, :who, :n, :x)"),
        {"i": exception_id, "t": actor.tenant_id, "p": project, "k": dkey, "pk": pack.pack_id,
         "rule": rule.rule_id, "a": asset, "title": fbody["title"], "r": run_id, "f": finding_id,
         "why": reason, "who": actor.actor_id, "n": now, "x": expires_at},
    )  # fmt: skip
    append_audit(
        conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="exception.request",
        resource=f"exception:{exception_id}", result="SUCCESS", correlation_id=cid,
        after_hash=canonical_hash({"key": dkey, "expires_at": expires_at.isoformat(),
                                   "reason": reason}),
    )  # fmt: skip
    return exception_id


@router.get("/exceptions")
def list_exceptions(
    state: str | None = Query(default=None, pattern="^(PENDING|ACTIVE|EXPIRED|REJECTED|REVOKED)$"),
    project_id: str | None = None,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
) -> dict[str, Any]:
    actor = actor.on(project_id)
    authorize(actor, Permission.FINDING_READ)
    now = c.clock()
    with tenant_connection(engine, actor.tenant_id) as conn:
        rows = conn.execute(
            text(f"SELECT {EXCEPTION_COLS}, (SELECT p.name FROM projects p "  # noqa: S608
                 "WHERE p.project_id = finding_exceptions.project_id) FROM finding_exceptions "
                 "WHERE (CAST(:p AS text) IS NULL OR project_id::text = :p) "
                 "ORDER BY requested_at DESC, exception_id DESC LIMIT 500"),
            {"p": project_id},
        ).all()  # fmt: skip
    items = [{**exception_json(r, now), "project_name": r[19]} for r in rows]
    counts = {s: 0 for s in ("PENDING", "ACTIVE", "EXPIRED", "REJECTED", "REVOKED")}
    for i in items:
        counts[i["state"]] += 1
    return {
        "as_of": now.isoformat(), "max_days": c.settings.exception_max_days, "counts": counts,
        "items": [i for i in items if state is None or i["state"] == state],
        "can_decide": actor.can(Permission.EXCEPTION_APPROVE),
    }  # fmt: skip


class DecisionRequest(StrictModel):
    decision: Literal["APPROVE", "REJECT"]
    reason: NonEmpty


class RevokeRequest(StrictModel):
    reason: NonEmpty


def _locked(conn: Connection, exception_id: str) -> Any:
    row = conn.execute(
        text(f"SELECT {EXCEPTION_COLS} FROM finding_exceptions "  # noqa: S608
             "WHERE exception_id=:i FOR UPDATE"),
        {"i": exception_id},
    ).first()  # fmt: skip
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    return row


def _source_lifecycle(conn: Connection, row: Any) -> str:
    return str(conn.execute(
        text("SELECT lifecycle FROM findings WHERE run_id=:r AND finding_id=:f FOR UPDATE"),
        {"r": row[6], "f": row[7]},
    ).scalar_one())  # fmt: skip


@router.post("/exceptions/{exception_id}/decision")
def decide_exception(
    exception_id: str,
    body: DecisionRequest,
    response: Response,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    actor = project_of_exception(engine, actor, exception_id)
    authorize(actor, Permission.EXCEPTION_APPROVE)
    reason = redact_text(body.reason)[:1000]
    status = "APPROVED" if body.decision == "APPROVE" else "REJECTED"
    now = c.clock()
    with tenant_connection(engine, actor.tenant_id) as conn:
        row = _locked(conn, exception_id)
        if row[12] == status and row[13] == actor.actor_id and row[15] == reason:
            response.headers["Idempotent-Replay"] = "true"
            return {**exception_json(row, now), "replayed": True}
        if row[12] != "REQUESTED":
            raise HTTPException(status_code=409, detail=f"exception is already {row[12]}")
        require_separation_of_duties(row[9], actor.actor_id)
        if status == "APPROVED" and now >= row[11]:
            raise HTTPException(status_code=409, detail="the requested expiry has passed; "
                                                        "request a new exception")  # fmt: skip
        conn.execute(
            text("UPDATE finding_exceptions SET status=:s, decided_by=:b, decided_at=:n, "
                 "decision_reason=:why WHERE exception_id=:i"),
            {"s": status, "b": actor.actor_id, "n": now, "why": reason, "i": exception_id},
        )  # fmt: skip
        before = _source_lifecycle(conn, row)
        after = (
            ("ACCEPTED" if status == "APPROVED" else "TRIAGED")
            if before == "EXCEPTION_PENDING"
            else before
        )
        _record(conn, actor, run_id=row[6], finding_id=row[7], action=f"EXCEPTION_{status}",
                before=before, after=after, reason=reason, now=now, exception_id=exception_id)  # fmt: skip
        append_audit(
            conn, tenant_id=actor.tenant_id, actor=actor.actor_id,
            action=f"exception.{body.decision.lower()}", resource=f"exception:{exception_id}",
            result="SUCCESS", correlation_id=cid, before_hash=canonical_hash({"status": row[12]}),
            after_hash=canonical_hash({"status": status, "reason": reason}),
        )  # fmt: skip
        out = _locked(conn, exception_id)
    return exception_json(out, now)


@router.post("/exceptions/{exception_id}/revoke")
def revoke_exception(
    exception_id: str,
    body: RevokeRequest,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    actor = project_of_exception(engine, actor, exception_id)
    authorize(actor, Permission.EXCEPTION_APPROVE)
    reason = redact_text(body.reason)[:1000]
    now = c.clock()
    with tenant_connection(engine, actor.tenant_id) as conn:
        row = _locked(conn, exception_id)
        if exc_rules.state(row[12], row[11], now) != "ACTIVE":
            raise HTTPException(status_code=409, detail="only an exception in force can be revoked")
        conn.execute(
            text("UPDATE finding_exceptions SET status='REVOKED', revoked_by=:b, revoked_at=:n, "
                 "revoke_reason=:why WHERE exception_id=:i"),
            {"b": actor.actor_id, "n": now, "why": reason, "i": exception_id},
        )  # fmt: skip
        before = _source_lifecycle(conn, row)
        after = "REOPENED" if before == "ACCEPTED" else before
        _record(conn, actor, run_id=row[6], finding_id=row[7], action="EXCEPTION_REVOKED",
                before=before, after=after, reason=reason, now=now, exception_id=exception_id)  # fmt: skip
        append_audit(
            conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="exception.revoke",
            resource=f"exception:{exception_id}", result="SUCCESS", correlation_id=cid,
            before_hash=canonical_hash({"status": "APPROVED"}),
            after_hash=canonical_hash({"status": "REVOKED", "reason": reason}),
        )  # fmt: skip
        out = _locked(conn, exception_id)
    return exception_json(out, now)
