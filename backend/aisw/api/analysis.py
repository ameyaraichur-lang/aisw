"""Scenarios, recommendations, recommendation decisions, ticket drafts and the agent registry.

Read-only MVP: a recommendation decision records a human choice and nothing else; a ticket draft is
stored in an outbox, and is delivered only through ``aisw.api.tickets`` when that is enabled.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import Engine, text

from aisw.agents.architecture import builtin_catalog
from aisw.agents.registry import AGENTS
from aisw.agents.roadmap import build_roadmap
from aisw.api.assessments import _run_or_404
from aisw.api.container import Container
from aisw.api.deps import correlation_id, get_actor, get_engine
from aisw.contracts.base import NonEmpty, StrictModel, canonical_hash
from aisw.core.audit import append_audit
from aisw.core.config import ModelProvider
from aisw.core.db import tenant_connection
from aisw.core.project_roles import project_of_run
from aisw.core.rbac import ActorContext, Forbidden, Permission, authorize
from aisw.core.redaction import redact_obj, redact_text
from aisw.orchestrator.analysis import usage_totals, validation_summary
from aisw.orchestrator.events import append_event
from aisw.policy import signoffs
from aisw.policy.rubric import builtin as builtin_rubric

router = APIRouter(prefix="/api/v1")
FINAL_RUN = {"REPORT_READY", "PARTIAL", "CLOSED"}


def _c(request: Request) -> Container:
    c: Container | None = request.app.state.container
    if c is None:
        raise HTTPException(status_code=503, detail="not configured")
    return c


def _narratives(conn: Any, run_id: str) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for purpose, ref, body, model, pv, _verdict in conn.execute(
        text(
            "SELECT purpose, subject_ref, body, model_id, prompt_version, assurance_verdict "
            "FROM narratives WHERE run_id=:r AND status='VALIDATED' AND assurance_verdict='ACCEPT'"
        ),
        {"r": run_id},
    ):
        if (body or {}).get("output"):
            out[(purpose, ref)] = {**body["output"], "model_id": model, "prompt_version": pv,
                                   "ai_generated": True}  # fmt: skip
    return out


def _visible(actor: ActorContext, verdict: str | None) -> bool:
    """Rejected candidates are auditor-only; pending ones are visible but never authoritative."""
    if verdict == "REJECT":
        return actor.can(Permission.AUDIT_READ)
    return True


@router.get("/assessments/{run_id}/scenarios")
def run_scenarios(
    run_id: str, actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> list[dict[str, Any]]:
    actor = project_of_run(engine, actor, run_id)
    authorize(actor, Permission.FINDING_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        _run_or_404(conn, run_id)
        rows = conn.execute(
            text("SELECT scenario_id, body, assurance_verdict FROM correlation_scenarios "
                 "WHERE run_id=:r ORDER BY scenario_id"), {"r": run_id},
        ).all()  # fmt: skip
        nar = _narratives(conn, run_id)
        meta = {
            fid: {"title": t, "severity": sev, "category": cat, "finding_verdict": fv}
            for fid, t, sev, cat, fv in conn.execute(
                text("SELECT finding_id, body->>'title', severity, body->>'category', "
                     "assurance_verdict FROM findings WHERE run_id=:r"), {"r": run_id},
            )
        }  # fmt: skip
    return [
        {**body, "chain": [{**c, **meta.get(c["finding_id"], {})} for c in body["chain"]],
         "assurance_verdict": v, "authoritative": v == "ACCEPT",
         "narrative": nar.get(("scenario", sid)) if v == "ACCEPT" else None}
        for sid, body, v in rows
        if _visible(actor, v)
    ]  # fmt: skip


def _rec_row(
    body: dict[str, Any], verdict: str | None, status: str, decided_by: str | None,
    decided_at: Any, reason: str | None, nar: dict[str, Any] | None,
) -> dict[str, Any]:  # fmt: skip
    return {
        **body, "status": status, "assurance_verdict": verdict, "authoritative": verdict == "ACCEPT",
        "decided_by": decided_by, "decided_at": decided_at.isoformat() if decided_at else None,
        "decision_reason": reason, "narrative": nar if verdict == "ACCEPT" else None,
        "executable": False,  # nothing in this platform executes a recommendation
    }  # fmt: skip


@router.get("/assessments/{run_id}/model-calls")
def run_model_calls(
    run_id: str, actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> dict[str, Any]:
    """The model-call ledger (ADR-023): who served each call, what it cost, and how it ended.
    Hashes only; prompts and replies are never returned."""
    actor = project_of_run(engine, actor, run_id)
    authorize(actor, Permission.FINDING_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        _run_or_404(conn, run_id)
        rows = conn.execute(
            text("SELECT purpose, subject_ref, model_id, prompt_version, status, attempts, defects, "
                 "input_tokens, output_tokens, latency_ms, replayed, input_hash, output_hash, "
                 "created_at FROM llm_calls WHERE run_id=:r ORDER BY created_at, purpose, "
                 "subject_ref"), {"r": run_id},
        ).mappings().all()  # fmt: skip
        totals = usage_totals(conn, run_id)
    return {
        "totals": totals,
        "items": [{**r, "created_at": r["created_at"].isoformat()} for r in rows],
    }


@router.get("/assessments/{run_id}/ai-validations")
def run_ai_validations(
    run_id: str, actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> dict[str, Any]:
    """The agent validation pass for a run (ADR-021). Model-written text, labelled as such."""
    actor = project_of_run(engine, actor, run_id)
    authorize(actor, Permission.FINDING_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        _run_or_404(conn, run_id)
        rows = conn.execute(
            text("SELECT target_ref, agent_id, verdict, effect, issues, human_questions, "
                 "validator_confidence, defects, model_id, prompt_version FROM ai_validations "
                 "WHERE run_id=:r ORDER BY agent_id, target_ref"), {"r": run_id},
        ).mappings().all()  # fmt: skip
        resolutions = {
            r["target_ref"]: {k: r[k] for k in ("decision", "reason", "decided_by")}
            | {"decided_at": r["decided_at"].isoformat()}
            for r in conn.execute(
                text("SELECT target_ref, decision, reason, decided_by, decided_at "
                     "FROM ai_validation_resolutions WHERE run_id=:r"), {"r": run_id},
            ).mappings()
        }  # fmt: skip
        summary = validation_summary(conn, run_id)
    names = {a.agent_id: a.name for a in AGENTS}
    return {
        "summary": summary,
        "items": [
            {**r, "agent_name": names[r["agent_id"]], "ai_generated": True,
             "resolution": resolutions.get(r["target_ref"])}
            for r in rows
        ],
    }  # fmt: skip


class ResolutionRequest(StrictModel):
    target_ref: NonEmpty
    decision: Literal["OVERRULE", "UPHOLD"]
    reason: NonEmpty


@router.post("/assessments/{run_id}/ai-validations/resolutions")
def resolve_dissent(
    run_id: str,
    body: ResolutionRequest,
    response: Response,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    """A human decides an AI dissent (ADR-022). OVERRULE re-runs assurance without it and issues a
    new report revision; UPHOLD records agreement and changes nothing. Nothing is ever ACCEPTed
    here directly: assurance decides again from the evidence."""
    actor = project_of_run(engine, actor, run_id)
    authorize(actor, Permission.REPORT_APPROVE)
    reason = redact_text(body.reason)[:1000]
    with tenant_connection(engine, actor.tenant_id) as conn:
        _run_or_404(conn, run_id)
        run = dict(conn.execute(
            text("SELECT * FROM assessment_runs WHERE run_id=:r FOR UPDATE"), {"r": run_id},
        ).mappings().one())  # fmt: skip
        found = conn.execute(
            text("SELECT verdict, effect FROM ai_validations WHERE run_id=:r AND target_ref=:t"),
            {"r": run_id, "t": body.target_ref},
        ).first()
        if found is None:
            raise HTTPException(status_code=404, detail="not found")
        verdict, effect = found
        # A scope dissent is a review note (ADR-024): overruling it records the decision only.
        reassess = body.decision == "OVERRULE" and effect == "HOLD_FOR_REVIEW"
        prior = conn.execute(
            text("SELECT decision, reason FROM ai_validation_resolutions "
                 "WHERE run_id=:r AND target_ref=:t"), {"r": run_id, "t": body.target_ref},
        ).first()  # fmt: skip
        if prior is not None:
            if tuple(prior) == (body.decision, reason):
                response.headers["Idempotent-Replay"] = "true"
                return {"target_ref": body.target_ref, "decision": body.decision, "replayed": True}
            raise HTTPException(status_code=409, detail=f"already resolved: {prior[0]}")
        if verdict != "DISSENT":
            raise HTTPException(status_code=409, detail="only an AI dissent can be resolved")
        if run["requested_by"] == actor.actor_id:
            raise Forbidden("the requester of a run cannot resolve its AI dissents")
        latest = conn.execute(
            text("SELECT approval_state FROM reports WHERE run_id=:r "
                 "ORDER BY revision DESC LIMIT 1"), {"r": run_id},
        ).scalar()  # fmt: skip
        if run["state"] not in {"REPORT_READY", "PARTIAL"} or latest != "PENDING":
            raise HTTPException(status_code=409, detail="run is not awaiting report approval")
        now = c.clock()
        revision = run["assurance_revision"] + reassess
        conn.execute(
            text("INSERT INTO ai_validation_resolutions (tenant_id, run_id, target_ref, decision, "
                 "reason, decided_by, decided_at, assurance_revision) VALUES (:t, :r, :ref, :d, "
                 ":why, :b, :n, :v)"),
            {"t": actor.tenant_id, "r": run_id, "ref": body.target_ref, "d": body.decision,
             "why": reason, "b": actor.actor_id, "n": now, "v": revision},
        )  # fmt: skip
        if reassess:
            conn.execute(
                text("UPDATE assessment_runs SET state='ASSURANCE', assurance_revision=:v, "
                     "updated_at=:n WHERE run_id=:r"), {"v": revision, "n": now, "r": run_id},
            )  # fmt: skip
            append_event(
                conn, tenant_id=actor.tenant_id, run_id=run_id, now=now,
                event_type="phase.changed",
                payload={"from": run["state"], "to": "ASSURANCE", "reason": "AI_DISSENT_OVERRULED"},
            )  # fmt: skip
        append_audit(
            conn, tenant_id=actor.tenant_id, actor=actor.actor_id,
            action=f"ai_validation.{body.decision.lower()}",
            resource=f"ai_validation:{run_id}:{body.target_ref}", result="SUCCESS",
            correlation_id=cid, before_hash=canonical_hash({"verdict": verdict}),
            after_hash=canonical_hash({"decision": body.decision, "reason": reason}),
        )  # fmt: skip
    return {"target_ref": body.target_ref, "decision": body.decision, "decided_by": actor.actor_id,
            "assurance_revision": revision, "reassessing": reassess}  # fmt: skip


@router.get("/assessments/{run_id}/recommendations")
def run_recommendations(
    run_id: str, actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> list[dict[str, Any]]:
    actor = project_of_run(engine, actor, run_id)
    authorize(actor, Permission.FINDING_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        _run_or_404(conn, run_id)
        rows = conn.execute(
            text("SELECT recommendation_id, body, assurance_verdict, status, decided_by, decided_at, "
                 "decision_reason FROM recommendations WHERE run_id=:r ORDER BY recommendation_id"),
            {"r": run_id},
        ).all()  # fmt: skip
        nar = _narratives(conn, run_id)
    return [
        _rec_row(body, v, st, by, at, why, nar.get(("recommendation", rid)))
        for rid, body, v, st, by, at, why in rows
        if _visible(actor, v)
    ]


@router.get("/assessments/{run_id}/roadmap")
def run_roadmap(
    run_id: str, actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> dict[str, Any]:
    actor = project_of_run(engine, actor, run_id)
    authorize(actor, Permission.FINDING_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        run = _run_or_404(conn, run_id)
        rows = conn.execute(
            text("SELECT body, assurance_verdict, status FROM recommendations WHERE run_id=:r"),
            {"r": run_id},
        ).all()  # fmt: skip
        owners: dict[str, str | None] = {
            a: o
            for a, o in conn.execute(
                text("SELECT asset_id, owner FROM assets WHERE project_id=:p"),
                {"p": run["project_id"]},
            )
        }
    recs = [{**body, "assurance_verdict": v, "status": st} for body, v, st in rows]
    return {"run_id": run_id, **build_roadmap(recs, owners),
            "catalog_signoff": signoffs.builtin().status_of(
                f"architecture-catalog-{builtin_catalog().version}")}  # fmt: skip


@router.get("/recommendations")
def all_recommendations(
    run_id: str | None = None,
    status: str | None = Query(
        default=None, pattern="^(DRAFT|NEEDS_REVIEW|APPROVED_FOR_PLANNING|REJECTED)$"
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> dict[str, Any]:
    """Cross-run workbench list: assurance-ACCEPTed recommendations only."""
    authorize(actor, Permission.FINDING_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        rows = conn.execute(
            text(
                "SELECT r.run_id, r.recommendation_id, r.body, r.status, r.decided_by, r.decided_at, "
                "r.decision_reason, p.name, count(*) OVER (), a.requested_by FROM recommendations r "
                "JOIN projects p ON p.project_id = r.project_id "
                "JOIN assessment_runs a ON a.run_id = r.run_id "
                "WHERE r.assurance_verdict='ACCEPT' AND (CAST(:s AS text) IS NULL OR r.status=:s) "
                "AND (CAST(:r AS text) IS NULL OR r.run_id=:r) "
                "ORDER BY r.run_id DESC, r.recommendation_id LIMIT :l OFFSET :o"
            ),
            {"s": status, "r": run_id, "l": limit, "o": offset},
        ).all()
    return {
        "items": [
            {"run_id": r[0], "project_name": r[7], "run_requested_by": r[9],
             **_rec_row(r[2], "ACCEPT", r[3], r[4], r[5], r[6], None)}
            for r in rows
        ],
        "total": rows[0][8] if rows else 0,
    }  # fmt: skip


class DecisionRequest(StrictModel):
    decision: Literal["ACCEPT", "REJECT", "DEFER"]
    reason: NonEmpty


_TARGET_STATUS = {"ACCEPT": "APPROVED_FOR_PLANNING", "REJECT": "REJECTED", "DEFER": "NEEDS_REVIEW"}


@router.post("/assessments/{run_id}/recommendations/{recommendation_id}/decision")
def decide(
    run_id: str,
    recommendation_id: str,
    body: DecisionRequest,
    response: Response,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    actor = project_of_run(engine, actor, run_id)
    authorize(actor, Permission.RECOMMENDATION_DECIDE)
    target = _TARGET_STATUS[body.decision]
    reason = redact_text(body.reason)[:1000]
    with tenant_connection(engine, actor.tenant_id) as conn:
        run = _run_or_404(conn, run_id)
        row = conn.execute(
            text("SELECT status, assurance_verdict, decision_reason FROM recommendations "
                 "WHERE run_id=:r AND recommendation_id=:i FOR UPDATE"),
            {"r": run_id, "i": recommendation_id},
        ).first()  # fmt: skip
        if row is None:
            raise HTTPException(status_code=404, detail="not found")
        status, verdict, prior_reason = row
        if verdict == "REJECT" and not actor.can(Permission.AUDIT_READ):
            raise HTTPException(status_code=404, detail="not found")
        if status == target and prior_reason == reason:
            response.headers["Idempotent-Replay"] = "true"
            return {"recommendation_id": recommendation_id, "status": status, "replayed": True}
        if status in {"APPROVED_FOR_PLANNING", "REJECTED"}:
            raise HTTPException(status_code=409, detail=f"decision already recorded: {status}")
        if body.decision != "DEFER" and run["requested_by"] == actor.actor_id:
            raise HTTPException(
                status_code=403,
                detail="separation of duties: you launched this run, so another approver decides",
            )
        if body.decision == "ACCEPT" and (verdict != "ACCEPT" or run["state"] not in FINAL_RUN):
            raise HTTPException(
                status_code=409,
                detail="only an assurance-accepted recommendation of a finished run can be accepted",
            )
        now = c.clock()
        conn.execute(
            text("UPDATE recommendations SET status=:s, decided_by=:b, decided_at=:n, "
                 "decision_reason=:why WHERE run_id=:r AND recommendation_id=:i"),
            {"s": target, "b": actor.actor_id, "n": now, "why": reason, "r": run_id, "i": recommendation_id},
        )  # fmt: skip
        append_audit(
            conn, tenant_id=actor.tenant_id, actor=actor.actor_id,
            action=f"recommendation.{body.decision.lower()}",
            resource=f"recommendation:{recommendation_id}", result="SUCCESS", correlation_id=cid,
            before_hash=canonical_hash({"status": status}),
            after_hash=canonical_hash({"status": target, "reason": reason}),
        )  # fmt: skip
    return {"recommendation_id": recommendation_id, "status": target, "decided_by": actor.actor_id,
            "executed": False}  # fmt: skip


# ------------------------------------------------------------------ ticket drafts (outbox only)
class TicketDraftRequest(StrictModel):
    run_id: NonEmpty
    recommendation_id: NonEmpty


def _draft_payload(rec: dict[str, Any], run_id: str) -> dict[str, Any]:
    desc = "\n".join(
        [
            f"Recommendation {rec['recommendation_id']} ({rec.get('catalog_ref')}), run {run_id}.",
            f"Target pattern: {rec.get('target_pattern')}",
            f"Action: {rec['action']}",
            f"Related findings: {', '.join(rec['finding_refs'])}",
            f"Affected assets: {', '.join(rec.get('affected_assets', []))}",
            f"Rollback: {rec.get('rollback')}",
            f"Acceptance test: {rec.get('acceptance_test')}",
            "Owner questions: " + "; ".join(rec.get("owner_questions", [])),
            "Effort: unknown (to be estimated by the owner).",
        ]
    )
    payload: dict[str, Any] = redact_obj({
        "summary": rec.get("title") or rec["action"], "description": desc,
        "labels": ["aisw", "draft", *( [rec["risk_tier"]] if rec.get("risk_tier") else [] )],
        "delivery": "NOT_SENT",
    })  # fmt: skip
    return payload


@router.post("/tickets/drafts", status_code=201)
def create_ticket_draft(
    body: TicketDraftRequest,
    response: Response,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    actor = project_of_run(engine, actor, body.run_id)
    authorize(actor, Permission.RECOMMENDATION_DECIDE)
    if not c.settings.enable_itsm_ticket_creation:
        raise HTTPException(
            status_code=403, detail="ticket drafts are disabled (enable_itsm_ticket_creation)"
        )
    with tenant_connection(engine, actor.tenant_id) as conn:
        _run_or_404(conn, body.run_id)
        row = conn.execute(
            text("SELECT status, assurance_verdict, body, project_id::text FROM recommendations "
                 "WHERE run_id=:r AND recommendation_id=:i"),
            {"r": body.run_id, "i": body.recommendation_id},
        ).first()  # fmt: skip
        if row is None:
            raise HTTPException(status_code=404, detail="not found")
        status, verdict, rec, project_id = row
        if status != "APPROVED_FOR_PLANNING" or verdict != "ACCEPT":
            raise HTTPException(
                status_code=409, detail="only an accepted recommendation can be drafted"
            )
        payload = _draft_payload(rec, body.run_id)
        inserted = conn.execute(
            text("INSERT INTO ticket_outbox (tenant_id, run_id, recommendation_id, project_id, payload, "
                 "created_by, created_at) VALUES (:t, :r, :i, :p, CAST(:b AS jsonb), :by, :n) "
                 "ON CONFLICT (tenant_id, run_id, recommendation_id) DO NOTHING RETURNING outbox_id::text"),
            {"t": actor.tenant_id, "r": body.run_id, "i": body.recommendation_id, "p": project_id,
             "b": json.dumps(payload), "by": actor.actor_id, "n": c.clock()},
        ).first()  # fmt: skip
        if inserted is None:
            response.status_code = 200
            response.headers["Idempotent-Replay"] = "true"
            oid = conn.execute(
                text(
                    "SELECT outbox_id::text FROM ticket_outbox WHERE tenant_id=:t AND run_id=:r "
                    "AND recommendation_id=:i"
                ),
                {"t": actor.tenant_id, "r": body.run_id, "i": body.recommendation_id},
            ).scalar_one()
        else:
            oid = inserted[0]
            append_audit(
                conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="ticket.draft",
                resource=f"recommendation:{body.recommendation_id}", result="SUCCESS",
                correlation_id=cid, after_hash=canonical_hash(payload),
            )  # fmt: skip
    return {"outbox_id": oid, "status": "DRAFT", "delivered": False, "payload": payload}


@router.get("/tickets/drafts")
def list_ticket_drafts(
    run_id: str | None = None,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> list[dict[str, Any]]:
    authorize(actor, Permission.FINDING_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        rows = conn.execute(
            text("SELECT outbox_id::text, run_id, recommendation_id, status, payload, created_by, "
                 "created_at, target, attempts, external_ref, external_url, last_error, sent_by, "
                 "sent_at FROM ticket_outbox WHERE (CAST(:r AS text) IS NULL OR run_id=:r) "
                 "ORDER BY created_at DESC"),
            {"r": run_id},
        ).all()  # fmt: skip
    return [
        {"outbox_id": r[0], "run_id": r[1], "recommendation_id": r[2], "status": r[3], "payload": r[4],
         "created_by": r[5], "created_at": r[6].isoformat(), "delivered": r[3] == "SENT",
         "target": r[7], "attempts": r[8], "external_ref": r[9], "external_url": r[10],
         "last_error": r[11], "sent_by": r[12], "sent_at": r[13].isoformat() if r[13] else None}
        for r in rows
    ]  # fmt: skip


# ------------------------------------------------------------------ agent registry
@router.get("/agents")
def agents(actor: ActorContext = Depends(get_actor), c: Container = Depends(_c)) -> dict[str, Any]:
    authorize(actor, Permission.PROJECT_READ)
    s = c.settings
    registered = set(c.registry.ids())
    rubric = builtin_rubric()
    return {
        "agents": [
            {
                "agent_id": a.agent_id,
                "name": a.name,
                "purpose": a.purpose,
                "kind": a.kind,
                "adapters": [x for x in a.adapter_ids if x in registered],
                "outputs": list(a.outputs),
                "read_only": True,
                "ai_capable": a.ai_capable,
                "ai_active": a.ai_capable
                and s.ai_enabled
                and (s.ai_narrative_enabled if a.agent_id == 5 else s.ai_architecture_enabled),
                "ai_validated": a.ai_validated and s.ai_enabled and s.ai_validation_enabled,
            }
            for a in AGENTS
        ],
        "ai": {
            "enabled": s.ai_enabled,
            "validation_enabled": s.ai_enabled and s.ai_validation_enabled,
            "validation_model": (s.astra_validation_deployment or s.model_id)
            if s.ai_enabled and s.ai_validation_enabled
            else None,
            "model_id": s.model_id if s.ai_enabled else None,
            "model_license": s.model_license if s.ai_enabled else None,
            "provider": s.model_provider.value if s.ai_enabled else None,
            "endpoint_local_only": s.model_provider is ModelProvider.OLLAMA,
            "tools_available_to_model": False,
            "may_decide": False,  # a model explains; deterministic checks decide
        },
        "ticket_drafts_enabled": s.enable_itsm_ticket_creation,
        "ticket_delivery": {
            "enabled": s.enable_itsm_ticket_delivery,
            "target": s.itsm_target if s.enable_itsm_ticket_delivery else None,
        },
        "rubric_version": rubric.version,
        "signoffs": {
            "rubric": signoffs.builtin().status_of(f"risk-rubric-{rubric.version}"),
            "catalog": signoffs.builtin().status_of(
                f"architecture-catalog-{builtin_catalog().version}"
            ),
        },
    }
