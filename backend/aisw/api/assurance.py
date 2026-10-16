"""Assurance Console read models: deterministic assurance, the engine-vs-AI disagreement queue, the
AVP trigger policy and its decisions, and the tenant-wide model-call ledger.

Everything here reads; a dissent is still resolved through the per-run resolution endpoint, so the
same separation and re-assessment rules apply. Model prompts and replies are never returned.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Engine, text

from aisw.agents.registry import AGENTS
from aisw.api.analysis import _c
from aisw.api.container import Container
from aisw.api.deps import get_actor, get_engine
from aisw.core.db import tenant_connection
from aisw.core.rbac import ActorContext, Permission, authorize
from aisw.llm import triggers
from aisw.policy import signoffs

router = APIRouter(prefix="/api/v1")
NAMES = {a.agent_id: a.name for a in AGENTS}
DISAGREE = ("DISSENT", "CONCERN", "INSUFFICIENT_EVIDENCE")


@router.get("/assurance/overview")
def overview(
    actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> dict[str, Any]:
    authorize(actor, Permission.FINDING_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        verdicts = conn.execute(
            text("SELECT split_part(a.item_ref, ':', 1), a.verdict, count(*) FROM assurance_results a "
                 "JOIN assessment_runs r ON r.run_id=a.run_id AND a.revision=r.assurance_revision "
                 "GROUP BY 1, 2 ORDER BY 1, 2"),
        ).all()  # fmt: skip
        defects = conn.execute(
            text("SELECT d, count(*) FROM assurance_results a JOIN assessment_runs r "
                 "ON r.run_id=a.run_id AND a.revision=r.assurance_revision, "
                 "jsonb_array_elements_text(a.defect_codes) d GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 15"),
        ).all()  # fmt: skip
        ai = conn.execute(
            text("SELECT v.verdict, count(*), count(*) FILTER (WHERE x.decision IS NULL "
                 "AND v.verdict='DISSENT') FROM ai_validations v LEFT JOIN ai_validation_resolutions x "
                 "ON x.run_id=v.run_id AND x.target_ref=v.target_ref GROUP BY 1 ORDER BY 1"),
        ).all()  # fmt: skip
        trig = conn.execute(
            text("SELECT agent_id, count(*) FILTER (WHERE triggered), count(*) FILTER (WHERE NOT "
                 "triggered) FROM ai_validation_triggers GROUP BY 1 ORDER BY 1"),
        ).all()  # fmt: skip
    by_kind: dict[str, dict[str, int]] = {}
    for kind, verdict, n in verdicts:
        by_kind.setdefault(kind, {})[verdict] = n
    return {
        "assurance": by_kind,
        "defects": [{"code": c, "count": n} for c, n in defects],
        "ai_validation": {v: n for v, n, _ in ai},
        "open_dissent": sum(o for *_, o in ai),
        "triggers": [{"agent_id": a, "agent_name": NAMES[a], "triggered": t, "skipped": s}
                     for a, t, s in trig],
    }  # fmt: skip


@router.get("/assurance/disagreements")
def disagreements(
    state: str = Query(default="open", pattern="^(open|resolved|notes|all)$"),
    run_id: str | None = None,
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> dict[str, Any]:
    """Where the AI reviewer disagreed with the deterministic engine. ``open``: dissent awaiting a
    human; ``resolved``: dissent a human decided; ``notes``: concerns and insufficient-evidence
    review items, which never hold anything."""
    authorize(actor, Permission.FINDING_READ)
    where = {
        "open": "v.verdict='DISSENT' AND x.decision IS NULL",
        "resolved": "v.verdict='DISSENT' AND x.decision IS NOT NULL",
        "notes": "v.verdict IN ('CONCERN','INSUFFICIENT_EVIDENCE')",
        "all": "v.verdict IN ('DISSENT','CONCERN','INSUFFICIENT_EVIDENCE')",
    }[state]
    with tenant_connection(engine, actor.tenant_id) as conn:
        rows = conn.execute(
            text("SELECT v.run_id, p.name, v.agent_id, v.target_ref, v.verdict, v.effect, v.issues, "  # noqa: S608
                 "v.human_questions, v.validator_confidence, v.model_id, v.prompt_version, "
                 "v.created_at, a.verdict, a.defect_codes, x.decision, x.reason, x.decided_by, "
                 "x.decided_at, r.state, count(*) OVER () FROM ai_validations v "
                 "JOIN assessment_runs r ON r.run_id=v.run_id "
                 "JOIN projects p ON p.project_id=r.project_id "
                 "LEFT JOIN assurance_results a ON a.run_id=v.run_id AND a.item_ref=v.target_ref "
                 "AND a.revision=r.assurance_revision "
                 "LEFT JOIN ai_validation_resolutions x ON x.run_id=v.run_id "
                 f"AND x.target_ref=v.target_ref WHERE {where} "
                 "AND (CAST(:r AS text) IS NULL OR v.run_id=:r) "
                 "ORDER BY v.created_at DESC, v.run_id, v.target_ref LIMIT :l OFFSET :o"),
            {"l": limit, "o": offset, "r": run_id},
        ).all()  # fmt: skip
    return {
        "items": [
            {"run_id": r[0], "project_name": r[1], "agent_id": r[2], "agent_name": NAMES[r[2]],
             "target_ref": r[3], "ai_verdict": r[4], "effect": r[5], "issues": r[6],
             "human_questions": r[7], "validator_confidence": r[8], "model_id": r[9],
             "prompt_version": r[10], "created_at": r[11].isoformat(), "engine_verdict": r[12],
             "engine_defects": r[13] or [], "run_state": r[18], "ai_generated": True,
             "resolution": None if r[14] is None else {
                 "decision": r[14], "reason": r[15], "decided_by": r[16],
                 "decided_at": r[17].isoformat()},
             "resolvable": r[4] == "DISSENT" and r[14] is None}
            for r in rows
        ],
        "total": rows[0][19] if rows else 0,
    }  # fmt: skip


@router.get("/assurance/trigger-policy")
def trigger_policy(
    run_id: str | None = None,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
) -> dict[str, Any]:
    """The active AVP trigger policy and, for a run, every decision it made (triggered or not)."""
    authorize(actor, Permission.FINDING_READ)
    p = triggers.load(c.settings.ai_validation_trigger_version)
    decisions: list[dict[str, Any]] = []
    if run_id:
        with tenant_connection(engine, actor.tenant_id) as conn:
            decisions = [
                {"agent_id": a, "agent_name": NAMES[a], "target_ref": ref, "triggered": hit,
                 "rule": rule, "policy_version": v}
                for a, ref, hit, rule, v in conn.execute(
                    text("SELECT agent_id, target_ref, triggered, rule, policy_version FROM "
                         "ai_validation_triggers WHERE run_id=:r ORDER BY agent_id, target_ref"),
                    {"r": run_id},
                )
            ]  # fmt: skip
    return {
        "version": p.version, "status": p.status, "sha256": p.sha256,
        "signoff": signoffs.builtin().status_of(f"avp-triggers-{p.version}"),
        "priority": [{"agent_id": a, "agent_name": NAMES[a]} for a in p.priority],
        "agents": [
            {"agent_id": a, "agent_name": NAMES[a], "why": t.why, "rules": [r.name for r in t.rules]}
            for a, t in sorted(p.agents.items())
        ],
        "ai_validation_enabled": c.settings.ai_enabled and c.settings.ai_validation_enabled,
        "decisions": decisions,
    }  # fmt: skip


@router.get("/model-calls")
def model_calls(
    run_id: str | None = None,
    purpose: str | None = Query(default=None, max_length=60),
    status: str | None = Query(default=None, pattern="^[A-Z_]{2,40}$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> dict[str, Any]:
    """Tenant-wide model-call ledger (ADR-023): hashes, cost and outcome; never prompt or reply."""
    authorize(actor, Permission.AUDIT_READ)
    where = (
        "(CAST(:r AS text) IS NULL OR l.run_id=:r) AND (CAST(:p AS text) IS NULL OR "
        "l.purpose LIKE :p || '%') AND (CAST(:s AS text) IS NULL OR l.status=:s)"
    )
    params = {"r": run_id, "p": purpose, "s": status}
    with tenant_connection(engine, actor.tenant_id) as conn:
        rows = conn.execute(
            text("SELECT l.run_id, p.name, l.purpose, l.subject_ref, l.model_id, l.prompt_version, "  # noqa: S608
                 "l.status, l.attempts, l.defects, l.input_tokens, l.output_tokens, l.latency_ms, "
                 "l.replayed, l.input_hash, l.output_hash, l.created_at, count(*) OVER () "
                 "FROM llm_calls l JOIN assessment_runs r ON r.run_id=l.run_id "
                 f"JOIN projects p ON p.project_id=r.project_id WHERE {where} "
                 "ORDER BY l.created_at DESC, l.purpose, l.subject_ref LIMIT :l OFFSET :o"),
            {**params, "l": limit, "o": offset},
        ).all()  # fmt: skip
        totals = conn.execute(
            text("SELECT count(*), coalesce(sum(input_tokens), 0), coalesce(sum(output_tokens), 0), "  # noqa: S608
                 "coalesce(sum(latency_ms), 0), count(*) FILTER (WHERE replayed), "
                 "count(*) FILTER (WHERE input_tokens IS NULL AND NOT replayed), "
                 f"count(*) FILTER (WHERE status <> 'VALIDATED') FROM llm_calls l WHERE {where}"),
            params,
        ).one()  # fmt: skip
    keys = ("run_id", "project_name", "purpose", "subject_ref", "model_id", "prompt_version",
            "status", "attempts", "defects", "input_tokens", "output_tokens", "latency_ms",
            "replayed", "input_hash", "output_hash")  # fmt: skip
    return {
        "items": [dict(zip(keys, r[:15], strict=True)) | {"created_at": r[15].isoformat()}
                  for r in rows],
        "total": rows[0][16] if rows else 0,
        "totals": dict(zip(("calls", "input_tokens", "output_tokens", "latency_ms", "replayed",
                            "unmetered", "not_validated"), totals, strict=True)),
    }  # fmt: skip
