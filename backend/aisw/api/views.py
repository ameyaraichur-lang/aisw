"""Read models for the operator console. Every route is authorised and tenant-scoped server-side;
the UI hiding a control is never the security boundary."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import Engine, text

from aisw.api.assessments import TERMINAL_RUN, _run_or_404
from aisw.api.container import Container
from aisw.api.deps import get_actor, get_engine
from aisw.core.auth import list_dev_users
from aisw.core.config import Environment
from aisw.core.db import tenant_connection
from aisw.core.rbac import ROLE_PERMISSIONS, ActorContext, Permission, authorize
from aisw.orchestrator.analysis import current_assurance
from aisw.orchestrator.stream import stream_events
from aisw.policy.results import finding_id as make_finding_id

router = APIRouter(prefix="/api/v1")
OPEN_STATES_EXCLUDED = ("CLOSED", "FAILED", "CANCELLED", "EXPIRED", "REPORT_READY", "PARTIAL")


def _c(request: Request) -> Container:
    c: Container | None = request.app.state.container
    if c is None:
        raise HTTPException(status_code=503, detail="not configured")
    return c


@router.get("/auth/mode")
def auth_mode(request: Request) -> dict[str, Any]:
    s = request.app.state.settings
    if s.dev_auth_stub and s.env in {Environment.DEV, Environment.TEST}:
        return {"mode": "dev_stub", "users": list_dev_users()}
    return {"mode": "none", "users": []}


@router.get("/me")
def me(actor: ActorContext = Depends(get_actor)) -> dict[str, Any]:
    perms = sorted({p.value for r in actor.roles for p in ROLE_PERMISSIONS[r]})
    return {"tenant_id": actor.tenant_id, "actor_id": actor.actor_id,
            "roles": sorted(r.value for r in actor.roles), "permissions": perms}  # fmt: skip


@router.get("/connectors")
def connectors(
    actor: ActorContext = Depends(get_actor), c: Container = Depends(_c)
) -> list[dict[str, Any]]:
    authorize(actor, Permission.PROJECT_READ)
    out = []
    for aid in c.registry.ids():
        cap = c.registry.capability(aid)
        if cap is None:
            continue
        out.append(
            {
                "adapter_id": cap.adapter_id,
                "version": cap.version,
                "enabled": cap.enabled,
                "permission_ok": cap.permission_ok,
                "domains": sorted(cap.domains),
                "target_kinds": sorted(cap.target_kinds),
                "profiles": [
                    {"profile_id": k, "profile_class": v.value} for k, v in cap.profiles.items()
                ],
                "read_only": not cap.mutates_infrastructure,
                "kind": cap.kind,
                "import_kinds": sorted(cap.import_kinds),
                "formats": list(cap.formats),
                "health": next(
                    (h.status for h in c.registry.health() if h.adapter_id == aid), "DISABLED"
                ),
            }
        )
    return out


@router.get("/policy-packs")
def policy_packs(
    actor: ActorContext = Depends(get_actor), c: Container = Depends(_c)
) -> list[dict[str, Any]]:
    authorize(actor, Permission.PROJECT_READ)
    return [
        {"key": k, "pack_hash": p.pack_hash, "description": p.description,
         "rules": len(p.rules), "framework": p.framework.model_dump()}
        for k in c.packs.keys()  # noqa: SIM118 - PackRegistry.keys() is not a dict
        if (p := c.packs.get(k)) is not None
    ]  # fmt: skip


@router.get("/inventory")
def list_inventory(
    project_id: str, actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> list[dict[str, Any]]:
    authorize(actor, Permission.PROJECT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        try:
            rows = conn.execute(
                text(
                    "SELECT kind, selector, resolved_id, expected_assets FROM inventory_entries "
                    "WHERE project_id=:p ORDER BY kind, selector"
                ),
                {"p": project_id},
            ).all()
        except Exception as exc:
            raise HTTPException(status_code=422, detail="invalid project id") from exc
    return [
        {"kind": r[0], "selector": r[1], "resolved_id": r[2], "expected_assets": r[3]} for r in rows
    ]


@router.get("/scope-manifests")
def list_manifests(
    project_id: str | None = None,
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> list[dict[str, Any]]:
    authorize(actor, Permission.PROJECT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        rows = conn.execute(
            text(
                "SELECT m.manifest_id::text, m.project_id::text, p.name, m.version, m.status, "
                "m.canonical_hash, m.created_by, m.approved_by, m.created_at, m.body "
                "FROM scope_manifests m JOIN projects p ON p.project_id = m.project_id "
                "WHERE (CAST(:p AS text) IS NULL OR m.project_id::text = :p) "
                "AND (CAST(:s AS text) IS NULL OR m.status = :s) "
                "ORDER BY m.created_at DESC LIMIT :l"
            ),
            {"p": project_id, "s": status, "l": limit},
        ).all()
    return [
        {
            "manifest_id": r[0], "project_id": r[1], "project_name": r[2], "version": r[3],
            "status": r[4], "canonical_hash": r[5], "created_by": r[6], "approved_by": list(r[7] or []),
            "created_at": r[8].isoformat(),
            "targets": [t["selector"] for t in r[9]["targets"]],
            "exclusions": [t["selector"] for t in r[9]["exclusions"]],
            "adapters": r[9]["allowed_adapters"], "domains": r[9]["domains"],
            "profiles": r[9]["profiles"], "policy_version": r[9]["policy_version"],
            "expires_at": r[9]["expires_at"], "quotas": r[9]["quotas"],
            "evidence_retention_days": r[9]["evidence_retention_days"],
            "active_profiles": [a for a, p in r[9]["profiles"].items() if p["profile_class"] == "ACTIVE"],
        }
        for r in rows
    ]  # fmt: skip


@router.get("/assessments")
def list_runs(
    project_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> dict[str, Any]:
    authorize(actor, Permission.PROJECT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        rows = conn.execute(
            text(
                "SELECT a.run_id, a.project_id::text, p.name, a.state, a.partial, a.created_at, "
                "a.manifest_hash, a.policy_version, a.requested_by, a.reason, count(*) OVER (), "
                "(SELECT count(*) FROM run_tasks t WHERE t.run_id=a.run_id), "
                "(SELECT count(*) FROM run_tasks t WHERE t.run_id=a.run_id "
                " AND t.status IN ('QUEUED','RUNNING')) "
                "FROM assessment_runs a JOIN projects p ON p.project_id = a.project_id "
                "WHERE (CAST(:p AS text) IS NULL OR a.project_id::text = :p) "
                "ORDER BY a.created_at DESC LIMIT :l OFFSET :o"
            ),
            {"p": project_id, "l": limit, "o": offset},
        ).all()
    return {
        "items": [
            {"run_id": r[0], "project_id": r[1], "project_name": r[2], "state": r[3],
             "partial": r[4], "created_at": r[5].isoformat(), "manifest_hash": r[6],
             "policy_version": r[7], "requested_by": r[8], "reason": r[9],
             "tasks_total": r[11], "tasks_open": r[12]}
            for r in rows
        ],
        "total": rows[0][10] if rows else 0,
    }  # fmt: skip


@router.get("/assessments/{run_id}/tasks")
def run_tasks(
    run_id: str, actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> list[dict[str, Any]]:
    authorize(actor, Permission.PROJECT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        _run_or_404(conn, run_id)
        rows = conn.execute(
            text(
                "SELECT task_id::text, adapter_id, profile, target_kind, target_selector, status, "
                "attempts, max_attempts, started_at, completed_at, warnings, errors, output_refs, "
                "tool_version FROM run_tasks WHERE run_id=:r ORDER BY created_at, task_id"
            ),
            {"r": run_id},
        ).all()
    return [
        {"task_id": r[0], "agent_id": r[1], "profile": r[2], "target_kind": r[3], "target": r[4],
         "status": r[5], "attempts": r[6], "max_attempts": r[7],
         "started_at": r[8].isoformat() if r[8] else None,
         "completed_at": r[9].isoformat() if r[9] else None, "warnings": r[10], "errors": r[11],
         "output_refs": r[12], "tool_version": r[13], "contract_version": "1.1"}
        for r in rows
    ]  # fmt: skip


@router.get("/assessments/{run_id}/controls")
def run_controls(
    run_id: str, actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> list[dict[str, Any]]:
    authorize(actor, Permission.PROJECT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        run = _run_or_404(conn, run_id)
        rows = conn.execute(
            text(
                "SELECT framework, version, control_id, applicability, outcome, evidence_refs, "
                "policy_version FROM control_assessments WHERE run_id=:r ORDER BY control_id"
            ),
            {"r": run_id},
        ).all()
    final = run["state"] in TERMINAL_RUN | {"PARTIAL", "REPORT_READY"}
    return [
        {"framework": r[0], "version": r[1], "control_id": r[2], "applicability": r[3],
         "outcome": r[4], "evidence_refs": r[5], "policy_version": r[6], "final": final}
        for r in rows
    ]  # fmt: skip


@router.get("/assessments/{run_id}/findings/{finding_id}")
def finding_detail(
    run_id: str,
    finding_id: str,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
) -> dict[str, Any]:
    authorize(actor, Permission.FINDING_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        run = _run_or_404(conn, run_id)
        row = conn.execute(
            text("SELECT body, assurance_verdict FROM findings WHERE run_id=:r AND finding_id=:f"),
            {"r": run_id, "f": finding_id},
        ).first()
        if row is None:
            raise HTTPException(status_code=404, detail="not found")
        body, verdict = row
        if verdict == "REJECT":
            authorize(actor, Permission.AUDIT_READ)  # rejected candidates: auditors only
        evidence = conn.execute(
            text(
                "SELECT evidence_ref, content_hash, source, tool_version, collected_at, redacted, "
                "media_type, size_bytes, (SELECT executed_at FROM retention_actions a WHERE a.kind='EVIDENCE' "
                "AND a.ref=evidence_artifacts.evidence_ref) FROM evidence_artifacts WHERE tenant_id=:t "
                "AND evidence_ref = ANY(:refs)"
            ),
            {"t": actor.tenant_id, "refs": body["evidence_refs"]},
        ).all()
        obs = conn.execute(
            text(
                "SELECT asset_id, rule_id, observed_value, expected_value, outcome, observed_at "
                "FROM observations WHERE run_id=:r AND asset_id = ANY(:a) "
                "AND evidence_ref = ANY(:refs) AND outcome='FAIL'"
            ),
            {"r": run_id, "a": body["affected_assets"], "refs": body["evidence_refs"]},
        ).all()
        assurance = current_assurance(conn, run_id, f"finding:{finding_id}")
        risk_row = conn.execute(
            text(
                "SELECT r.rubric_version, r.tier, r.provisional_tier, r.basis, r.factors, "
                "r.missing_evidence, r.rationale, a.verdict FROM risk_assessments r "
                "JOIN assessment_runs ar ON ar.run_id = r.run_id "
                "LEFT JOIN assurance_results a ON a.run_id=r.run_id AND a.item_ref='risk:' || r.finding_id "
                "AND a.revision = ar.assurance_revision "
                "WHERE r.run_id=:r AND r.finding_id=:f"
            ),
            {"r": run_id, "f": finding_id},
        ).first()
        scenarios = [
            {"scenario_id": sid, "title": b["title"], "tier": b["tier"], "basis": b["basis"]}
            for sid, b, v in conn.execute(
                text(
                    "SELECT scenario_id, body, assurance_verdict FROM correlation_scenarios WHERE run_id=:r"
                ),
                {"r": run_id},
            )
            if finding_id in b["finding_ids"] and v == "ACCEPT"
        ]
    risk = (
        {"rubric_version": risk_row[0], "tier": risk_row[1], "provisional_tier": risk_row[2],
         "basis": risk_row[3], "factors": risk_row[4], "missing_evidence": risk_row[5],
         "rationale": risk_row[6], "assurance_verdict": risk_row[7]}
        if risk_row else None
    )  # fmt: skip
    # a tier is shown as business risk only when it is complete AND independently reproduced
    business_risk = risk["tier"] if risk and risk["assurance_verdict"] == "ACCEPT" else None
    pack = c.packs.get(run["policy_version"])
    matched = None
    if pack is not None:
        for o in obs:
            if make_finding_id(pack, o[1], o[0]) == finding_id:
                matched = o
    return {
        "finding": body, "assurance_verdict": verdict, "authoritative": verdict == "ACCEPT",
        "evidence": [
            {"evidence_ref": e[0], "content_hash": e[1], "source": e[2], "tool_version": e[3],
             "collected_at": e[4].isoformat(), "redacted": e[5], "media_type": e[6], "size_bytes": e[7],
             "purged_at": e[8].isoformat() if e[8] else None}
            for e in evidence
        ],
        "observation": (
            {"asset_id": matched[0], "rule_id": matched[1], "observed_value": matched[2],
             "expected_value": matched[3], "outcome": matched[4], "observed_at": matched[5].isoformat()}
            if matched else None
        ),
        "assurance": (
            {"verdict": assurance[0], "defect_codes": assurance[1], "missing_refs": assurance[2],
             "stale_refs": assurance[3], "validation_version": assurance[4],
             "validated_at": assurance[5].isoformat()}
            if assurance else None
        ),
        "risk_explanation": {
            "deterministic": {"severity": body["severity"], "severity_source": body["severity_source"],
                              "confidence": body["confidence"], "policy_version": body["policy_version"]},
            "business_risk": business_risk,  # None unless the rubric inputs were complete
            "risk": risk, "scenarios": scenarios,
            "inferred_links": [], "assumptions": body["assumptions"],
            "ai_narrative": None,  # model text is attached to scenarios/recommendations, never here
        },
    }  # fmt: skip


@router.get("/findings")
def all_findings(
    severity: list[str] = Query(default_factory=list),
    verdict: str = Query(default="ACCEPT", pattern="^(ACCEPT|NEEDS_REVIEW)$"),
    run_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> dict[str, Any]:
    authorize(actor, Permission.FINDING_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        rows = conn.execute(
            text(
                "SELECT f.run_id, f.finding_id, f.severity, f.lifecycle, f.assurance_verdict, "
                "f.body, p.name, count(*) OVER () FROM findings f "
                "JOIN projects p ON p.project_id = f.project_id "
                "WHERE f.assurance_verdict=:v AND (cardinality(CAST(:s AS text[])) = 0 "
                "OR f.severity = ANY(CAST(:s AS text[]))) "
                "AND (CAST(:r AS text) IS NULL OR f.run_id=:r) "
                "ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
                "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, f.finding_id "
                "LIMIT :l OFFSET :o"
            ),
            {"v": verdict, "s": severity, "r": run_id, "l": limit, "o": offset},
        ).all()
    return {
        "items": [
            {"run_id": r[0], "finding_id": r[1], "severity": r[2], "lifecycle": r[3],
             "assurance_verdict": r[4], "title": r[5]["title"], "outcome": r[5]["outcome"],
             "affected_assets": r[5]["affected_assets"], "project_name": r[6],
             "authoritative": r[4] == "ACCEPT"}
            for r in rows
        ],
        "total": rows[0][7] if rows else 0,
    }  # fmt: skip


@router.get("/overview")
def overview(
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
) -> dict[str, Any]:
    authorize(actor, Permission.PROJECT_READ)
    now: datetime = c.clock()
    with tenant_connection(engine, actor.tenant_id) as conn:
        by_state = {
            s: n
            for s, n in conn.execute(
                text("SELECT state, count(*) FROM assessment_runs GROUP BY state")
            )
        }
        active = conn.execute(
            text(
                "SELECT run_id, state, created_at FROM assessment_runs WHERE state <> ALL(:x) "
                "ORDER BY created_at DESC LIMIT 10"
            ),
            {"x": list(OPEN_STATES_EXCLUDED)},
        ).all()
        partial = conn.execute(
            text("SELECT run_id, state, created_at FROM assessment_runs WHERE state='PARTIAL' "
                 "ORDER BY created_at DESC LIMIT 10")
        ).all()  # fmt: skip
        latest = [
            r[0]
            for r in conn.execute(
                text("SELECT DISTINCT ON (project_id) run_id FROM assessment_runs "
                     "WHERE state IN ('REPORT_READY','PARTIAL','CLOSED') "
                     "ORDER BY project_id, created_at DESC")
            )
        ]  # fmt: skip
        ledgers = (
            [
                r[0]
                for r in conn.execute(
                    text("SELECT body FROM coverage_ledger WHERE run_id = ANY(:r)"), {"r": latest}
                )
            ]
            if latest
            else []
        )
        sev = {
            (v, s): n
            for v, s, n in conn.execute(
                text(
                    "SELECT assurance_verdict, severity, count(*) FROM findings "
                    "WHERE lifecycle <> 'RESOLVED' AND severity IN ('CRITICAL','HIGH') "
                    "AND assurance_verdict IN ('ACCEPT','NEEDS_REVIEW') GROUP BY 1,2"
                )
            )
        }
    expected = sum(b["expected_count"] for b in ledgers)
    return {
        "as_of": now.isoformat(),
        "runs": {"total": sum(by_state.values()), "by_state": by_state},
        "active_runs": [{"run_id": r[0], "state": r[1], "created_at": r[2].isoformat()} for r in active],
        "partial_runs": [{"run_id": r[0], "state": r[1], "created_at": r[2].isoformat()} for r in partial],
        "coverage": {
            "basis": "latest finished run per project", "runs_considered": len(latest),
            "segments_total": len(ledgers),
            "segments_incomplete": sum(
                1 for b in ledgers
                if not (b["source_ok"] and b["unknown_count"] == 0 and b["unsupported_count"] == 0
                        and b["reconciled_count"] + b["excluded_count"] >= b["expected_count"])
            ),
            "expected": expected, "reconciled": sum(b["reconciled_count"] for b in ledgers),
            "unknown": sum(b["unknown_count"] for b in ledgers),
            "unsupported": sum(b["unsupported_count"] for b in ledgers),
        },
        "findings": {
            "open_critical_high_authoritative": sev.get(("ACCEPT", "CRITICAL"), 0) + sev.get(("ACCEPT", "HIGH"), 0),
            "critical": sev.get(("ACCEPT", "CRITICAL"), 0), "high": sev.get(("ACCEPT", "HIGH"), 0),
            "pending_review_critical_high": sev.get(("NEEDS_REVIEW", "CRITICAL"), 0) + sev.get(("NEEDS_REVIEW", "HIGH"), 0),
        },
        "connectors": [
            {"adapter_id": a, "enabled": cap.enabled, "permission_ok": cap.permission_ok}
            for a in c.registry.ids() if (cap := c.registry.capability(a)) is not None
        ],
    }  # fmt: skip


@router.get("/audit/events")
def audit_events(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    result: str | None = Query(default=None, pattern="^(SUCCESS|DENIED|FAILURE)$"),
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> dict[str, Any]:
    authorize(actor, Permission.AUDIT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        rows = conn.execute(
            text(
                "SELECT seq, actor, action, resource, result, occurred_at, correlation_id, "
                "count(*) OVER () FROM audit_events WHERE (CAST(:r AS text) IS NULL OR result=:r) "
                "ORDER BY seq DESC LIMIT :l OFFSET :o"
            ),
            {"r": result, "l": limit, "o": offset},
        ).all()
    return {
        "items": [{"seq": r[0], "actor": r[1], "action": r[2], "resource": r[3], "result": r[4],
                   "occurred_at": r[5].isoformat(), "correlation_id": r[6]} for r in rows],
        "total": rows[0][7] if rows else 0,
    }  # fmt: skip


@router.get("/assessments/{run_id}/events/stream")
def event_stream(
    run_id: str,
    cursor: int = Query(default=0, ge=0),
    last_event_id: str | None = Header(default=None),
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> StreamingResponse:
    authorize(actor, Permission.PROJECT_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        _run_or_404(conn, run_id)
    start = cursor
    if last_event_id and last_event_id.isdigit():
        start = max(start, int(last_event_id))  # a reconnecting client resumes after what it saw
    return StreamingResponse(
        stream_events(engine, tenant_id=actor.tenant_id, run_id=run_id, cursor=start),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
            "X-Content-Type-Options": "nosniff",
        },
    )
