"""Asset Explorer read models: the reconciled asset view Agent 1 maintains, per project.

Owner and criticality are shown with their source or as unknown; nothing is inferred here. An
asset's posture is the latest observation per rule, with the run that produced it, so a stale
result is visibly old rather than silently current.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import Engine, text

from aisw.api.deps import get_actor, get_engine
from aisw.core.db import tenant_connection
from aisw.core.rbac import ActorContext, Permission, authorize

router = APIRouter(prefix="/api/v1")


def _asset(r: Any) -> dict[str, Any]:
    return {
        "project_id": r.project_id, "project_name": r.project_name, "asset_id": r.asset_id,
        "asset_type": r.asset_type, "native_ids": r.native_ids, "attrs": r.attrs,
        "environment": r.environment, "owner": r.owner, "owner_source": r.owner_source,
        "criticality": r.criticality, "criticality_source": r.criticality_source,
        "technology": r.technology, "match_confidence": r.match_confidence,
        "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat(),
        "last_run_id": r.run_id,
    }  # fmt: skip


COLUMNS = (
    "a.project_id::text AS project_id, p.name AS project_name, a.asset_id, a.asset_type, "
    "a.native_ids, a.attrs, a.environment, a.owner, a.owner_source, a.criticality, "
    "a.criticality_source, a.technology, a.match_confidence, a.first_seen, a.last_seen, a.run_id"
)


@router.get("/assets")
def list_assets(
    project_id: str | None = None,
    asset_type: str | None = Query(default=None, max_length=40),
    q: str | None = Query(default=None, max_length=100),
    confidence: str | None = Query(default=None, pattern="^(HIGH|MEDIUM|LOW)$"),
    owner: str | None = Query(default=None, pattern="^(known|unknown)$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> dict[str, Any]:
    actor = actor.on(project_id)
    authorize(actor, Permission.PROJECT_READ)
    like = f"%{q.replace('%', '').replace('_', '')}%" if q else None
    where = (
        "(CAST(:p AS text) IS NULL OR a.project_id::text=:p) "
        "AND (CAST(:t AS text) IS NULL OR a.asset_type=:t) "
        "AND (CAST(:c AS text) IS NULL OR a.match_confidence=:c) "
        "AND (CAST(:o AS text) IS NULL OR (a.owner IS NOT NULL) = (:o = 'known')) "
        "AND (CAST(:q AS text) IS NULL OR a.asset_id ILIKE :q OR a.native_ids::text ILIKE :q)"
    )
    params = {"p": project_id, "t": asset_type, "c": confidence, "o": owner, "q": like}
    with tenant_connection(engine, actor.tenant_id) as conn:
        rows = conn.execute(
            text(f"SELECT {COLUMNS}, count(*) OVER () AS total FROM assets a "  # noqa: S608
                 f"JOIN projects p ON p.project_id=a.project_id WHERE {where} "
                 "ORDER BY p.name, a.asset_type, a.asset_id LIMIT :l OFFSET :off"),
            {**params, "l": limit, "off": offset},
        ).all()  # fmt: skip
        facets = conn.execute(
            text("SELECT a.asset_type, count(*), count(*) FILTER (WHERE a.owner IS NULL), "  # noqa: S608
                 "count(*) FILTER (WHERE a.match_confidence='LOW') FROM assets a "
                 f"JOIN projects p ON p.project_id=a.project_id WHERE {where.replace('a.asset_type=:t', 'TRUE')} "
                 "GROUP BY 1 ORDER BY 1"),
            params,
        ).all()  # fmt: skip
    return {
        "items": [_asset(r) for r in rows],
        "total": rows[0].total if rows else 0,
        "types": [
            {"asset_type": f[0], "count": f[1], "owner_unknown": f[2], "low_confidence": f[3]}
            for f in facets
        ],  # fmt: skip
    }


@router.get("/assets/{project_id}/{asset_id}")
def asset_detail(
    project_id: str,
    asset_id: str,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> dict[str, Any]:
    actor = actor.on(project_id)
    authorize(actor, Permission.PROJECT_READ)
    can_read_findings = actor.can(Permission.FINDING_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        row = conn.execute(
            text(f"SELECT {COLUMNS} FROM assets a JOIN projects p ON p.project_id=a.project_id "  # noqa: S608
                 "WHERE a.project_id::text=:p AND a.asset_id=:a"),
            {"p": project_id, "a": asset_id},
        ).first()  # fmt: skip
        if row is None:
            raise HTTPException(status_code=404, detail="not found")
        posture = conn.execute(
            text("SELECT DISTINCT ON (o.rule_id) o.rule_id, o.outcome, o.observed_value, "
                 "o.expected_value, o.observed_at, o.run_id, o.source FROM observations o "
                 "JOIN assessment_runs r ON r.run_id=o.run_id "
                 "WHERE r.project_id::text=:p AND o.asset_id=:a "
                 "ORDER BY o.rule_id, r.created_at DESC, o.observed_at DESC, o.run_id DESC"),
            {"p": project_id, "a": asset_id},
        ).all()  # fmt: skip
        runs = conn.execute(
            text("SELECT s.run_id, s.segment, s.status, s.reason, r.created_at FROM run_asset_status s "
                 "JOIN assessment_runs r ON r.run_id=s.run_id WHERE r.project_id::text=:p "
                 "AND s.asset_id=:a ORDER BY r.created_at DESC, s.run_id LIMIT 20"),
            {"p": project_id, "a": asset_id},
        ).all()  # fmt: skip
        findings = (
            conn.execute(
                text("SELECT DISTINCT ON (f.stable_dedupe_key) f.run_id, f.finding_id, f.severity, "
                     "f.lifecycle, f.body->>'title', r.created_at FROM findings f "
                     "JOIN assessment_runs r ON r.run_id=f.run_id WHERE f.project_id::text=:p "
                     "AND f.assurance_verdict='ACCEPT' AND f.body->'affected_assets' ? :a "
                     "ORDER BY f.stable_dedupe_key, r.created_at DESC"),
                {"p": project_id, "a": asset_id},
            ).all()
            if can_read_findings
            else []
        )  # fmt: skip
    return {
        **_asset(row),
        "posture": [
            {"rule_id": p[0], "outcome": p[1], "observed": p[2], "expected": p[3],
             "observed_at": p[4].isoformat(), "run_id": p[5], "source": p[6]}
            for p in posture
        ],
        "runs": [{"run_id": r[0], "segment": r[1], "status": r[2], "reason": r[3],
                  "at": r[4].isoformat()} for r in runs],
        "findings": [{"run_id": f[0], "finding_id": f[1], "severity": f[2], "lifecycle": f[3],
                      "title": f[4]} for f in findings],
        "findings_visible": can_read_findings,
        "relationships": None,  # not modelled yet: no edge is ever invented (ADR-010)
    }  # fmt: skip
