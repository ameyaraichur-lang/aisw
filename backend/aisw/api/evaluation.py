"""Evaluation Lab read models: per-run scorecard against the §7.2 targets, and a trend (ADR-039).

Scorecards are computed on read from what each run recorded, so they cannot drift from the
evidence. The validator catch-rate is not a property of a run and is reported as NOT_MEASURED here;
tools/eval_targets.py adds it from the offline labelled evaluation.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import Engine, text

from aisw.api.deps import get_actor, get_engine
from aisw.core.db import tenant_connection
from aisw.core.project_roles import project_of_run
from aisw.core.rbac import ActorContext, Permission, authorize
from aisw.evaluation import answer_key
from aisw.evaluation.scorecard import collect, run_scorecard, score

router = APIRouter(prefix="/api/v1/evaluation")
TREND = ("asset_reconciliation", "status_coverage", "detection_recall", "detection_precision",
         "finding_traceability", "unsupported_compliance_claims", "reproducibility")  # fmt: skip


@router.get("/answer-keys")
def answer_keys(actor: ActorContext = Depends(get_actor)) -> list[dict[str, Any]]:
    authorize(actor, Permission.FINDING_READ)
    out = []
    for key_id in answer_key.KEY_IDS:
        k = answer_key.load(key_id)
        out.append({
            "key_id": k.key_id, "fixture_set": k.fixture_set, "policy_version": k.policy_version,
            "note": k.note, "cmdb_expected_assets": k.cmdb_expected_assets,
            "known_issues": len(k.known_issues), "known_clean": len(k.known_clean),
        })  # fmt: skip
    return out


@router.get("/runs/{run_id}/scorecard")
def scorecard(
    run_id: str, actor: ActorContext = Depends(get_actor), engine: Engine = Depends(get_engine)
) -> dict[str, Any]:
    actor = project_of_run(engine, actor, run_id)
    authorize(actor, Permission.FINDING_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        card = run_scorecard(conn, run_id)
    if card is None:
        raise HTTPException(404, "no reported run with that id")
    return card


@router.get("/runs")
def trend(
    project_id: str | None = Query(default=None, max_length=64),
    fixture_set: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=10, ge=1, le=20),
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> list[dict[str, Any]]:
    """Recent reported runs, newest first. Reproducibility compares runs within this window."""
    actor = actor.on(project_id)
    authorize(actor, Permission.FINDING_READ)
    with tenant_connection(engine, actor.tenant_id) as conn:
        runs = conn.execute(
            text("SELECT r.run_id, r.project_id::text AS project_id, r.created_at, r.state "
                 "FROM assessment_runs r WHERE EXISTS (SELECT 1 FROM reports p "
                 "WHERE p.run_id=r.run_id) AND (CAST(:p AS text) IS NULL OR r.project_id::text=:p) "
                 "AND (CAST(:fx AS text) IS NULL OR EXISTS (SELECT 1 FROM run_tasks t WHERE "
                 "t.run_id=r.run_id AND t.adapter_id='fixture' AND t.params->>'fixture_set'=:fx)) "
                 "ORDER BY r.created_at DESC, r.run_id DESC LIMIT :l"),
            {"p": project_id, "fx": fixture_set, "l": limit},
        ).all()  # fmt: skip
        facts = [(r, collect(conn, r.run_id)) for r in runs]
    out: list[dict[str, Any]] = []
    for i, (r, got) in enumerate(facts):
        if got is None:
            continue
        f, sig = got
        older = next(((o.run_id, g[0].digest) for o, g in facts[i + 1:]
                      if g is not None and g[1] == sig), None)  # fmt: skip
        card = score(f, answer_key.for_fixture(f.fixture_set, f.policy_version), previous=older)
        out.append({
            "run_id": r.run_id, "project_id": r.project_id, "state": r.state,
            "created_at": r.created_at.isoformat(), "fixture_set": f.fixture_set,
            "answer_key": card["answer_key"]["key_id"] if card["answer_key"] else None,
            "summary": card["summary"],
            "metrics": {m["metric"]: {"status": m["status"], "value": m["value"]}
                        for m in card["metrics"] if m["metric"] in TREND},
        })  # fmt: skip
    return out
