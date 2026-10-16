"""Coverage Ledger read model: what was and was not assessed, per project, tenant-wide.

The basis is each project's latest finished run, the same as the Command Center. Completeness is
derived from the ledger contract, never asserted. Gaps are grouped by kind with the assets they
name. Inventory the latest run did not target, and projects never assessed, are gaps too: absence
of a result is shown as absence, not as clean.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import Engine, text

from aisw.api.container import Container
from aisw.api.deps import get_actor, get_engine
from aisw.contracts.domain import CoverageLedger
from aisw.core.db import tenant_connection
from aisw.core.rbac import ActorContext, Permission, authorize

router = APIRouter(prefix="/api/v1")
FINISHED = ("REPORT_READY", "PARTIAL", "CLOSED")
GAP_LABEL = {
    "EXPECTED_ASSET_ABSENT": "Expected but not found",
    "ASSET_UNREACHABLE": "Unreachable",
    "ASSET_UNSUPPORTED": "No compatible collector",
    "UNEXPECTED_ASSET": "Found but not in the inventory (owner unknown)",
    "ZERO_ASSETS_RETURNED": "Tool reported success with zero assets",
    "NO_EXPECTED_ASSET_LIST": "No expected asset list to reconcile against",
}


def _c(request: Request) -> Container:
    c: Container | None = request.app.state.container
    if c is None:
        raise HTTPException(status_code=503, detail="not configured")
    return c


def _gaps(reasons: list[str]) -> list[dict[str, Any]]:
    by: dict[str, list[dict[str, str | None]]] = {}
    for r in reasons:
        kind, _, rest = r.partition(":")
        asset, _, detail = rest.partition(":")
        by.setdefault(kind, []).append({"asset_id": asset or None, "detail": detail or None})
    return [
        {"kind": k, "label": GAP_LABEL.get(k, k.replace("_", " ").capitalize()),
         "count": len(v), "items": [i for i in v if i["asset_id"]][:100]}
        for k, v in sorted(by.items())
    ]  # fmt: skip


def _segment(body: dict[str, Any], now: datetime) -> dict[str, Any]:
    ledger = CoverageLedger.model_validate(body)
    age = (now - ledger.last_success_at).days if ledger.last_success_at else None
    return {
        "segment": ledger.segment, "expected": ledger.expected_count,
        "discovered": ledger.discovered_count, "reconciled": ledger.reconciled_count,
        "excluded": ledger.excluded_count, "unsupported": ledger.unsupported_count,
        "unknown": ledger.unknown_count, "source_ok": ledger.source_ok,
        "complete": ledger.is_complete,
        "assessed_by_outcome": {k.value: v for k, v in ledger.assessed_by_outcome.items()},
        "last_success_at": ledger.last_success_at.isoformat() if ledger.last_success_at else None,
        "age_days": age, "gaps": _gaps(ledger.reasons),
    }  # fmt: skip


@router.get("/coverage")
def coverage_ledger(
    project_id: str | None = Query(default=None, max_length=64),
    incomplete_only: bool = False,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
) -> dict[str, Any]:
    actor = actor.on(project_id)
    authorize(actor, Permission.PROJECT_READ)
    now: datetime = c.clock()
    with tenant_connection(engine, actor.tenant_id) as conn:
        projects = conn.execute(
            text("SELECT project_id::text, name, environment FROM projects "
                 "WHERE CAST(:p AS text) IS NULL OR project_id::text=:p ORDER BY name"),
            {"p": project_id},
        ).all()  # fmt: skip
        latest = {
            r[0]: r
            for r in conn.execute(
                text("SELECT DISTINCT ON (project_id) project_id::text, run_id, state, created_at, "
                     "partial FROM assessment_runs WHERE state = ANY(:s) "
                     "ORDER BY project_id, created_at DESC, run_id DESC"),
                {"s": list(FINISHED)},
            )
        }  # fmt: skip
        runs = [r[1] for r in latest.values()]
        ledgers: dict[str, list[dict[str, Any]]] = {}
        targeted: dict[str, set[tuple[str, str]]] = {}
        if runs:
            for run_id, body in conn.execute(
                text("SELECT run_id, body FROM coverage_ledger WHERE run_id = ANY(:r) "
                     "ORDER BY segment"), {"r": runs},
            ):  # fmt: skip
                ledgers.setdefault(run_id, []).append(body)
            for run_id, kind, sel in conn.execute(
                text("SELECT DISTINCT run_id, target_kind, target_selector FROM run_tasks "
                     "WHERE run_id = ANY(:r)"), {"r": runs},
            ):  # fmt: skip
                targeted.setdefault(run_id, set()).add((kind, sel))
        inventory: dict[str, list[tuple[str, str]]] = {}
        for pid, kind, sel in conn.execute(
            text("SELECT project_id::text, kind, selector FROM inventory_entries ORDER BY kind, selector")
        ):  # fmt: skip
            inventory.setdefault(pid, []).append((kind, sel))

    out, never = [], []
    for pid, name, env in projects:
        run = latest.get(pid)
        if run is None:
            never.append({"project_id": pid, "name": name, "environment": env,
                          "inventory_entries": len(inventory.get(pid, []))})  # fmt: skip
            continue
        segments = [_segment(b, now) for b in ledgers.get(run[1], [])]
        untargeted = [{"kind": k, "selector": s} for k, s in inventory.get(pid, [])
                      if (k, s) not in targeted.get(run[1], set())]  # fmt: skip
        complete = bool(segments) and all(s["complete"] for s in segments) and not untargeted
        out.append({
            "project_id": pid, "name": name, "environment": env,
            "run": {"run_id": run[1], "state": run[2], "created_at": run[3].isoformat(),
                    "partial": run[4]},
            "complete": complete, "segments": segments, "untargeted_inventory": untargeted,
            "totals": {k: sum(s[k] for s in segments)
                       for k in ("expected", "discovered", "reconciled", "unsupported", "unknown")},
        })  # fmt: skip
    return {
        "as_of": now.isoformat(), "basis": "latest finished run per project",
        "projects": [p for p in out if not (incomplete_only and p["complete"])],
        "never_assessed": never,
        "summary": {
            "projects": len(projects), "assessed": len(out), "never_assessed": len(never),
            "complete": sum(p["complete"] for p in out),
            "incomplete": sum(not p["complete"] for p in out),
        },
    }  # fmt: skip
