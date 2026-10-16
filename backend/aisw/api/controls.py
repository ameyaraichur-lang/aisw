"""Control Matrix: pack controls, their latest outcome in a run, and reviewed framework mappings.

A mapping is a proposal until this tenant's policy owner approves it (ADR-032). Approving one changes
how it is labelled, never a control outcome.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import Engine, text

from aisw.api.assessments import _run_or_404
from aisw.api.container import Container
from aisw.api.deps import correlation_id, get_actor, get_engine
from aisw.contracts.base import NonEmpty, StrictModel, canonical_hash
from aisw.core.audit import append_audit
from aisw.core.db import tenant_connection
from aisw.core.rbac import ActorContext, Permission, authorize
from aisw.core.redaction import redact_text
from aisw.policy import mappings
from aisw.policy.engine import PolicyPack

router = APIRouter(prefix="/api/v1")
FINAL_RUN = {"REPORT_READY", "PARTIAL", "CLOSED"}


def _c(request: Request) -> Container:
    c: Container | None = request.app.state.container
    if c is None:
        raise HTTPException(status_code=503, detail="not configured")
    return c


def latest_reviews(conn: Any, catalog: mappings.Catalog) -> dict[str, dict[str, Any]]:
    rows = conn.execute(
        text(
            "SELECT DISTINCT ON (mapping_key) mapping_key, decision, reason, decided_by, decided_at "
            "FROM framework_mapping_reviews WHERE catalog_version=:v "
            "ORDER BY mapping_key, seq DESC"
        ),
        {"v": catalog.version},
    ).all()
    return {
        r[0]: {"status": r[1], "reason": r[2], "reviewed_by": r[3],
               "reviewed_at": r[4].isoformat()}
        for r in rows
    }  # fmt: skip


def effective(
    catalog: mappings.Catalog, reviews: dict[str, dict[str, Any]], pack_control: str
) -> list[dict[str, Any]]:
    out = []
    for m in catalog.for_control(pack_control):
        fw = catalog.framework(m.framework)
        r = reviews.get(m.key)
        out.append({
            "key": m.key, "framework": m.framework, "version": fw.version,
            "control_id": m.control_id, "title": catalog.title(m),
            "status": r["status"] if r else "NEEDS_REVIEW",
            "reviewed_by": r["reviewed_by"] if r else None,
            "reviewed_at": r["reviewed_at"] if r else None,
            "reason": r["reason"] if r else None,
        })  # fmt: skip
    return out


def _matrix(pack: PolicyPack, reviews: dict[str, dict[str, Any]],
            outcomes: dict[str, str] | None) -> list[dict[str, Any]]:  # fmt: skip
    catalog = mappings.builtin()
    controls: dict[str, list[Any]] = {}
    for rule in pack.rules:
        controls.setdefault(rule.control_id, []).append(rule)
    return [
        {"control_id": ctrl,
         "rules": [{"rule_id": r.rule_id, "title": r.title, "severity": r.severity.value}
                   for r in rules],
         "outcome": outcomes.get(ctrl) if outcomes is not None else None,
         "mappings": effective(catalog, reviews, ctrl)}
        for ctrl, rules in controls.items()
    ]  # fmt: skip


@router.get("/control-matrix")
def control_matrix(
    run_id: str | None = None,
    policy_version: str | None = None,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
) -> dict[str, Any]:
    authorize(actor, Permission.PROJECT_READ)
    catalog = mappings.builtin()
    with tenant_connection(engine, actor.tenant_id) as conn:
        run, outcomes = None, None
        if run_id is not None:
            run = _run_or_404(conn, run_id)
            policy_version = run["policy_version"]
            outcomes = {
                r[0]: r[1]
                for r in conn.execute(
                    text("SELECT control_id, outcome FROM control_assessments WHERE run_id=:r"),
                    {"r": run_id},
                )
            }
        if policy_version is None:
            raise HTTPException(status_code=422, detail="give a run_id or a policy_version")
        pack = c.packs.get(policy_version)
        if pack is None:
            raise HTTPException(status_code=404, detail="unknown policy pack")
        reviews = latest_reviews(conn, catalog)
    rows = _matrix(pack, reviews, outcomes)
    counts = {s: 0 for s in ("APPROVED", "NEEDS_REVIEW", "REJECTED")}
    for row in rows:
        for m in row["mappings"]:
            counts[m["status"]] += 1
    return {
        "policy_version": policy_version, "pack_framework": pack.framework.model_dump(),
        "run_id": run_id, "final": run is not None and run["state"] in FINAL_RUN,
        "catalog_version": catalog.version, "notice": catalog.notice,
        "frameworks": [f.model_dump(exclude={"id_pattern"}) for f in catalog.frameworks],
        "controls": rows, "summary": counts,
        "can_review": actor.can(Permission.POLICY_APPROVE),
    }  # fmt: skip


class MappingReviewRequest(StrictModel):
    key: NonEmpty
    decision: Literal["APPROVED", "REJECTED", "NEEDS_REVIEW"]
    reason: NonEmpty


@router.post("/framework-mappings/reviews")
def review_mapping(
    body: MappingReviewRequest,
    response: Response,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    c: Container = Depends(_c),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    authorize(actor, Permission.POLICY_APPROVE)
    catalog = mappings.builtin()
    if catalog.get(body.key) is None:
        raise HTTPException(status_code=404, detail="unknown mapping")
    reason = redact_text(body.reason)[:1000]
    with tenant_connection(engine, actor.tenant_id) as conn:
        conn.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"mapping:{body.key}"}
        )
        prior = latest_reviews(conn, catalog).get(body.key)
        before = prior["status"] if prior else "NEEDS_REVIEW"
        if prior and prior["status"] == body.decision and prior["reason"] == reason:
            response.headers["Idempotent-Replay"] = "true"
            return {"key": body.key, "status": body.decision, "replayed": True}
        if prior is None and body.decision == "NEEDS_REVIEW":
            raise HTTPException(status_code=409, detail="mapping is already awaiting review")
        conn.execute(
            text(
                "INSERT INTO framework_mapping_reviews (review_id, tenant_id, catalog_version, "
                "mapping_key, decision, reason, decided_by, decided_at) VALUES "
                "(:i, :t, :v, :k, :d, :why, :b, :n)"
            ),
            {"i": str(uuid.uuid4()), "t": actor.tenant_id, "v": catalog.version, "k": body.key,
             "d": body.decision, "why": reason, "b": actor.actor_id, "n": c.clock()},
        )  # fmt: skip
        append_audit(
            conn, tenant_id=actor.tenant_id, actor=actor.actor_id,
            action=f"framework_mapping.{body.decision.lower()}",
            resource=f"framework_mapping:{body.key}", result="SUCCESS", correlation_id=cid,
            before_hash=canonical_hash({"status": before}),
            after_hash=canonical_hash({"status": body.decision, "reason": reason}),
        )  # fmt: skip
    return {"key": body.key, "status": body.decision, "reviewed_by": actor.actor_id}
