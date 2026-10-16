"""Scope manifest and inventory routes. All authorisation decisions are made server-side by Agent 0."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError

from aisw.adapters.url_smoke import url_asset_id
from aisw.api.container import Container
from aisw.api.deps import correlation_id, get_actor, get_engine
from aisw.authz.gate import GateOutcome
from aisw.authz.net_guard import NetGuardError, canonicalize_url
from aisw.authz.service import ScopeService
from aisw.contracts.base import NonEmpty, Slug, StrictModel
from aisw.contracts.manifest import (
    MaintenanceWindow,
    ManifestProfile,
    Quotas,
    ScopeManifest,
    ScopeManifestBody,
    ScopeTarget,
)
from aisw.core.audit import append_audit
from aisw.core.db import tenant_connection
from aisw.core.rbac import ActorContext, Permission, authorize

router = APIRouter(prefix="/api/v1")


def container(request: Request) -> Container:
    c: Container | None = request.app.state.container
    if c is None or c.service is None:
        raise HTTPException(status_code=503, detail="manifest signing is not configured")
    return c


def service(c: Container = Depends(container)) -> ScopeService:
    if c.service is None:  # container() already guarantees this; keeps the type honest
        raise HTTPException(status_code=503, detail="manifest signing is not configured")
    return c.service


class ManifestCreate(StrictModel):
    """No tenant field: the tenant is always the authenticated one."""

    project_id: Slug
    targets: list[ScopeTarget] = Field(min_length=1)
    exclusions: list[ScopeTarget] = Field(default_factory=list)
    domains: list[Slug] = Field(min_length=1)
    allowed_adapters: list[Slug] = Field(min_length=1)
    profiles: dict[Slug, ManifestProfile] = Field(min_length=1)
    allowed_ports: list[int] = Field(default_factory=list)
    internal_range_authorization: list[NonEmpty] = Field(default_factory=list)
    windows: list[MaintenanceWindow] = Field(default_factory=list)
    quotas: Quotas = Field(default_factory=Quotas)
    evidence_retention_days: int = Field(ge=1)
    policy_version: NonEmpty
    expires_at: datetime


class ApproveRequest(StrictModel):
    acknowledge_active_adapters: list[Slug] = Field(default_factory=list)


class InventoryCreate(StrictModel):
    project_id: Slug
    kind: NonEmpty
    selector: NonEmpty
    expected_assets: list[Slug] = Field(default_factory=list)


def _manifest_json(m: ScopeManifest) -> dict[str, Any]:
    d = m.model_dump(mode="json")
    d["approved_by"] = list(m.approved_by)
    return d


def _outcome_json(o: GateOutcome) -> dict[str, Any]:
    return {
        "decision": o.decision.model_dump(mode="json"),
        "issues": [{"code": i.code, "severity": i.severity, "detail": i.detail} for i in o.issues],
    }


@router.post("/inventory", status_code=201)
def create_inventory(
    body: InventoryCreate,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    authorize(actor, Permission.INVENTORY_MANAGE)
    resolved = "inv-" + hashlib.sha256(f"{body.kind}|{body.selector}".encode()).hexdigest()[:12]
    expected = body.expected_assets
    if body.kind == "url" and not expected:  # a URL source expects exactly its own origin asset
        try:
            expected = [url_asset_id(canonicalize_url(body.selector))]
        except NetGuardError as exc:
            raise HTTPException(status_code=422, detail=f"invalid url: {exc.code}") from exc
    try:
        with tenant_connection(engine, actor.tenant_id) as conn:
            conn.execute(
                text(
                    "INSERT INTO inventory_entries (tenant_id, project_id, kind, selector, "
                    "resolved_id, expected_assets, created_by) VALUES (:t, :p, :k, :s, :r, "
                    "CAST(:e AS jsonb), :by)"
                ),
                {"t": actor.tenant_id, "p": body.project_id, "k": body.kind, "s": body.selector,
                 "r": resolved, "e": json.dumps(expected), "by": actor.actor_id},
            )  # fmt: skip
            append_audit(
                conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="inventory.create",
                resource=f"inventory:{resolved}", result="SUCCESS", correlation_id=cid,
            )  # fmt: skip
    except IntegrityError as exc:
        raise HTTPException(
            status_code=409, detail="inventory entry exists or project unknown"
        ) from exc
    return {"resolved_id": resolved, "kind": body.kind, "selector": body.selector}


@router.post("/scope-manifests", status_code=201)
def create_manifest(
    body: ManifestCreate,
    actor: ActorContext = Depends(get_actor),
    svc: ScopeService = Depends(service),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    data = body.model_dump(exclude={"project_id"})
    manifest_body = ScopeManifestBody.model_validate({**data, "tenant_id": actor.tenant_id,
                                                      "project_id": body.project_id})  # fmt: skip
    m, outcome = svc.create_draft(actor, body.project_id, manifest_body, cid=cid)
    return {"manifest": _manifest_json(m), **_outcome_json(outcome)}


@router.get("/scope-manifests/{manifest_id}")
def get_manifest(
    manifest_id: str,
    actor: ActorContext = Depends(get_actor),
    engine: Engine = Depends(get_engine),
) -> dict[str, Any]:
    authorize(actor, Permission.PROJECT_READ)
    from aisw.authz.service import row_to_manifest

    try:
        with tenant_connection(engine, actor.tenant_id) as conn:
            row = conn.execute(
                text("SELECT * FROM scope_manifests WHERE manifest_id=:m"), {"m": manifest_id}
            ).mappings().first()  # fmt: skip
    except Exception:
        row = None
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    return _manifest_json(row_to_manifest(row))


@router.post("/scope-manifests/{manifest_id}/preflight")
def preflight(
    manifest_id: str,
    actor: ActorContext = Depends(get_actor),
    svc: ScopeService = Depends(service),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    return _outcome_json(svc.preflight(actor, manifest_id, cid=cid))


@router.post("/scope-manifests/{manifest_id}/approve")
def approve(
    manifest_id: str,
    body: ApproveRequest,
    actor: ActorContext = Depends(get_actor),
    svc: ScopeService = Depends(service),
    cid: str = Depends(correlation_id),
) -> dict[str, Any]:
    m = svc.approve(
        actor, manifest_id,
        acknowledge_active_adapters=frozenset(body.acknowledge_active_adapters), cid=cid,
    )  # fmt: skip
    return _manifest_json(m)
