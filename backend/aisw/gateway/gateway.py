"""Tool gateway: the single choke point between the orchestrator and any adapter.

Fail-closed pipeline. A request reaches ``adapter.execute`` only if EVERY check passes, and every
outcome (allowed or denied, with reason codes) is audited. Requests are structured objects: free
text, model output or evidence content can never select an adapter, profile or target, and the
registry refuses any adapter capable of mutating infrastructure.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from aisw.authz import scope as scope_rules
from aisw.authz.net_guard import (
    NetGuardError,
    Resolver,
    VettedTarget,
    canonicalize_url,
    resolve_and_vet,
    system_resolver,
)
from aisw.authz.signing import SignatureVerifier, signing_payload
from aisw.contracts.base import NonEmpty, Sha256, Slug, StrictModel
from aisw.contracts.enums import ManifestStatus, ProfileClass
from aisw.gateway.registry import AdapterJob, AdapterRegistry
from aisw.gateway.stores import AuditSink, AuthorizationStore

ALLOWED_KINDS = {"cloud_account", "region", "asset_group", "cidr", "host", "url"}


class ToolRequest(StrictModel):
    tenant_id: Slug
    project_id: Slug
    run_id: Slug
    task_id: Slug
    task_type: Slug
    adapter_id: Slug
    profile: Slug
    target_kind: NonEmpty
    target_selector: NonEmpty
    params: dict[str, Any] = Field(default_factory=dict)
    permit_id: Slug
    manifest_hash: Sha256


class GatewayDenied(Exception):
    def __init__(self, reason_codes: list[str]) -> None:
        super().__init__(",".join(reason_codes))
        self.reason_codes = reason_codes


@dataclass(frozen=True)
class GatewayResult:
    adapter_result: Any
    vetted: VettedTarget | None
    warnings: tuple[str, ...] = ()


class QuotaTracker:
    """Per-run concurrency and request budget (in-memory; persisted by the orchestrator in M3)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._in_flight: dict[str, int] = {}
        self._used: dict[str, int] = {}

    def acquire(self, run_id: str, *, max_concurrency: int, max_requests: int, cost: int) -> bool:
        with self._lock:
            if self._in_flight.get(run_id, 0) >= max_concurrency:
                return False
            if self._used.get(run_id, 0) + cost > max_requests:
                return False
            self._in_flight[run_id] = self._in_flight.get(run_id, 0) + 1
            self._used[run_id] = self._used.get(run_id, 0) + cost
            return True

    def release(self, run_id: str) -> None:
        with self._lock:
            self._in_flight[run_id] = max(0, self._in_flight.get(run_id, 1) - 1)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class ToolGateway:
    def __init__(
        self,
        *,
        registry: AdapterRegistry,
        store: AuthorizationStore,
        verifier: SignatureVerifier,
        audit: AuditSink,
        resolver: Resolver = system_resolver,
        clock: Callable[[], datetime] = _utcnow,
        quotas: QuotaTracker | None = None,
    ) -> None:
        self.registry = registry
        self.store = store
        self.verifier = verifier
        self.audit = audit
        self.resolver = resolver
        self.clock = clock
        self.quotas = quotas or QuotaTracker()
        self.dispatched = 0  # number of adapter executions actually started

    # ----------------------------------------------------------------------------------------
    def dispatch(self, req: ToolRequest) -> GatewayResult:
        resource = f"adapter:{req.adapter_id}/task:{req.task_id}"
        try:
            job, vetted, warnings, run_limits = self._authorize(req)
        except GatewayDenied as exc:
            self._audit(req, "gateway.dispatch", resource, "DENIED", exc.reason_codes)
            raise
        adapter = self.registry.get(req.adapter_id)
        if adapter is None:  # pragma: no cover - checked in _authorize
            raise GatewayDenied(["UNKNOWN_ADAPTER"])
        max_conc, max_req, cost = run_limits
        if not self.quotas.acquire(
            req.run_id, max_concurrency=max_conc, max_requests=max_req, cost=cost
        ):
            self._audit(req, "gateway.dispatch", resource, "DENIED", ["QUOTA_EXCEEDED"])
            raise GatewayDenied(["QUOTA_EXCEEDED"])
        try:
            self._audit(req, "gateway.dispatch", resource, "SUCCESS", ["AUTHORIZED"])
            self.dispatched += 1
            result = adapter.execute(job)
        finally:
            self.quotas.release(req.run_id)
        return GatewayResult(result, vetted, warnings)

    # ----------------------------------------------------------------------------------------
    def _authorize(
        self, req: ToolRequest
    ) -> tuple[AdapterJob, VettedTarget | None, tuple[str, ...], tuple[int, int, int]]:
        now = self.clock()

        # 1) allowlist: unknown adapters (e.g. "shell", "exec", "remediate") do not exist
        adapter = self.registry.get(req.adapter_id)
        if adapter is None:
            raise GatewayDenied(["UNKNOWN_ADAPTER"])
        cap = adapter.capability
        if cap.mutates_infrastructure:  # defence in depth; registration already refuses these
            raise GatewayDenied(["MUTATING_ADAPTER_FORBIDDEN"])
        if not cap.enabled or not cap.permission_ok:
            raise GatewayDenied(["CONNECTOR_DENIED"])
        if req.target_kind not in ALLOWED_KINDS or req.target_kind not in cap.target_kinds:
            raise GatewayDenied(["TARGET_KIND_NOT_SUPPORTED"])

        # 2) permit: exists in THIS tenant, bound to this run/project, not revoked
        loaded = self.store.load(req.tenant_id, req.permit_id)
        if loaded is None:
            raise GatewayDenied(["PERMIT_NOT_FOUND"])
        permit, manifest = loaded.permit, loaded.manifest
        if loaded.revoked:
            raise GatewayDenied(["PERMIT_REVOKED"])
        if (permit.tenant_id, permit.project_id, permit.run_id) != (
            req.tenant_id, req.project_id, req.run_id,
        ):  # fmt: skip
            raise GatewayDenied(["PERMIT_BINDING_MISMATCH"])

        # 3) manifest integrity: approved, unexpired, hash recomputed, signature verified
        body = manifest.body
        if manifest.status is not ManifestStatus.APPROVED:
            raise GatewayDenied(["MANIFEST_NOT_APPROVED"])
        if body.expires_at <= now:
            raise GatewayDenied(["MANIFEST_EXPIRED"])
        if (
            body.hash() != manifest.canonical_hash
            or permit.manifest_hash != manifest.canonical_hash
        ):
            raise GatewayDenied(["HASH_MISMATCH"])
        if req.manifest_hash != permit.manifest_hash:
            raise GatewayDenied(["STALE_HASH"])
        if not (manifest.key_id and manifest.signature) or not self.verifier.verify(
            manifest.key_id,
            signing_payload(
                tenant_id=body.tenant_id, project_id=body.project_id,
                manifest_id=manifest.manifest_id, version=manifest.version,
                canonical_hash=manifest.canonical_hash,
            ),
            manifest.signature,
        ):  # fmt: skip
            raise GatewayDenied(["BAD_SIGNATURE"])
        if (body.tenant_id, body.project_id) != (req.tenant_id, req.project_id):
            raise GatewayDenied(["CROSS_TENANT"])

        # 4) permit validity window and task type
        if not permit.is_valid_at(
            now, manifest_hash=manifest.canonical_hash, task_type=req.task_type
        ):
            raise GatewayDenied(["PERMIT_EXPIRED_OR_TASK_NOT_ALLOWED"])

        # 5) adapter/profile authorised by the manifest, class verified against the registry
        if req.adapter_id not in body.allowed_adapters:
            raise GatewayDenied(["ADAPTER_NOT_IN_MANIFEST"])
        mp = body.profiles.get(req.adapter_id)
        if mp is None or mp.profile_id != req.profile:
            raise GatewayDenied(["PROFILE_NOT_IN_MANIFEST"])
        if cap.profiles.get(req.profile) is not mp.profile_class:
            raise GatewayDenied(["PROFILE_CLASS_MISMATCH"])
        if mp.profile_class is ProfileClass.ACTIVE and not manifest.approved_by:
            raise GatewayDenied(["ACTIVE_PROFILE_NOT_APPROVED"])

        # 6) maintenance window
        if body.windows and not any(w.start <= now <= w.end for w in body.windows):
            raise GatewayDenied(["OUTSIDE_MAINTENANCE_WINDOW"])

        # 7) target inside scope and outside exclusions; URLs get DNS/egress vetting at dispatch
        if not scope_rules.in_scope(body, req.target_kind, req.target_selector):
            raise GatewayDenied(["TARGET_OUT_OF_SCOPE"])
        vetted: VettedTarget | None = None
        warnings: tuple[str, ...] = ()
        if req.target_kind == "url":
            try:
                vetted = resolve_and_vet(
                    canonicalize_url(req.target_selector),
                    allowed_ports=body.allowed_ports,
                    internal_ranges=body.internal_range_authorization,
                    resolver=self.resolver,
                )
            except NetGuardError as exc:
                raise GatewayDenied([exc.code]) from exc
            warnings = vetted.warnings

        # 8) parameters must satisfy the adapter's strict schema; no schema means no parameters
        params = self._validate_params(cap.param_model, req.params)
        cost = self._estimate(adapter, params)

        job = AdapterJob(
            tenant_id=req.tenant_id, project_id=req.project_id, run_id=req.run_id,
            task_id=req.task_id, profile=req.profile, target_kind=req.target_kind,
            target_selector=req.target_selector, params=params,
            pinned_addresses=vetted.addresses if vetted else (), request_budget=cost,
        )  # fmt: skip
        return job, vetted, warnings, (body.quotas.max_concurrency, body.quotas.max_requests, cost)

    @staticmethod
    def _validate_params(model: type[BaseModel] | None, params: dict[str, Any]) -> dict[str, Any]:
        if model is None:
            if params:
                raise GatewayDenied(["PARAMS_NOT_ALLOWED"])
            return {}
        try:
            return model.model_validate(params).model_dump(mode="json")
        except ValidationError as exc:
            raise GatewayDenied(["INVALID_PARAMS"]) from exc

    @staticmethod
    def _estimate(adapter: Any, params: dict[str, Any]) -> int:
        fn = getattr(adapter, "estimate_requests", None)
        cost = fn(params) if callable(fn) else 1
        if not isinstance(cost, int) or cost < 1:
            raise GatewayDenied(["INVALID_REQUEST_ESTIMATE"])
        return cost

    def _audit(
        self, req: ToolRequest, action: str, resource: str, result: str, codes: list[str]
    ) -> None:
        try:
            self.audit.record(req.tenant_id, action, resource, result, codes)
        except Exception as exc:  # an unauditable action must not proceed
            raise GatewayDenied(["AUDIT_UNAVAILABLE"]) from exc
