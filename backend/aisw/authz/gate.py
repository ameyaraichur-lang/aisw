"""Agent 0 - Scope, Authorization & Policy Gate. Deterministic: no LLM, no I/O of its own.

``evaluate`` collects every issue (so the wizard can show a complete preflight), then decides:
  DENY               any blocking issue
  APPROVAL_REQUIRED  valid, but lacks a valid independent approval (active profiles also need an
                     explicit acknowledgement of each active profile)
  ALLOW              valid and approved; bound to the canonical hash of the *resolved* manifest
Nothing is widened or silently narrowed: a problem is a denial, never a quiet edit.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from aisw.authz import scope as scope_rules
from aisw.authz.net_guard import (
    NetGuardError,
    Resolver,
    canonicalize_url,
    parse_internal_ranges,
    resolve_and_vet,
    system_resolver,
)
from aisw.authz.policy import GatePolicy, Inventory
from aisw.contracts.enums import Decision, ProfileClass
from aisw.contracts.manifest import AuthorizationDecision, ScopeManifestBody, ScopeTarget
from aisw.core.rbac import ActorContext, Permission
from aisw.gateway.registry import AdapterRegistry


@dataclass(frozen=True)
class Issue:
    code: str
    severity: Literal["BLOCKING", "WARNING"]
    detail: str = ""


@dataclass(frozen=True)
class Approval:
    actor_id: str
    can_approve: bool  # holds MANIFEST_APPROVE, derived server-side
    acknowledged_active_profiles: frozenset[str] = frozenset()


@dataclass(frozen=True)
class GateOutcome:
    decision: AuthorizationDecision
    issues: tuple[Issue, ...]
    body: ScopeManifestBody  # resolved copy: hash this, store this, sign this
    reasons: tuple[str, ...] = field(default=())

    @property
    def blocking_codes(self) -> list[str]:
        return [i.code for i in self.issues if i.severity == "BLOCKING"]


class ScopeGate:
    def __init__(
        self,
        *,
        registry: AdapterRegistry,
        inventory: Inventory,
        policy: GatePolicy | None = None,
        resolver: Resolver = system_resolver,
        egress_zones: tuple[str, ...] = (),
    ) -> None:
        self.egress_zones = egress_zones
        self.registry = registry
        self.inventory = inventory
        self.policy = policy or GatePolicy()
        self.resolver = resolver

    # ------------------------------------------------------------------------------------
    def evaluate(
        self,
        *,
        actor: ActorContext,
        project_id: str,
        body: ScopeManifestBody,
        requested_by: str,
        approvals: Sequence[Approval] = (),
        now: datetime,
        project_known: bool = True,
        require_requester_permission: bool = True,
    ) -> GateOutcome:
        issues: list[Issue] = []

        def block(code: str, detail: str = "") -> None:
            issues.append(Issue(code, "BLOCKING", detail))

        def warn(code: str, detail: str = "") -> None:
            issues.append(Issue(code, "WARNING", detail))

        # 1) identity, tenant and project (always derived from trusted server context)
        if body.tenant_id != actor.tenant_id:
            block("CROSS_TENANT", "manifest tenant differs from the authenticated tenant")
        if body.project_id != project_id:
            block("PROJECT_MISMATCH")
        if not project_known:
            block("PROJECT_NOT_FOUND")
        if require_requester_permission and not actor.can(Permission.MANIFEST_CREATE):
            block("ROLE_NOT_PERMITTED", Permission.MANIFEST_CREATE.value)

        # 2) validity, quotas, retention (requested may be lower than policy, never higher)
        p = self.policy
        if body.expires_at <= now:
            block("MANIFEST_EXPIRED")
        elif body.expires_at - now > p.max_manifest_validity:
            block("VALIDITY_EXCEEDS_POLICY")
        q = body.quotas
        if q.max_concurrency > p.max_concurrency:
            block("CONCURRENCY_EXCEEDS_POLICY")
        if q.max_requests > p.max_requests:
            block("REQUEST_BUDGET_EXCEEDS_POLICY")
        if q.max_duration_seconds > p.max_duration_seconds:
            block("DURATION_EXCEEDS_POLICY")
        if body.evidence_retention_days > p.max_retention_days:
            block("RETENTION_EXCEEDS_POLICY")

        # 3) adapters, profiles, connectors, domains
        caps = {}
        for adapter_id in body.allowed_adapters:
            cap = self.registry.capability(adapter_id)
            if cap is None:
                block("UNKNOWN_ADAPTER", adapter_id)
                continue
            caps[adapter_id] = cap
            if not cap.enabled or not cap.permission_ok:
                block("CONNECTOR_DENIED", adapter_id)
            if adapter_id not in body.profiles:
                block("ADAPTER_WITHOUT_PROFILE", adapter_id)
        for adapter_id, mp in body.profiles.items():
            cap = caps.get(adapter_id)
            if cap is None:
                continue
            declared = cap.profiles.get(mp.profile_id)
            if declared is None:
                block("UNSUPPORTED_PROFILE", f"{adapter_id}:{mp.profile_id}")
            elif declared is not mp.profile_class:
                block("PROFILE_CLASS_MISMATCH", f"{adapter_id}:{mp.profile_id} is {declared.value}")
        supported_domains = {d for c in caps.values() for d in c.domains}
        for d in body.domains:
            if d not in supported_domains:
                block("UNSUPPORTED_DOMAIN", d)

        # 4) targets: wildcards, syntax, inventory resolution, adapter fit, URL safety
        resolved: list[ScopeTarget] = []
        url_count = 0
        for t in body.targets:
            wc = scope_rules.wildcard_reason(t, p)
            if wc and not (p.allow_wildcards and wc != "INVALID_CIDR"):
                block(wc, t.selector)
                resolved.append(t)
                continue
            if not any(t.kind in c.target_kinds for c in caps.values()):
                block("NO_ADAPTER_FOR_TARGET", f"{t.kind}:{t.selector}")
            if scope_rules.is_excluded(body, t.kind, t.selector):
                block("TARGET_EXCLUDED", t.selector)
            rid = self.inventory.resolve(actor.tenant_id, project_id, t.kind, t.selector)
            if rid is None:
                block("TARGET_NOT_IN_INVENTORY", f"{t.kind}:{t.selector}")
            elif t.resolved_asset_id is not None and t.resolved_asset_id != rid:
                block("RESOLUTION_MISMATCH", t.selector)
            resolved.append(t.model_copy(update={"resolved_asset_id": rid or t.resolved_asset_id}))
            if t.kind == "url":
                url_count += 1
                self._vet_url(t, body, block)
        if url_count > p.max_urls_per_manifest:
            block("TOO_MANY_URL_TARGETS")
        for e in body.exclusions:
            if e.kind == "cidr" and scope_rules._network(e.selector) is None:
                block("INVALID_EXCLUSION", e.selector)
        if body.internal_range_authorization:
            try:
                parse_internal_ranges(body.internal_range_authorization)
                warn("INTERNAL_RANGE_AUTHORIZED", "internal address ranges are reachable")
            except NetGuardError as exc:
                block(exc.code)

        resolved_body = body.model_copy(update={"targets": resolved})

        # 5) approvals: always required; active profiles need an explicit acknowledgement
        active = {a for a, mp in body.profiles.items() if mp.profile_class is ProfileClass.ACTIVE}
        reasons: list[str] = []
        valid_approvals = [a for a in approvals if a.can_approve and a.actor_id != requested_by]
        if any(a.actor_id == requested_by for a in approvals):
            block("SELF_APPROVAL")
        if active:
            ack = set().union(*(a.acknowledged_active_profiles for a in valid_approvals))
            if not active <= ack:
                reasons.append("ACTIVE_PROFILE_REQUIRES_APPROVAL")
                valid_approvals = []
        if not valid_approvals:
            reasons.append("APPROVAL_REQUIRED")

        blocking = [i for i in issues if i.severity == "BLOCKING"]
        digest = resolved_body.hash()
        if blocking:
            decision = AuthorizationDecision(
                decision=Decision.DENY, reason_codes=sorted({i.code for i in blocking})
            )
        elif reasons:
            decision = AuthorizationDecision(
                decision=Decision.APPROVAL_REQUIRED, reason_codes=reasons, manifest_hash=digest
            )
        else:
            decision = AuthorizationDecision(
                decision=Decision.ALLOW, reason_codes=["WITHIN_POLICY", "APPROVED"],
                manifest_hash=digest,
            )  # fmt: skip
        return GateOutcome(decision, tuple(issues), resolved_body, tuple(reasons))

    # ------------------------------------------------------------------------------------
    def _vet_url(self, t: ScopeTarget, body: ScopeManifestBody, block) -> None:  # type: ignore[no-untyped-def]
        try:
            url = canonicalize_url(t.selector)
            resolve_and_vet(
                url,
                allowed_ports=body.allowed_ports,
                internal_ranges=body.internal_range_authorization,
                resolver=self.resolver,
                egress_zones=self.egress_zones,
            )
        except NetGuardError as exc:
            block(exc.code, t.selector)
