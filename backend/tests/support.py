"""Test environment for Agent 0 / gateway tests: real Postgres, fake adapters, fake DNS, fixed clock."""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import Field
from sqlalchemy import Engine, text

from aisw.authz.gate import ScopeGate
from aisw.authz.policy import GatePolicy, StaticInventory
from aisw.authz.service import LaunchAuthorization, ScopeService
from aisw.authz.signing import KeyRing, LocalKeySigner
from aisw.contracts.base import StrictModel
from aisw.contracts.enums import ProfileClass
from aisw.contracts.manifest import ScopeManifest, ScopeManifestBody
from aisw.core.db import tenant_connection
from aisw.core.rbac import ActorContext, Role
from aisw.gateway.gateway import ToolGateway, ToolRequest
from aisw.gateway.registry import AdapterCapability, AdapterJob, AdapterRegistry
from aisw.gateway.stores import DbAuthorizationStore, MemoryAuditSink

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)


class UrlParams(StrictModel):
    max_redirects: int = Field(default=3, ge=0, le=5)


class FakeAdapter:
    """Counts executions so tests can assert ZERO dispatch for every rejected request."""

    def __init__(
        self,
        adapter_id: str,
        profiles: dict[str, ProfileClass],
        target_kinds: set[str],
        *,
        domains: set[str] | None = None,
        param_model: type[StrictModel] | None = None,
        mutates: bool = False,
        cost: int = 1,
    ) -> None:
        self.capability = AdapterCapability(
            adapter_id=adapter_id, version="0.1.0", domains=frozenset(domains or {"url"}),
            profiles=profiles, target_kinds=frozenset(target_kinds), mutates_infrastructure=mutates,
            param_model=param_model,
        )  # fmt: skip
        self.executed: list[AdapterJob] = []
        self.cost = cost
        self.gate: threading.Event | None = None
        self.entered = threading.Event()

    def estimate_requests(self, params: dict[str, Any]) -> int:
        return self.cost

    def execute(self, job: AdapterJob) -> dict[str, Any]:
        self.executed.append(job)
        if self.gate is not None:
            self.entered.set()
            self.gate.wait(5)
        return {"ok": True, "pinned": list(job.pinned_addresses)}


@dataclass
class Env:
    engine: Engine
    tenant: str
    project_id: str
    now: datetime = NOW
    dns: dict[str, list[str]] = field(default_factory=lambda: {"example.com": ["93.184.216.34"]})
    url_adapter: FakeAdapter = field(init=False)
    active_adapter: FakeAdapter = field(init=False)
    registry: AdapterRegistry = field(init=False)
    inventory: StaticInventory = field(init=False)
    signer: LocalKeySigner = field(init=False)
    keyring: KeyRing = field(init=False)
    audit: MemoryAuditSink = field(init=False)
    gate: ScopeGate = field(init=False)
    service: ScopeService = field(init=False)
    gateway: ToolGateway = field(init=False)

    def __post_init__(self) -> None:
        self.url_adapter = FakeAdapter(
            "url_smoke", {"PASSIVE_HTTP_SMOKE": ProfileClass.READ_ONLY}, {"url", "host"},
            param_model=UrlParams,
        )  # fmt: skip
        self.active_adapter = FakeAdapter(
            "zap", {"BASELINE": ProfileClass.READ_ONLY, "ACTIVE_SCAN": ProfileClass.ACTIVE}, {"url"}
        )  # fmt: skip
        self.registry = AdapterRegistry()
        self.registry.register(self.url_adapter)
        self.registry.register(self.active_adapter)
        self.inventory = StaticInventory(
            {(self.tenant, self.project_id, "url", "https://example.com"): "src-1"}
        )
        self.signer = LocalKeySigner.generate("test-key-1")
        self.keyring = KeyRing.from_signer(self.signer)
        self.audit = MemoryAuditSink()
        self.gate = ScopeGate(
            registry=self.registry, inventory=self.inventory,
            policy=GatePolicy(), resolver=self._resolve,
        )  # fmt: skip
        self.service = ScopeService(
            engine=self.engine, gate=self.gate, signer=self.signer, keyring=self.keyring,
            clock=lambda: self.now,
        )  # fmt: skip
        self.gateway = ToolGateway(
            registry=self.registry, store=DbAuthorizationStore(self.engine),
            verifier=self.keyring, audit=self.audit, resolver=self._resolve,
            clock=lambda: self.now,
        )  # fmt: skip

    def _resolve(self, host: str, port: int) -> list[str]:
        if host not in self.dns:
            raise OSError("NXDOMAIN")
        return self.dns[host]

    # actors -------------------------------------------------------------------------------
    def actor(self, name: str, *roles: Role) -> ActorContext:
        return ActorContext(self.tenant, name, frozenset(roles))

    @property
    def operator(self) -> ActorContext:
        return self.actor("alice", Role.ASSESSMENT_OPERATOR, Role.PROJECT_ADMIN)

    @property
    def approver(self) -> ActorContext:
        return self.actor("bob", Role.APPROVER)

    # builders -----------------------------------------------------------------------------
    def body(self, **over: Any) -> ScopeManifestBody:
        d: dict[str, Any] = {
            "tenant_id": self.tenant, "project_id": self.project_id,
            "targets": [{"kind": "url", "selector": "https://example.com"}],
            "domains": ["url"], "allowed_adapters": ["url_smoke"],
            "profiles": {"url_smoke": {"profile_id": "PASSIVE_HTTP_SMOKE", "profile_class": "READ_ONLY"}},
            "allowed_ports": [443], "evidence_retention_days": 30, "policy_version": "p-1",
            "expires_at": self.now + timedelta(days=1),
        }  # fmt: skip
        d.update(over)
        return ScopeManifestBody.model_validate(d)

    def draft(self, body: ScopeManifestBody | None = None) -> ScopeManifest:
        m, _ = self.service.create_draft(
            self.operator, self.project_id, body or self.body(), cid="t"
        )
        return m

    def approved(
        self, body: ScopeManifestBody | None = None, *, ack: frozenset[str] = frozenset()
    ) -> ScopeManifest:
        m = self.draft(body)
        self.service.preflight(self.operator, m.manifest_id, cid="t")
        return self.service.approve(
            self.approver, m.manifest_id, acknowledge_active_adapters=ack, cid="t"
        )

    def launch(self, m: ScopeManifest, key: str | None = None, **kw: Any) -> LaunchAuthorization:
        return self.service.authorize_launch(
            self.operator, project_id=self.project_id, manifest_id=m.manifest_id,
            manifest_hash=kw.pop("manifest_hash", m.canonical_hash),
            task_types=kw.pop("task_types", None),
            idempotency_key=key or uuid.uuid4().hex, cid="t",
        )  # fmt: skip

    def request(self, auth: LaunchAuthorization, m: ScopeManifest, **over: Any) -> ToolRequest:
        d: dict[str, Any] = {
            "tenant_id": self.tenant, "project_id": self.project_id, "run_id": auth.run_id,
            "task_id": f"task-{uuid.uuid4().hex[:6]}", "task_type": "url_smoke",
            "adapter_id": "url_smoke", "profile": "PASSIVE_HTTP_SMOKE", "target_kind": "url",
            "target_selector": "https://example.com", "params": {},
            "permit_id": auth.permit.permit_id, "manifest_hash": m.canonical_hash,
        }  # fmt: skip
        d.update(over)
        return ToolRequest.model_validate(d)

    @property
    def total_dispatched(self) -> int:
        return len(self.url_adapter.executed) + len(self.active_adapter.executed)


def make_env(engine: Engine) -> Env:
    tenant = f"t-{uuid.uuid4().hex[:10]}"
    with tenant_connection(engine, tenant) as c:
        pid = str(
            c.execute(
                text(
                    "INSERT INTO projects (tenant_id, name, environment, created_by) "
                    "VALUES (:t, 'p', 'test', 'alice') RETURNING project_id"
                ),
                {"t": tenant},
            ).scalar_one()
        )
    return Env(engine, tenant, pid)
