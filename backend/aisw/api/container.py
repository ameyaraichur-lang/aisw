"""Composition root: wires the registry, gate, service, gateway and evidence store.

The fixture adapter is registered ONLY outside prod. Missing signing key or evidence directory
means the dependent routes answer 503 rather than running without the control.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Engine

from aisw.adapters.cloud_import import ProwlerImportAdapter
from aisw.adapters.cmdb_import import CmdbImportAdapter
from aisw.adapters.fixture import FixtureAdapter
from aisw.adapters.scanner_imports import (
    GreenboneImportAdapter,
    NmapImportAdapter,
    OpenScapImportAdapter,
    WazuhImportAdapter,
)
from aisw.adapters.url_smoke import UrlSmokeAdapter
from aisw.adapters.web_import import ZapImportAdapter
from aisw.authz.gate import ScopeGate
from aisw.authz.inventory import DbInventory
from aisw.authz.net_guard import Resolver, system_resolver
from aisw.authz.policy import GatePolicy
from aisw.authz.service import ScopeService
from aisw.authz.signing import KeyRing, LocalKeySigner, ManifestSigner
from aisw.core.config import Environment, Settings
from aisw.evidence.imports import ImportStore
from aisw.evidence.store import EvidenceStore
from aisw.gateway.gateway import ToolGateway
from aisw.gateway.registry import AdapterRegistry
from aisw.gateway.stores import AuditSink, DbAuditSink, DbAuthorizationStore
from aisw.llm.factory import build_model_client, build_validation_client
from aisw.orchestrator.worker import Worker
from aisw.policy.engine import PackRegistry, PolicyEvaluator, PythonRuleEvaluator


@dataclass
class Container:
    settings: Settings
    engine: Engine
    registry: AdapterRegistry
    packs: PackRegistry
    evaluator: PolicyEvaluator
    clock: Callable[[], datetime]
    resolver: Resolver
    signer: ManifestSigner | None = None
    keyring: KeyRing | None = None
    evidence: EvidenceStore | None = None
    audit_sink: AuditSink | None = None
    gate: ScopeGate = field(init=False)
    service: ScopeService | None = field(init=False, default=None)
    gateway: ToolGateway | None = field(init=False, default=None)
    imports: ImportStore | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self.gate = ScopeGate(
            registry=self.registry, inventory=DbInventory(self.engine), policy=GatePolicy(),
            resolver=self.resolver,
        )  # fmt: skip
        if self.signer is not None and self.keyring is not None:
            self.service = ScopeService(
                engine=self.engine, gate=self.gate, signer=self.signer, keyring=self.keyring,
                clock=self.clock,
            )  # fmt: skip
            if self.evidence is not None:
                self.imports = ImportStore(self.engine, self.evidence)
            self.gateway = ToolGateway(
                registry=self.registry, store=DbAuthorizationStore(self.engine),
                verifier=self.keyring, audit=self.audit_sink or DbAuditSink(self.engine),
                resolver=self.resolver, clock=self.clock, imports=self.imports,
            )  # fmt: skip

    def make_worker(self, worker_engine: Engine | None = None, **kw: Any) -> Worker:
        if self.gateway is None or self.evidence is None:
            raise RuntimeError("signing and evidence storage must be configured")
        kw.setdefault(
            "model", build_model_client(self.settings)
        )  # Disabled unless fully configured
        kw.setdefault("ai_scenario_narratives", self.settings.ai_narrative_enabled)
        kw.setdefault("ai_recommendation_narratives", self.settings.ai_architecture_enabled)
        kw.setdefault("ai_verification_questions", self.settings.ai_verification_questions_enabled)
        kw.setdefault("ai_executive_summary", self.settings.ai_executive_summary_enabled)
        kw.setdefault("model_timeout", float(self.settings.model_timeout_seconds))
        s = self.settings
        kw.setdefault("ai_validation", s.ai_enabled and s.ai_validation_enabled)
        if s.astra_validation_deployment:
            kw.setdefault("validation_model", build_validation_client(s))
        kw.setdefault("validation_batch", s.ai_validation_batch_size)
        kw.setdefault("validation_max_items", s.ai_validation_max_items_per_agent)
        kw.setdefault("validation_concurrency", s.ai_validation_concurrency)
        kw.setdefault("run_token_budget", s.ai_run_token_budget)
        if self.service is not None:
            kw.setdefault("renew_permit", self.service.renew_permit)
        return Worker(
            engine=worker_engine or self.engine, gateway=self.gateway, registry=self.registry,
            packs=self.packs, evaluator=self.evaluator, evidence=self.evidence,
            clock=self.clock, **kw,
        )  # fmt: skip


def build_container(
    settings: Settings,
    engine: Engine,
    *,
    signer: ManifestSigner | None = None,
    keyring: KeyRing | None = None,
    evidence: EvidenceStore | None = None,
    resolver: Resolver = system_resolver,
    clock: Callable[[], datetime] | None = None,
    audit_sink: AuditSink | None = None,
    ca_file: Path | None = None,
) -> Container:
    clock = clock or (lambda: datetime.now(UTC))
    registry = AdapterRegistry()
    registry.register(UrlSmokeAdapter(ca_file=ca_file, clock=clock))  # read-only, scope-bound
    for imp in (
        CmdbImportAdapter,
        ProwlerImportAdapter,
        GreenboneImportAdapter,
        NmapImportAdapter,
        OpenScapImportAdapter,
        WazuhImportAdapter,
        ZapImportAdapter,
    ):  # file in, evidence out
        registry.register(imp(clock=clock))
    if settings.env is not Environment.PROD:
        registry.register(FixtureAdapter(clock=clock))
    if signer is None and settings.signing_key_path and settings.env is not Environment.PROD:
        local = LocalKeySigner.load_or_create("local-1", settings.signing_key_path)
        signer, keyring = local, KeyRing.from_signer(local)
    if evidence is None and settings.evidence_dir is not None:
        evidence = EvidenceStore(settings.evidence_dir)
    return Container(
        settings=settings, engine=engine, registry=registry, packs=PackRegistry.builtin(),
        evaluator=PythonRuleEvaluator(), clock=clock, resolver=resolver, signer=signer,
        keyring=keyring, evidence=evidence, audit_sink=audit_sink,
    )  # fmt: skip
