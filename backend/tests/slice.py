"""Harness for the end-to-end vertical slice: real API, real Postgres, real worker, fixture adapter."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from aisw.api.app import create_app
from aisw.api.container import Container, build_container
from aisw.authz.signing import KeyRing, LocalKeySigner
from aisw.core.config import Settings
from aisw.core.db import tenant_connection
from aisw.evidence.store import EvidenceStore
from aisw.gateway.stores import MemoryAuditSink
from aisw.orchestrator.worker import Worker
from tests.conftest import auth

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
GROUP = "fixture-group-1"


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> None:
        self.now += timedelta(**kw)


class Slice:
    def __init__(
        self,
        app_engine: Engine,
        worker_engine: Engine,
        evidence_dir: Path,
        ca_file: Path | None = None,
        evidence: EvidenceStore | None = None,
    ) -> None:
        self.clock = Clock()
        self.uid = uuid.uuid4().hex[:10]
        self.dns: dict[str, list[str]] = {}  # mock DNS; unknown names fall back to a public literal
        self.app_engine, self.worker_engine = app_engine, worker_engine
        self.evidence_dir = evidence_dir
        signer = LocalKeySigner.generate("slice-key")
        self.audit = MemoryAuditSink()
        self.container: Container = build_container(
            Settings(env="test", dev_auth_stub=True),
            app_engine, signer=signer, keyring=KeyRing.from_signer(signer),
            evidence=evidence or EvidenceStore(evidence_dir), clock=self.clock, audit_sink=self.audit,
            resolver=lambda h, p: self.dns.get(h, ["93.184.216.34"]), ca_file=ca_file,
        )  # fmt: skip
        self.client = TestClient(create_app(self.container.settings, app_engine, self.container))
        self.worker: Worker = self.container.make_worker(worker_engine, worker_id="w-1")
        # The task queue is shared by every test (tenants are fixed by the dev identity stub), so
        # start from a drained queue: leftovers from earlier tests must not be claimed by this one.
        self.worker.run_until_idle()
        assert self.container.gateway is not None
        self.container.gateway.dispatched = 0
        self.fixture = self.container.registry.get("fixture")
        self.executions = 0
        orig = self.fixture.execute  # type: ignore[union-attr]

        def counting(job: Any) -> Any:
            self.executions += 1
            return orig(job)

        self.fixture.execute = counting  # type: ignore[union-attr,method-assign]

    def enable_ai(self, model: Any) -> None:
        """Turn AI on for this harness with a scripted stub: no weights, no network."""
        self.container.settings = Settings(
            env="test", dev_auth_stub=True, ai_enabled=True, model_id="stub-model-0",
            model_license="Apache-2.0",
        )  # fmt: skip
        self.worker.model = model

    # ---- API helpers -----------------------------------------------------------------------
    def call(self, method: str, url: str, user: str, **kw: Any) -> Any:
        headers = {**auth(user), **kw.pop("headers", {})}
        return self.client.request(method, url, headers=headers, **kw)

    def project(self) -> str:
        r = self.call("POST", "/api/v1/projects", "alice",
                      json={"name": f"p-{self.uid}-{uuid.uuid4().hex[:4]}", "environment": "test"},
                      headers={"Idempotency-Key": uuid.uuid4().hex})  # fmt: skip
        assert r.status_code == 201, r.text
        return str(r.json()["project_id"])

    def inventory(self, pid: str, expected: list[str]) -> None:
        r = self.call("POST", "/api/v1/inventory", "alice",
                      json={"project_id": pid, "kind": "asset_group", "selector": GROUP,
                            "expected_assets": expected})  # fmt: skip
        assert r.status_code == 201, r.text

    def manifest_payload(self, pid: str, **over: Any) -> dict[str, Any]:
        d: dict[str, Any] = {
            "project_id": pid, "targets": [{"kind": "asset_group", "selector": GROUP}],
            "domains": ["host"], "allowed_adapters": ["fixture"],
            "profiles": {"fixture": {"profile_id": "FIXTURE_BASELINE", "profile_class": "READ_ONLY"}},
            "evidence_retention_days": 30, "policy_version": "fixture-baseline:1.0.0",
            "expires_at": (self.clock.now + timedelta(days=1)).isoformat(),
        }  # fmt: skip
        d.update(over)
        return d

    def approved_manifest(self, pid: str, **over: Any) -> dict[str, Any]:
        r = self.call(
            "POST", "/api/v1/scope-manifests", "alice", json=self.manifest_payload(pid, **over)
        )
        assert r.status_code == 201, r.text
        m = r.json()["manifest"]
        pf = self.call("POST", f"/api/v1/scope-manifests/{m['manifest_id']}/preflight", "alice")
        assert pf.status_code == 200, pf.text
        ap = self.call("POST", f"/api/v1/scope-manifests/{m['manifest_id']}/approve", "bob",
                       json={})  # fmt: skip
        assert ap.status_code == 200, ap.text
        return dict(ap.json())

    def launch(
        self, pid: str, m: dict[str, Any], *, fixture_set: str = "baseline-ok", key: str | None = None,
        user: str = "alice", **over: Any,
    ) -> Any:  # fmt: skip
        body: dict[str, Any] = {
            "project_id": pid, "scope_manifest_id": m["manifest_id"],
            "scope_manifest_hash": m["canonical_hash"], "assessment_profile": "baseline-readonly-v1",
            "adapter_params": {"fixture": {"fixture_set": fixture_set}},
        }  # fmt: skip
        body.update(over)
        return self.call("POST", "/api/v1/assessments", user, json=body,
                         headers={"Idempotency-Key": key or uuid.uuid4().hex})  # fmt: skip

    def full_run(
        self, expected: list[str], fixture_set: str = "baseline-ok", **launch_kw: Any
    ) -> tuple[str, dict[str, Any], str]:  # fmt: skip
        pid = self.project()
        self.inventory(pid, expected)
        m = self.approved_manifest(pid)
        r = self.launch(pid, m, fixture_set=fixture_set, **launch_kw)
        assert r.status_code == 202, r.text
        return pid, m, str(r.json()["run_id"])

    def drain(self) -> int:
        return self.worker.run_until_idle()

    # ---- read helpers ----------------------------------------------------------------------
    def status(self, run_id: str, user: str = "alice") -> dict[str, Any]:
        r = self.call("GET", f"/api/v1/assessments/{run_id}", user)
        assert r.status_code == 200, r.text
        return dict(r.json())

    def events(self, run_id: str, cursor: int = 0) -> list[dict[str, Any]]:
        r = self.call("GET", f"/api/v1/assessments/{run_id}/events?cursor={cursor}", "alice")
        assert r.status_code == 200, r.text
        return list(r.json()["events"])

    def report(self, run_id: str) -> dict[str, Any]:
        rows = self.call("GET", f"/api/v1/assessments/{run_id}/reports", "carol").json()
        assert rows and all(row["approval_state"] == "SUPERSEDED" for row in rows[1:])
        r = self.call("GET", f"/api/v1/reports/{rows[0]['report_id']}", "carol")
        assert r.status_code == 200
        return dict(r.json())

    def sql(self, sql: str, **params: Any) -> list[Any]:
        with tenant_connection(self.app_engine, "tenant-a") as c:
            return list(c.execute(text(sql), params).all())
