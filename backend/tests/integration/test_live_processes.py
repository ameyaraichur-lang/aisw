"""The deployable processes run for real: bootstrap, API and worker as OS processes against Postgres,
a run driven end to end over HTTP, the doctor, heartbeat and graceful shutdown (ADR-029)."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine

from tests.conftest import make_db

BACKEND = Path(__file__).resolve().parents[2]


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def secret_file(path: Path, value: str) -> Path:
    path.write_text(value)
    os.chmod(path, 0o600)
    return path


class Http:
    def __init__(self, base: str) -> None:
        self.base = base

    def __call__(self, method: str, path: str, user: str | None = None, body: Any = None,
                 headers: dict[str, str] | None = None) -> tuple[int, Any]:  # fmt: skip
        h = {"accept": "application/json", **(headers or {})}
        if user:
            h["authorization"] = f"Bearer dev-{user}"
        data = None
        if body is not None:
            data, h["content-type"] = json.dumps(body).encode(), "application/json"
        req = urllib.request.Request(f"{self.base}{path}", data=data, headers=h, method=method)  # noqa: S310
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=10) as r:
                raw = r.read()
                return r.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            exc.close()
            return exc.code, json.loads(raw) if raw else None


@pytest.fixture()
def deployment(
    pg_server: Any, app_engine: Engine, worker_engine: Engine, tmp_path: Path
) -> Iterator[dict[str, Any]]:
    db = f"live_{uuid.uuid4().hex[:8]}"
    owner = make_db(pg_server, db)
    owner_url = owner.url.render_as_string(hide_password=False)
    owner.dispose()
    # Reuse the session's role passwords: the roles are cluster-wide and other tests hold pools.
    app_pw, worker_pw = app_engine.url.password, worker_engine.url.password
    assert app_pw and worker_pw
    app_url = app_engine.url.set(database=db).render_as_string(hide_password=False)
    worker_url = worker_engine.url.set(database=db).render_as_string(hide_password=False)
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    port = free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith("AISW_")}
    env.update({
        "AISW_ENV": "test", "AISW_DEV_AUTH_STUB": "true", "AISW_DATABASE_URL": app_url,
        "AISW_WORKER_DATABASE_URL": worker_url, "AISW_SIGNING_KEY_PATH": str(tmp_path / "k.pem"),
        "AISW_EVIDENCE_DIR": str(evidence), "AISW_API_PORT": str(port),
        "AISW_WORKER_HEARTBEAT_FILE": str(tmp_path / "heartbeat"),
    })  # fmt: skip
    yield {"env": env, "owner_url": owner_url, "app_pw": app_pw, "worker_pw": worker_pw,
           "port": port, "tmp": tmp_path}  # fmt: skip


def run(args: list[str], env: dict[str, str], **kw: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", *args], cwd=BACKEND, env=env, capture_output=True,  # noqa: S603
                          text=True, timeout=120, **kw)  # fmt: skip


def stop(p: subprocess.Popen[str]) -> int:
    p.send_signal(signal.SIGTERM)
    try:
        return p.wait(timeout=30)
    except subprocess.TimeoutExpired:
        p.kill()
        raise


def test_bootstrap_api_worker_and_doctor_as_live_processes(deployment: dict[str, Any]) -> None:
    env, tmp = deployment["env"], deployment["tmp"]
    boot_env = {
        **env,
        "AISW_MIGRATION_DATABASE_URL_FILE": str(
            secret_file(tmp / "owner-url", deployment["owner_url"])
        ),
    }
    args = ["aisw.bootstrap", "--app-password-file", str(secret_file(tmp / "app-pw", deployment["app_pw"])),
            "--worker-password-file", str(secret_file(tmp / "worker-pw", deployment["worker_pw"]))]  # fmt: skip
    boot = run(args, boot_env)
    assert boot.returncode == 0, boot.stderr
    assert "login enabled for aisw_app, aisw_worker" in boot.stdout
    assert deployment["app_pw"] not in boot.stdout + boot.stderr
    assert run(args, boot_env).returncode == 0  # idempotent

    api = subprocess.Popen([sys.executable, "-m", "aisw.api"], cwd=BACKEND, env=env, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)  # fmt: skip
    worker: subprocess.Popen[str] | None = None
    try:
        http = Http(f"http://127.0.0.1:{deployment['port']}")
        deadline = time.monotonic() + 60
        while True:
            try:
                status, ready = http("GET", "/readyz")
                if status == 200:
                    break
            except (urllib.error.URLError, ConnectionError):
                pass
            assert api.poll() is None, api.stdout.read() if api.stdout else ""
            assert time.monotonic() < deadline, "API did not become ready"
            time.sleep(0.3)
        assert ready["database_reachable"] is True and ready["signer_configured"] is True

        doctor = run(["aisw.doctor", "--role", "api", "--json"], env)
        checks = {c["name"]: c["status"] for c in json.loads(doctor.stdout)}
        assert doctor.returncode == 0, doctor.stdout
        assert checks["database_role"] == checks["row_level_security"] == "PASS"
        assert checks["migrations_at_head"] == checks["evidence_store"] == "PASS"
        assert checks["signing_custody"] == "WARN" and checks["sign_in"] == "WARN"
        assert checks["signoffs"] == "WARN"
        wdoc = run(["aisw.doctor", "--role", "worker", "--json"], env)
        assert wdoc.returncode == 0, wdoc.stdout
        assert {c["name"]: c["status"] for c in json.loads(wdoc.stdout)}["database_role"] == "PASS"

        worker = subprocess.Popen([sys.executable, "-m", "aisw.orchestrator"], cwd=BACKEND, env=env,
                                  text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)  # fmt: skip
        idem = {"Idempotency-Key": uuid.uuid4().hex}
        status, p = http(
            "POST", "/api/v1/projects", "alice", {"name": "live", "environment": "test"}, idem
        )
        assert status == 201, p
        pid = p["project_id"]
        status, _ = http("POST", "/api/v1/inventory", "alice", {
            "project_id": pid, "kind": "asset_group", "selector": "fixture-group-1",
            "expected_assets": ["host-1", "host-2", "host-3"]})  # fmt: skip
        assert status == 201
        manifest = {
            "project_id": pid, "targets": [{"kind": "asset_group", "selector": "fixture-group-1"}],
            "domains": ["host"], "allowed_adapters": ["fixture"],
            "profiles": {"fixture": {"profile_id": "FIXTURE_BASELINE", "profile_class": "READ_ONLY"}},
            "evidence_retention_days": 30, "policy_version": "fixture-baseline:1.0.0",
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        }  # fmt: skip
        status, m = http("POST", "/api/v1/scope-manifests", "alice", manifest)
        assert status == 201, m
        mid = m["manifest"]["manifest_id"]
        assert http("POST", f"/api/v1/scope-manifests/{mid}/preflight", "alice")[0] == 200
        status, approved = http("POST", f"/api/v1/scope-manifests/{mid}/approve", "bob", {})
        assert status == 200, approved
        status, launched = http("POST", "/api/v1/assessments", "alice", {
            "project_id": pid, "scope_manifest_id": mid, "scope_manifest_hash": approved["canonical_hash"],
            "assessment_profile": "baseline-readonly-v1",
            "adapter_params": {"fixture": {"fixture_set": "baseline-ok"}}}, {"Idempotency-Key": uuid.uuid4().hex})  # fmt: skip
        assert status == 202, launched
        run_id = launched["run_id"]
        deadline = time.monotonic() + 90
        while True:
            state = http("GET", f"/api/v1/assessments/{run_id}", "alice")[1]["state"]
            if state in {"REPORT_READY", "PARTIAL", "FAILED"}:
                break
            assert worker.poll() is None, worker.stdout.read() if worker.stdout else ""
            assert time.monotonic() < deadline, f"run stuck in {state}"
            time.sleep(0.5)
        assert state == "REPORT_READY"
        status, reports = http("GET", f"/api/v1/assessments/{run_id}/reports", "carol")
        assert status == 200 and reports
        assert run(["aisw.orchestrator", "--check-heartbeat"], env).returncode == 0

        assert stop(worker) == 0
        out = worker.stdout.read() if worker.stdout else ""
        assert "worker stopped" in out and deployment["worker_pw"] not in out
        worker = None
    finally:
        if worker is not None:
            worker.kill()
        code = stop(api)
    # uvicorn re-raises the captured SIGTERM after a graceful shutdown; systemd counts that as clean.
    assert code in (0, -signal.SIGTERM)
    logs = api.stdout.read() if api.stdout else ""
    assert "Application shutdown complete" in logs
    assert deployment["app_pw"] not in logs


def test_bootstrap_refuses_unsafe_password_files(tmp_path: Path) -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith("AISW_")}
    loose = tmp_path / "pw"
    loose.write_text("x" * 20)
    os.chmod(loose, 0o644)
    env["AISW_MIGRATION_DATABASE_URL"] = (
        "postgresql+psycopg://nobody@127.0.0.1:1/x"  # aisw:allow-secret
    )
    r = run(["aisw.bootstrap", "--app-password-file", str(loose)], env)
    assert r.returncode == 2 and "group/world" in r.stderr
    short = secret_file(tmp_path / "short", "abc")
    r = run(["aisw.bootstrap", "--app-password-file", str(short)], env)
    assert r.returncode == 2 and "16" in r.stderr
    del env["AISW_MIGRATION_DATABASE_URL"]
    assert run(["aisw.bootstrap"], env).returncode == 2
