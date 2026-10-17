"""Multi-node soak: worker processes share one queue while workers are killed at random (ADR-044).

Each worker is its own OS process with its own connection pool, as it would be on its own host; the
only shared state is PostgreSQL. Every few seconds one worker gets SIGKILL wherever it happens to be
and a fresh one starts. What must hold however the kills land: every run ends, as REPORT_READY or
failed with the explained LEASE_EXPIRED_MAX_ATTEMPTS; no task is left RUNNING or over its attempt
limit; each finished task's evidence is stored once; each run's event log is gap- and
duplicate-free; one report per finished run; the audit chain verifies.

AISW_SOAK_RUNS, AISW_SOAK_WORKERS, AISW_SOAK_KILL_SECONDS and AISW_SOAK_TASK_MS scale it; AISW_SOAK_REPORT appends the
measured numbers to a markdown file.
"""

from __future__ import annotations

import os
import random
import signal
import statistics
import subprocess
import sys
import time
import urllib.error
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import Engine, create_engine, text

from aisw.api.container import build_container
from aisw.core.audit import verify_chain
from aisw.core.config import Settings
from aisw.core.db import tenant_connection
from tests.integration.test_live_processes import (  # noqa: F401 - `deployment` is a fixture
    BACKEND,
    Http,
    deployment,
    run,
    secret_file,
    stop,
)

RUNS = int(os.environ.get("AISW_SOAK_RUNS", "24"))
WORKERS = int(os.environ.get("AISW_SOAK_WORKERS", "4"))
KILL_EVERY = float(os.environ.get("AISW_SOAK_KILL_SECONDS", "1.5"))
TASK_MS = int(os.environ.get("AISW_SOAK_TASK_MS", "1500"))  # long enough for kills to land mid-task
LEASE = 5
TERMINAL = {"REPORT_READY", "PARTIAL", "FAILED", "CANCELLED", "EXPIRED"}


def test_soak_knobs_are_bounded_and_the_fixture_delay_is_refused_in_production(
    app_engine: Engine, tmp_path: Path
) -> None:
    with pytest.raises(ValidationError, match="dev and test only"):
        Settings(env="prod", fixture_delay_ms=100)
    with pytest.raises(ValidationError):
        Settings(env="test", worker_lease_seconds=1)
    s = Settings(env="test", worker_lease_seconds=7, signing_key_path=tmp_path / "k.pem",
                 evidence_dir=tmp_path)  # fmt: skip
    assert build_container(s, app_engine).make_worker().lease == timedelta(seconds=7)


def spawn(env: dict[str, str], worker_id: str, log: Path) -> subprocess.Popen[str]:
    return subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "aisw.orchestrator", "--worker-id", worker_id], cwd=BACKEND,
        env=env, text=True, stdout=log.open("w"), stderr=subprocess.STDOUT,
    )  # fmt: skip


def launch_runs(http: Http, n: int) -> list[str]:
    idem = {"Idempotency-Key": uuid.uuid4().hex}
    status, p = http("POST", "/api/v1/projects", "alice", {"name": "soak", "environment": "test"}, idem)  # fmt: skip
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
    runs = []
    for _ in range(n):
        status, launched = http("POST", "/api/v1/assessments", "alice", {
            "project_id": pid, "scope_manifest_id": mid, "scope_manifest_hash": approved["canonical_hash"],
            "assessment_profile": "baseline-readonly-v1",
            "adapter_params": {"fixture": {"fixture_set": "baseline-ok"}}}, {"Idempotency-Key": uuid.uuid4().hex})  # fmt: skip
        assert status == 202, launched
        runs.append(str(launched["run_id"]))
    return runs


def test_worker_processes_survive_random_kills_without_losing_or_duplicating_work(
    deployment: dict[str, Any],  # noqa: F811
) -> None:
    env, tmp = dict(deployment["env"]), deployment["tmp"]
    env["AISW_WORKER_LEASE_SECONDS"] = str(LEASE)
    env["AISW_FIXTURE_DELAY_MS"] = str(TASK_MS)
    env.pop("AISW_WORKER_HEARTBEAT_FILE", None)
    boot_env = {**env, "AISW_MIGRATION_DATABASE_URL_FILE": str(secret_file(tmp / "owner-url", deployment["owner_url"]))}  # fmt: skip
    args = ["aisw.bootstrap", "--app-password-file", str(secret_file(tmp / "app-pw", deployment["app_pw"])),
            "--worker-password-file", str(secret_file(tmp / "worker-pw", deployment["worker_pw"]))]  # fmt: skip
    boot = run(args, boot_env)
    assert boot.returncode == 0, boot.stderr

    api = subprocess.Popen([sys.executable, "-m", "aisw.api"], cwd=BACKEND, env=env, text=True,  # noqa: S603
                           stdout=(tmp / "api.log").open("w"), stderr=subprocess.STDOUT)  # fmt: skip
    rng = random.Random(int(os.environ.get("AISW_SOAK_SEED", "7")))  # noqa: S311 - picks a victim, not a secret
    workers: dict[str, subprocess.Popen[str]] = {}
    kills, spawned = 0, 0
    try:
        http = Http(f"http://127.0.0.1:{deployment['port']}")
        deadline = time.monotonic() + 60
        while True:
            try:
                if http("GET", "/readyz")[0] == 200:
                    break
            except (urllib.error.URLError, ConnectionError):
                pass
            assert api.poll() is None, (tmp / "api.log").read_text()
            assert time.monotonic() < deadline, "API did not become ready"
            time.sleep(0.3)

        for _ in range(WORKERS):
            wid = f"soak-{spawned}"
            workers[wid] = spawn(env, wid, tmp / f"{wid}.log")
            spawned += 1
        started = time.monotonic()
        run_ids = launch_runs(http, RUNS)
        states: dict[str, str] = {}
        deadline = started + 120 + RUNS * 8
        next_kill = time.monotonic() + KILL_EVERY
        while True:
            states = {
                r: http("GET", f"/api/v1/assessments/{r}", "alice")[1]["state"] for r in run_ids
            }
            if all(s in TERMINAL for s in states.values()):
                break
            assert time.monotonic() < deadline, f"runs stuck: {sorted(set(states.values()))}"
            if time.monotonic() >= next_kill:
                victim = rng.choice(sorted(workers))
                workers.pop(victim).kill()  # SIGKILL: no cleanup, no lease release
                kills += 1
                wid = f"soak-{spawned}"
                workers[wid] = spawn(env, wid, tmp / f"{wid}.log")
                spawned += 1
                next_kill = time.monotonic() + KILL_EVERY
            time.sleep(0.5)
        elapsed = time.monotonic() - started
        for p in workers.values():
            assert stop(p) in (0, -signal.SIGTERM)  # one still starting has no handler yet
        survivors = sorted(workers)
        workers = {}
    finally:
        for p in workers.values():
            p.kill()
        stop(api)

    engine = create_engine(deployment["env"]["AISW_DATABASE_URL"], future=True)
    try:
        with tenant_connection(engine, "tenant-a") as c:
            tasks = c.execute(text(
                "SELECT run_id, task_id, status, attempts, max_attempts, errors FROM run_tasks "
                "WHERE run_id = ANY(:r)"), {"r": run_ids}).mappings().all()  # fmt: skip
            events = c.execute(text(
                "SELECT run_id, seq, event_type FROM run_events WHERE run_id = ANY(:r) ORDER BY run_id, seq"),
                {"r": run_ids}).all()  # fmt: skip
            reports: dict[str, int] = dict(c.execute(text(
                "SELECT run_id, count(*) FROM reports WHERE run_id = ANY(:r) GROUP BY run_id"), {"r": run_ids}).all())  # fmt: skip
            timing = c.execute(text(
                "SELECT r.run_id, extract(epoch FROM max(e.occurred_at) - min(e.occurred_at)) FROM assessment_runs r "
                "JOIN run_events e ON e.run_id=r.run_id WHERE r.run_id = ANY(:r) GROUP BY r.run_id"), {"r": run_ids}).all()  # fmt: skip
            chain = verify_chain(c, "tenant-a")
    finally:
        engine.dispose()

    by_run: dict[str, list[tuple[int, str]]] = {}
    for rid, seq, etype in events:
        by_run.setdefault(rid, []).append((seq, etype))
    for rid in run_ids:
        mine = [t for t in tasks if t["run_id"] == rid]
        assert mine and all(t["status"] != "RUNNING" for t in mine), rid
        assert all(t["attempts"] <= t["max_attempts"] for t in mine), rid
        seqs = [s for s, _ in by_run[rid]]
        assert seqs == list(range(1, len(seqs) + 1)), f"{rid}: event log has gaps"
        types = [t for _, t in by_run[rid]]
        done = sum(1 for t in mine if t["status"] in {"SUCCEEDED", "PARTIAL"})
        assert types.count("evidence.batch.stored") == done, f"{rid}: evidence stored twice or lost"
        if states[rid] == "REPORT_READY":
            assert reports.get(rid) == 1 and types.count("report.ready") == 1, rid
        else:
            failed = [e for t in mine for e in t["errors"]]
            assert failed and set(failed) <= {"LEASE_EXPIRED_MAX_ATTEMPTS"}, (
                rid,
                states[rid],
                failed,
            )
    assert chain.ok, chain
    reclaimed = sum(1 for t in tasks if t["attempts"] > 1)
    assert kills >= 1 and reclaimed >= 1, (
        f"no kill landed mid-task ({kills} kills); raise AISW_SOAK_RUNS"
    )

    for wid in survivors:
        assert "Traceback" not in (tmp / f"{wid}.log").read_text(), wid
    durations = sorted(float(d) for _, d in timing)
    ready = sum(1 for s in states.values() if s == "REPORT_READY")
    summary = (
        f"| {datetime.now(UTC):%Y-%m-%d} | {RUNS} | {len(tasks)} | {WORKERS} | {kills} | {LEASE}s | "
        f"{reclaimed} | {ready}/{RUNS} | {elapsed:.0f}s | {RUNS / elapsed * 60:.1f} | "
        f"{statistics.median(durations):.1f}s | {durations[int(0.95 * (len(durations) - 1))]:.1f}s |\n"
    )
    print(summary, end="")
    if os.environ.get("AISW_SOAK_REPORT"):
        with Path(os.environ["AISW_SOAK_REPORT"]).open("a") as fh:
            fh.write(summary)
