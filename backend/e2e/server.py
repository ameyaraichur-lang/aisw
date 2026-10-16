"""End-to-end test server: embedded PostgreSQL + API + in-process worker, dev identity stub.

Runs ONLY for Playwright (never part of the product). Extra control routes under /__e2e let tests
pause the worker to observe in-flight state; they do not exist in the real application.
Usage: uv run python e2e/server.py  (listens on 127.0.0.1:8099)
"""

from __future__ import annotations

import secrets
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pgserver  # type: ignore[import-untyped]
import uvicorn
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from sqlalchemy import URL, create_engine, text

from aisw.api.app import create_app
from aisw.api.container import build_container
from aisw.authz.signing import KeyRing, LocalKeySigner
from aisw.core.config import Settings
from aisw.evidence.store import EvidenceStore

BACKEND = Path(__file__).resolve().parents[1]
PORT = 8099


def main() -> None:
    work = Path(tempfile.mkdtemp(prefix="aisw-e2e-"))
    server = pgserver.get_server(work / "pg", cleanup_mode="stop")
    host = parse_qs(urlparse(server.get_uri()).query)["host"][0]

    def url(user: str, pw: str | None, db: str) -> URL:
        return URL.create(
            "postgresql+psycopg", username=user, password=pw, database=db, query={"host": host}
        )

    admin = create_engine(url("postgres", None, "postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text('CREATE DATABASE "aisw_e2e"'))
    owner = create_engine(url("postgres", None, "aisw_e2e"))
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "migrations"))
    with owner.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")
    app_pw, worker_pw = secrets.token_hex(16), secrets.token_hex(16)
    with owner.begin() as c:
        c.execute(text(f"ALTER ROLE aisw_app LOGIN PASSWORD '{app_pw}'"))
        c.execute(text(f"ALTER ROLE aisw_worker LOGIN PASSWORD '{worker_pw}'"))
    app_engine = create_engine(url("aisw_app", app_pw, "aisw_e2e"), future=True)
    worker_engine = create_engine(url("aisw_worker", worker_pw, "aisw_e2e"), future=True)

    signer = LocalKeySigner.generate("e2e-key")
    settings = Settings(env="dev", dev_auth_stub=True)
    container = build_container(
        settings, app_engine, signer=signer, keyring=KeyRing.from_signer(signer),
        evidence=EvidenceStore(work / "evidence"), resolver=lambda h, p: ["93.184.216.34"],
    )  # fmt: skip
    worker = container.make_worker(worker_engine, worker_id="e2e-worker")

    state: dict[str, Any] = {"paused": False, "step_delay": 0.15}
    stop = threading.Event()

    def loop() -> None:
        while not stop.is_set():
            if state["paused"]:
                time.sleep(0.05)
                continue
            try:
                progressed = worker.step()
            except Exception as exc:  # keep serving; the test will show the failure
                print("worker error:", exc, flush=True)
                progressed = False
            time.sleep(state["step_delay"] if progressed else 0.1)

    threading.Thread(target=loop, daemon=True).start()

    api: FastAPI = create_app(settings, app_engine, container)

    @api.post("/__e2e/pause")
    def pause() -> dict[str, bool]:
        state["paused"] = True
        return {"paused": True}

    @api.post("/__e2e/resume")
    def resume() -> dict[str, bool]:
        state["paused"] = False
        return {"paused": False}

    @api.post("/__e2e/delay/{ms}")
    def delay(ms: int) -> dict[str, float]:
        state["step_delay"] = max(0, min(ms, 5000)) / 1000
        return {"step_delay": state["step_delay"]}

    print(f"e2e server ready on {PORT}", flush=True)
    uvicorn.run(api, host="127.0.0.1", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
