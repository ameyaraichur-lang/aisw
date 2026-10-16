"""End-to-end test server: embedded PostgreSQL + API + in-process worker, dev identity stub,
and a loopback mock OIDC IdP so single sign-on through the BFF is exercised too (ADR-026).

Runs ONLY for Playwright (never part of the product). Extra control routes under /__e2e let tests
pause the worker to observe in-flight state; they do not exist in the real application.
Usage: uv run python e2e/server.py  (listens on 127.0.0.1:8099)
"""

from __future__ import annotations

import json
import os
import secrets
import signal
import sys
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
from pydantic import SecretStr
from sqlalchemy import URL, create_engine, text

from aisw.api.app import create_app
from aisw.api.container import build_container
from aisw.authz.signing import KeyRing, LocalKeySigner
from aisw.core.config import Settings
from aisw.evidence.store import EvidenceStore
from aisw.llm.client import ModelUnavailable
from aisw.llm.validation import SYSTEM_PROMPT as VALIDATION_PROMPT

BACKEND = Path(__file__).resolve().parents[1]
PORT = int(os.environ.get("AISW_E2E_PORT", "8099"))


class DissentingReviewer:
    """No weights, no network. Narration is unavailable (the deterministic text stands); review
    concurs with everything except the first finding of each batch. ``concur=True`` narrates from
    the first fact of each subject and concurs with everything, so AI-written sections appear."""

    model_id = "e2e-reviewer-0"

    def __init__(self, *, concur: bool = False) -> None:
        self.concur = concur

    def complete(self, *, system: str, user: str, schema: dict[str, Any], timeout: float) -> str:
        if not system.startswith(VALIDATION_PROMPT[:40]):
            if not self.concur:
                raise ModelUnavailable("MODEL_UNREACHABLE")
            subject = json.loads(user.removeprefix("DATA:\n"))
            f = subject["facts"][0]
            asset = f["asset_ids"][0]
            return json.dumps({
                "summary": f"{len(subject['facts'])} recorded weaknesses relate to {asset}.",
                "claims": [{"text": f"The assessment recorded: {f['title']}.",
                            "finding_ids": [f["finding_id"]], "asset_ids": [asset]}],
                "open_questions": [f"Is the exposure recorded for {asset} intended?"]
                if subject["purpose"] == "verification" else [],
            })  # fmt: skip
        targets = json.loads(user.removeprefix("DATA:\n"))["targets"]
        first = (
            None
            if self.concur
            else next((t["target_ref"] for t in targets if t["kind"] == "finding"), None)
        )
        return json.dumps({"verdicts": [
            {"target_ref": t["target_ref"], "verdict": "DISSENT" if t["target_ref"] == first else "CONCUR",
             "validator_confidence": "MEDIUM",
             "issues": [{"code": "OUTCOME_NOT_SUPPORTED", "explanation": "The observed value is ambiguous.",
                         "evidence_refs": t["evidence_refs"][:1]}] if t["target_ref"] == first else []}
            for t in targets
        ]})  # fmt: skip


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
    # AISW_E2E_ENV_FILE (e.g. ../.env.astra) runs this server against a live model, by hand only.
    env_file = os.environ.get("AISW_E2E_ENV_FILE")
    sys.path.insert(0, str(BACKEND))
    from tests.oidc_idp import MockIdp  # noqa: PLC0415 - test-only module, needs the path above

    web = os.environ.get("AISW_E2E_WEB", "http://127.0.0.1:5199")
    idp = MockIdp([f"{web}/api/v1/auth/callback"]).start()
    settings = Settings(  # type: ignore[call-arg]
        _env_file=env_file, env="dev", dev_auth_stub=True, oidc_issuer=idp.issuer,
        oidc_client_id=idp.client_id, oidc_client_secret=idp.client_secret,
        oidc_redirect_uri=f"{web}/api/v1/auth/callback", session_secret=secrets.token_urlsafe(32),
    )  # fmt: skip
    container = build_container(
        settings, app_engine, signer=signer, keyring=KeyRing.from_signer(signer),
        evidence=EvidenceStore(work / "evidence"), resolver=lambda h, p: ["93.184.216.34"],
    )  # fmt: skip
    worker = container.make_worker(worker_engine, worker_id="e2e-worker")

    state: dict[str, Any] = {"paused": False, "step_delay": 0.15, "stalls": 0}
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

    plain = (container.settings, worker.model, worker.ai_validation)

    @api.post("/__e2e/ai-reviewer/{mode}")
    def ai_reviewer(mode: str) -> dict[str, str]:
        """``dissent``: a local scripted reviewer that dissents on the first finding it sees, so the
        UI's dissent resolution can be driven end to end. ``concur``: it narrates and concurs, so
        AI-written report sections appear. ``off`` restores the AI-off server."""
        if mode == "off":
            container.settings, worker.model, worker.ai_validation = plain
        else:
            container.settings = settings.model_copy(
                update={
                    "ai_enabled": True,
                    "model_id": "e2e-reviewer-0",
                    "model_license": "Apache-2.0",
                }
            )
            worker.model = DissentingReviewer(concur=mode == "concur")
            worker.ai_validation = True
        return {"mode": mode}

    fake_itsm: list[Any] = []

    @api.post("/__e2e/itsm/{mode}")
    def itsm(mode: str) -> dict[str, Any]:
        """``jira`` / ``servicenow``: ticket drafts and delivery on, delivering to a loopback fake
        ITSM. ``off`` restores the server's settings."""
        if mode == "off":
            container.settings = plain[0]
            return {"mode": mode}
        from tests.itsm_fake import FakeItsm  # noqa: PLC0415 - test-only module

        if not fake_itsm:
            fake_itsm.append(FakeItsm().start())
        f = fake_itsm[0]
        container.settings = container.settings.model_copy(
            update={"enable_itsm_ticket_creation": True, "enable_itsm_ticket_delivery": True,
                    "itsm_target": mode, "itsm_base_url": f.url, "itsm_username": f.username,
                    "itsm_token": SecretStr(f.token), "itsm_jira_project_key": "SEC"}
        )  # fmt: skip
        return {"mode": mode, "tickets": len(f.jira) + len(f.servicenow)}

    import aisw.api.views as views  # noqa: PLC0415

    real_stream = getattr(views, "stream_events")  # noqa: B009

    def stalling_stream(*args: Any, **kw: Any) -> Any:
        if state["stalls"] <= 0:
            return real_stream(*args, **kw)
        state["stalls"] -= 1

        def silent() -> Any:  # headers go out, then nothing: an open but dead stream
            end = time.monotonic() + 20
            while time.monotonic() < end and not stop.is_set():
                time.sleep(0.1)
            yield from ()

        return silent()

    setattr(views, "stream_events", stalling_stream)  # noqa: B010

    @api.post("/__e2e/stall-streams/{n}")
    def stall_streams(n: int) -> dict[str, int]:
        """The next ``n`` live-stream connections send headers and then nothing at all."""
        state["stalls"] = max(0, min(n, 5))
        return {"stalls": state["stalls"]}

    @api.post("/__e2e/delay/{ms}")
    def delay(ms: int) -> dict[str, float]:
        state["step_delay"] = max(0, min(ms, 5000)) / 1000
        return {"step_delay": state["step_delay"]}

    def _exit(
        *_: Any,
    ) -> None:  # uvicorn re-raises the signal to the ORIGINAL handler when it stops
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _exit)
    print(f"e2e server ready on {PORT}", flush=True)
    try:
        uvicorn.run(
            api, host="127.0.0.1", port=PORT, log_level="warning"
        )  # returns on SIGTERM/SIGINT
    finally:  # never leave an embedded Postgres behind (the machine allows few shared-memory segments)
        stop.set()
        idp.close()
        for f in fake_itsm:
            f.stop()
        for eng in (app_engine, worker_engine, owner, admin):
            eng.dispose()
        server.cleanup()


if __name__ == "__main__":
    main()
