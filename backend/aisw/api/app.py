"""FastAPI application factory."""

from __future__ import annotations

import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import Engine

from aisw import __version__
from aisw.api import assessments, projects, scope
from aisw.api.container import Container, build_container
from aisw.authz.service import ScopeDenied
from aisw.core.auth import AuthError
from aisw.core.config import Settings, get_settings
from aisw.core.db import make_engine
from aisw.core.idempotency import IdempotencyConflict
from aisw.core.rbac import Forbidden


def create_app(
    settings: Settings | None = None,
    engine: Engine | None = None,
    container: Container | None = None,
) -> FastAPI:
    cfg = settings or get_settings()
    if engine is None and cfg.database_url is not None:
        engine = make_engine(cfg.database_url.get_secret_value())
    app = FastAPI(title="AISW", version=__version__, docs_url=None, redoc_url=None)
    app.state.settings = cfg
    app.state.engine = engine
    if container is None and engine is not None:
        container = build_container(cfg, engine)
    app.state.container = container

    @app.middleware("http")
    async def correlation_id(request: Request, call_next):  # type: ignore[no-untyped-def]
        cid = request.headers.get("x-correlation-id") or str(uuid.uuid4())
        request.state.correlation_id = cid[:128]
        response = await call_next(request)
        response.headers["x-correlation-id"] = request.state.correlation_id
        return response

    @app.exception_handler(AuthError)
    async def _auth(_: Request, __: AuthError) -> JSONResponse:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)

    @app.exception_handler(Forbidden)
    async def _forbidden(_: Request, __: Forbidden) -> JSONResponse:
        return JSONResponse({"error": "forbidden"}, status_code=403)

    @app.exception_handler(ScopeDenied)
    async def _scope_denied(_: Request, exc: ScopeDenied) -> JSONResponse:
        codes = exc.reason_codes
        if codes == ["MANIFEST_NOT_FOUND"]:
            status = 404
        elif set(codes) & {"ROLE_NOT_PERMITTED", "CROSS_TENANT", "SELF_APPROVAL"}:
            status = 403
        else:
            status = 422
        issues = (
            [
                {"code": i.code, "severity": i.severity, "detail": i.detail}
                for i in exc.outcome.issues
            ]
            if exc.outcome
            else []
        )
        return JSONResponse(
            {"error": "scope_denied", "reason_codes": codes, "issues": issues}, status_code=status
        )

    @app.exception_handler(IdempotencyConflict)
    async def _idem(_: Request, exc: IdempotencyConflict) -> JSONResponse:
        return JSONResponse({"error": "idempotency_conflict", "detail": str(exc)}, status_code=409)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/readyz")
    def readyz() -> dict[str, str | bool]:
        return {
            "status": "ready",
            "assessment_mode": cfg.assessment_mode.value,
            "ai_enabled": cfg.ai_enabled,
            "database_configured": engine is not None,
        }

    app.include_router(projects.router)
    app.include_router(scope.router)
    app.include_router(assessments.router)
    return app
