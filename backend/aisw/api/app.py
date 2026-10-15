"""FastAPI application factory. M0 exposes health/readiness only."""

from __future__ import annotations

from fastapi import FastAPI

from aisw import __version__
from aisw.core.config import Settings, get_settings


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or get_settings()
    app = FastAPI(title="AISW", version=__version__, docs_url=None, redoc_url=None)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/readyz")
    def readyz() -> dict[str, str | bool]:
        return {
            "status": "ready",
            "assessment_mode": cfg.assessment_mode.value,
            "ai_enabled": cfg.ai_enabled,
        }

    return app
