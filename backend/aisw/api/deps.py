"""Request-scoped dependencies: identity and database access."""

from __future__ import annotations

from fastapi import Header, HTTPException, Request
from sqlalchemy import Engine

from aisw.core.auth import resolve_actor
from aisw.core.rbac import ActorContext


def get_actor(request: Request, authorization: str | None = Header(default=None)) -> ActorContext:
    return resolve_actor(request.app.state.settings, authorization)


def get_engine(request: Request) -> Engine:
    engine: Engine | None = request.app.state.engine
    if engine is None:
        raise HTTPException(status_code=503, detail="database not configured")
    return engine


def correlation_id(request: Request) -> str:
    return str(request.state.correlation_id)
