"""Request-scoped dependencies: identity and database access."""

from __future__ import annotations

from fastapi import Header, HTTPException, Request
from sqlalchemy import Engine

from aisw.api.auth import session_actor
from aisw.core.auth import AuthError, resolve_actor
from aisw.core.config import Environment, Settings
from aisw.core.oidc import OidcProvider
from aisw.core.rbac import ActorContext
from aisw.core.session import SESSION_COOKIE


def get_actor(request: Request, authorization: str | None = Header(default=None)) -> ActorContext:
    """A bearer header wins over a cookie: dev stub tokens, else an IdP-issued JWT (ADR-026)."""
    s: Settings = request.app.state.settings
    oidc: OidcProvider | None = getattr(request.app.state, "oidc", None)
    stub = s.dev_auth_stub and s.env in {Environment.DEV, Environment.TEST}
    if authorization is not None:
        if oidc is not None and not (stub and authorization.startswith("Bearer dev-")):
            if not authorization.startswith("Bearer "):
                raise AuthError("missing bearer credential")
            jwt = authorization.removeprefix("Bearer ").strip()
            claims = oidc.verify(jwt, audience=s.oidc_audience or s.oidc_client_id or "")
            return oidc.actor(claims)
        return resolve_actor(s, authorization)
    if oidc is not None and SESSION_COOKIE in request.cookies:
        return session_actor(request)
    return resolve_actor(s, authorization)


def get_engine(request: Request) -> Engine:
    engine: Engine | None = request.app.state.engine
    if engine is None:
        raise HTTPException(status_code=503, detail="database not configured")
    return engine


def correlation_id(request: Request) -> str:
    return str(request.state.correlation_id)
