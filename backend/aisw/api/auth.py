"""BFF sign-in: OIDC authorization code + PKCE, signed session cookies, CSRF (ADR-026).

The browser never sees an IdP token. The callback verifies the ID token server-side and issues an
HttpOnly session cookie; unsafe requests made with that cookie must echo the session's CSRF token
in a header. Logout records the session id as revoked so the cookie stops working immediately.
"""

from __future__ import annotations

import hmac
import logging
import re
import time
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from sqlalchemy import Engine, text

from aisw.core import session as cookies
from aisw.core.audit import append_audit
from aisw.core.auth import AuthError
from aisw.core.config import Settings
from aisw.core.db import tenant_connection
from aisw.core.oidc import OidcError, OidcProvider
from aisw.core.rbac import ActorContext, Forbidden, Role
from aisw.core.session import CookieCodec, SessionError, token

log = logging.getLogger("aisw.auth")
router = APIRouter(prefix="/api/v1/auth")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_RETURN_TO = re.compile(r"^/(?![/\\])[\w\-./?=&%~]*$")
LOGIN_FAILED = "/login?error=sso_failed"


def safe_return_to(value: str | None) -> str:
    """Only same-origin absolute paths; anything else (``//evil``, ``https:``, ``/\\``) is ``/``."""
    if not value or len(value) > 512 or not _RETURN_TO.match(value):
        return "/"
    return value


def _provider(request: Request) -> OidcProvider:
    p: OidcProvider | None = getattr(request.app.state, "oidc", None)
    if p is None:
        raise AuthError("single sign-on is not configured")
    return p


def _codec(settings: Settings) -> CookieCodec:
    if settings.session_secret is None:
        raise AuthError("sessions are not configured")
    return CookieCodec(settings.session_secret.get_secret_value())


def _engine(request: Request) -> Engine:
    engine: Engine | None = request.app.state.engine
    if engine is None:
        raise AuthError("sessions need the database")
    return engine


def _secure(settings: Settings) -> bool:
    return urlparse(settings.oidc_redirect_uri or "").scheme == "https"


def _cid(request: Request) -> str:
    return str(getattr(request.state, "correlation_id", "") or uuid.uuid4())


def session_actor(request: Request) -> ActorContext:
    """Resolve the cookie session. Unsafe methods must carry the session's CSRF token."""
    s: Settings = request.app.state.settings
    _provider(request)
    try:
        sess = _codec(s).loads(
            "session", request.cookies.get(cookies.SESSION_COOKIE), now=int(time.time())
        )
    except SessionError as exc:
        raise AuthError(str(exc)) from None
    fields = [sess.get(k) for k in ("sid", "tid", "sub", "csrf")]
    if not all(isinstance(v, str) and v for v in fields):
        raise AuthError("malformed session")
    sid, tenant, sub, csrf = (str(v) for v in fields)
    if request.method not in SAFE_METHODS:
        sent = request.headers.get(cookies.CSRF_HEADER, "")
        if not hmac.compare_digest(sent.encode(), csrf.encode()):
            raise Forbidden("csrf token missing or wrong")
    with tenant_connection(_engine(request), tenant) as conn:
        revoked = conn.execute(
            text("SELECT 1 FROM auth_session_revocations WHERE sid = :s"), {"s": sid}
        ).first()
    if revoked:
        raise AuthError("session revoked")
    valid = {r.value for r in Role}
    roles = frozenset(Role(v) for v in sess.get("roles", []) if isinstance(v, str) and v in valid)
    return ActorContext(tenant, sub, roles)


@router.get("/login")
def login(request: Request, return_to: str | None = None) -> Response:
    s: Settings = request.app.state.settings
    provider = _provider(request)
    state, nonce, verifier = token(), token(), token(48)
    try:
        url = provider.authorize_url(state=state, nonce=nonce, verifier=verifier)
    except OidcError as exc:
        log.warning("sso login unavailable: %s", exc)
        return JSONResponse({"error": "sso_unavailable"}, status_code=503)
    now = int(time.time())
    value = _codec(s).dumps(
        "login", {"state": state, "nonce": nonce, "verifier": verifier,
                  "return_to": safe_return_to(return_to)},
        expires_at=now + cookies.LOGIN_TTL_SECONDS,
    )  # fmt: skip
    resp = RedirectResponse(url, status_code=302)
    resp.set_cookie(cookies.LOGIN_COOKIE, value, max_age=cookies.LOGIN_TTL_SECONDS, path="/api/v1/auth",
                    httponly=True, secure=_secure(s), samesite="lax")  # fmt: skip
    resp.headers["cache-control"] = "no-store"
    return resp


def _failed(reason: str, settings: Settings) -> RedirectResponse:
    log.warning("sso callback rejected: %s", reason)
    resp = RedirectResponse(LOGIN_FAILED, status_code=302)
    resp.delete_cookie(cookies.LOGIN_COOKIE, path="/api/v1/auth", secure=_secure(settings))
    resp.headers["cache-control"] = "no-store"
    return resp


@router.get("/callback")
def callback(
    request: Request, code: str | None = None, state: str | None = None, error: str | None = None
) -> Response:
    s: Settings = request.app.state.settings
    provider = _provider(request)
    now = int(time.time())
    try:
        pending = _codec(s).loads("login", request.cookies.get(cookies.LOGIN_COOKIE), now=now)
    except SessionError as exc:
        return _failed(f"login cookie: {exc}", s)
    if error is not None:
        return _failed(f"idp returned error {error[:64]!r}", s)
    if (
        not code
        or not state
        or not hmac.compare_digest(state.encode(), str(pending["state"]).encode())
    ):
        return _failed("state mismatch", s)
    try:
        tokens = provider.exchange_code(code, str(pending["verifier"]))
        claims = provider.verify(tokens["id_token"], audience=s.oidc_client_id or "",
                                 nonce=str(pending["nonce"]))  # fmt: skip
        actor = provider.actor(claims)
    except OidcError as exc:
        return _failed(str(exc), s)
    sid, csrf = token(24), token(24)
    expires = now + s.oidc_session_minutes * 60
    value = _codec(s).dumps(
        "session", {"sid": sid, "tid": actor.tenant_id, "sub": actor.actor_id, "csrf": csrf,
                    "roles": sorted(r.value for r in actor.roles), "iat": now},
        expires_at=expires,
    )  # fmt: skip
    with tenant_connection(_engine(request), actor.tenant_id) as conn:
        append_audit(conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="auth.login",
                     resource=f"session:{sid[:8]}", result="SUCCESS",
                     correlation_id=_cid(request))  # fmt: skip
    resp = RedirectResponse(str(pending.get("return_to") or "/"), status_code=302)
    secure, ttl = _secure(s), s.oidc_session_minutes * 60
    resp.delete_cookie(cookies.LOGIN_COOKIE, path="/api/v1/auth", secure=secure)
    resp.set_cookie(cookies.SESSION_COOKIE, value, max_age=ttl, path="/api", httponly=True,
                    secure=secure, samesite="lax")  # fmt: skip
    resp.set_cookie(cookies.CSRF_COOKIE, csrf, max_age=ttl, path="/", httponly=False,
                    secure=secure, samesite="strict")  # fmt: skip
    resp.headers["cache-control"] = "no-store"
    return resp


@router.post("/logout")
def logout(request: Request) -> Response:
    s: Settings = request.app.state.settings
    provider = _provider(request)
    actor = session_actor(request)
    sess = _codec(s).loads(
        "session", request.cookies.get(cookies.SESSION_COOKIE), now=int(time.time())
    )
    sid = str(sess["sid"])
    with tenant_connection(_engine(request), actor.tenant_id) as conn:
        conn.execute(
            text("INSERT INTO auth_session_revocations (tenant_id, sid, actor_id, revoked_at, "
                 "expires_at) VALUES (:t, :s, :a, :r, :e) ON CONFLICT DO NOTHING"),
            {"t": actor.tenant_id, "s": sid, "a": actor.actor_id, "r": datetime.now(UTC),
             "e": datetime.fromtimestamp(int(sess["exp"]), UTC)},
        )  # fmt: skip
        append_audit(conn, tenant_id=actor.tenant_id, actor=actor.actor_id, action="auth.logout",
                     resource=f"session:{sid[:8]}", result="SUCCESS",
                     correlation_id=_cid(request))  # fmt: skip
    try:
        end = provider.end_session_url()
    except OidcError:
        end = None
    body: dict[str, Any] = {"signed_out": True, "end_session_url": end}
    resp = JSONResponse(body)
    secure = _secure(s)
    resp.delete_cookie(cookies.SESSION_COOKIE, path="/api", secure=secure, httponly=True)
    resp.delete_cookie(cookies.CSRF_COOKIE, path="/", secure=secure)
    resp.headers["cache-control"] = "no-store"
    return resp
