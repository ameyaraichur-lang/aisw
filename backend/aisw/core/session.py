"""Signed cookies for BFF sessions (ADR-026).

A cookie value is ``base64url(json).base64url(hmac)``. The HMAC key is derived per purpose, so a
login cookie can never be replayed as a session cookie. Payloads carry their own expiry; revocation
is a database lookup by session id done by the caller.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from typing import Any

SESSION_COOKIE = "aisw_session"
CSRF_COOKIE = "aisw_csrf"
LOGIN_COOKIE = "aisw_login"
CSRF_HEADER = "x-aisw-csrf"
LOGIN_TTL_SECONDS = 600
MAX_COOKIE_BYTES = 3800


class SessionError(Exception):
    pass


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


class CookieCodec:
    def __init__(self, secret: str) -> None:
        if len(secret) < 32:
            raise ValueError("session secret must be at least 32 characters")
        self._root = secret.encode()

    def _key(self, purpose: str) -> bytes:
        return hmac.new(self._root, b"aisw-cookie:" + purpose.encode(), hashlib.sha256).digest()

    def dumps(self, purpose: str, payload: dict[str, Any], *, expires_at: int) -> str:
        body = _b64(json.dumps({**payload, "exp": expires_at}, separators=(",", ":")).encode())
        sig = _b64(hmac.new(self._key(purpose), body.encode(), hashlib.sha256).digest())
        value = f"{body}.{sig}"
        if len(value) > MAX_COOKIE_BYTES:
            raise SessionError("cookie payload too large")
        return value

    def loads(self, purpose: str, value: str | None, *, now: int) -> dict[str, Any]:
        if not value or len(value) > MAX_COOKIE_BYTES or value.count(".") != 1:
            raise SessionError("missing or malformed cookie")
        body, sig = value.split(".")
        expected = _b64(hmac.new(self._key(purpose), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            raise SessionError("bad cookie signature")
        try:
            payload = json.loads(_unb64(body))
        except ValueError:
            raise SessionError("malformed cookie") from None
        if not isinstance(payload, dict) or not isinstance(payload.get("exp"), int):
            raise SessionError("malformed cookie")
        if payload["exp"] <= now:
            raise SessionError("cookie expired")
        return payload
