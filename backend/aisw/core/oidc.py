"""OIDC relying party for the BFF (ADR-026). Any standards-compliant IdP; nothing IdP-specific.

Tokens are verified against the issuer's published keys with an allow-list of asymmetric
algorithms (never ``none`` or HMAC), exact issuer, audience, expiry and, for ID tokens, the nonce.
Discovery and key fetches use a transport that ignores proxy variables, refuses redirects and caps
response size. Roles and the tenant come only from verified claims.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

import jwt

from aisw.core import safe_http
from aisw.core.auth import AuthError
from aisw.core.config import Settings, oidc_url_problem
from aisw.core.rbac import ActorContext, Role

ALLOWED_ALGS = ("RS256", "PS256", "ES256", "EdDSA")
LEEWAY_SECONDS = 60
MAX_DOC_BYTES = 512 * 1024
METADATA_TTL = 3600.0
JWKS_TTL = 600.0
JWKS_MIN_REFRESH = 30.0
_TENANT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


class OidcError(AuthError):
    """Any OIDC failure. Callers answer 401; the reason is for logs, never for the client."""


Fetch = Callable[[urllib.request.Request], bytes]


def _default_fetch(req: urllib.request.Request) -> bytes:
    try:
        return safe_http.fetch(req, max_bytes=MAX_DOC_BYTES)
    except safe_http.HttpError as exc:
        raise OidcError(f"idp {exc}") from None


def _json(raw: bytes) -> dict[str, Any]:
    try:
        doc = json.loads(raw)
    except ValueError:
        raise OidcError("idp response is not JSON") from None
    if not isinstance(doc, dict):
        raise OidcError("idp response is not an object")
    return doc


class OidcProvider:
    def __init__(
        self, settings: Settings, *, fetch: Fetch | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:  # fmt: skip
        if not settings.oidc_enabled or settings.oidc_issuer is None:
            raise ValueError("OIDC is not configured")
        self._s = settings
        self._issuer = settings.oidc_issuer.rstrip("/")
        self._fetch = fetch or _default_fetch
        self._clock = clock
        self._lock = threading.Lock()
        self._meta: tuple[float, dict[str, Any]] | None = None
        self._jwks: tuple[float, jwt.PyJWKSet] | None = None
        self._jwks_fetched = 0.0

    # ---- discovery and keys ----------------------------------------------------------------------
    def _get(self, url: str) -> dict[str, Any]:
        if problem := oidc_url_problem("idp url", url, self._s.env):
            raise OidcError(problem)
        req = urllib.request.Request(url, headers={"accept": "application/json"})  # noqa: S310
        return _json(self._fetch(req))

    def metadata(self) -> dict[str, Any]:
        with self._lock:
            if self._meta and self._clock() - self._meta[0] < METADATA_TTL:
                return self._meta[1]
        doc = self._get(f"{self._issuer}/.well-known/openid-configuration")
        if str(doc.get("issuer", "")).rstrip("/") != self._issuer:
            raise OidcError("discovery issuer does not match the configured issuer")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not isinstance(doc.get(key), str) or oidc_url_problem(key, doc[key], self._s.env):
                raise OidcError(f"discovery {key} is missing or unsafe")
        for key in ("token_endpoint", "jwks_uri"):  # the server connects to these: egress-bound
            if not self._egress_ok(doc[key]):
                raise OidcError(f"discovery {key} is on a host outside the egress allow-list")
        with self._lock:
            self._meta = (self._clock(), doc)
        return doc

    def _egress_ok(self, url: str) -> bool:
        u, issuer = urllib.parse.urlparse(url), urllib.parse.urlparse(self._issuer)
        host = (u.hostname or "").lower()
        if (host, u.port) == ((issuer.hostname or "").lower(), issuer.port):
            return True
        port = u.port or (443 if u.scheme == "https" else 80)
        extras = self._s.egress_extra_hosts
        return host in extras or f"{host}:{port}" in extras

    def _keyset(self, *, refresh: bool) -> jwt.PyJWKSet:
        now = self._clock()
        with self._lock:
            cached = self._jwks
            fresh = cached is not None and now - cached[0] < JWKS_TTL
            throttled = now - self._jwks_fetched < JWKS_MIN_REFRESH
        if cached is not None and (fresh and not refresh or throttled):
            return cached[1]
        doc = self._get(self.metadata()["jwks_uri"])
        try:
            keyset = jwt.PyJWKSet.from_dict(doc)
        except jwt.PyJWTError:
            raise OidcError("idp key set is unusable") from None
        with self._lock:
            self._jwks, self._jwks_fetched = (now, keyset), now
        return keyset

    def _key(self, kid: str) -> jwt.PyJWK:
        for refresh in (False, True):  # an unknown kid may mean the IdP rotated: refetch once
            for k in self._keyset(refresh=refresh).keys:
                if k.key_id == kid:
                    return k
        raise OidcError("token signed by an unknown key")

    # ---- tokens ----------------------------------------------------------------------------------
    def verify(self, token: str, *, audience: str, nonce: str | None = None) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise OidcError("malformed token") from None
        alg, kid = header.get("alg"), header.get("kid")
        if alg not in ALLOWED_ALGS or not isinstance(kid, str):
            raise OidcError("token algorithm or key id not accepted")
        key = self._key(kid)
        try:
            claims: dict[str, Any] = jwt.decode(
                token, key.key, algorithms=[alg], audience=audience, issuer=self._issuer,
                leeway=LEEWAY_SECONDS, options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )  # fmt: skip
        except jwt.PyJWTError as exc:
            raise OidcError(f"token rejected: {type(exc).__name__}") from None
        aud = claims.get("aud")
        if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != audience:
            raise OidcError("token issued to another party")
        if nonce is not None and claims.get("nonce") != nonce:
            raise OidcError("nonce mismatch")
        return claims

    def actor(self, claims: dict[str, Any]) -> ActorContext:
        tenant = claims.get(self._s.oidc_tenant_claim)
        if not isinstance(tenant, str) or not _TENANT.match(tenant):
            raise OidcError("token has no usable tenant claim")
        raw = claims.get(self._s.oidc_roles_claim, [])
        values = raw.split() if isinstance(raw, str) else raw if isinstance(raw, list) else []
        mapping = self._s.oidc_roles or {r.value: r.value for r in Role}
        roles = frozenset(Role(mapping[v]) for v in values if isinstance(v, str) and v in mapping)
        sub = claims["sub"]  # stable and unique per issuer, unlike preferred_username
        if not isinstance(sub, str) or not 0 < len(sub) <= 128:
            raise OidcError("token subject is unusable")
        return ActorContext(tenant, sub, roles)

    # ---- authorization code flow -----------------------------------------------------------------
    def authorize_url(self, *, state: str, nonce: str, verifier: str) -> str:
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        params = {
            "response_type": "code", "client_id": self._s.oidc_client_id,
            "redirect_uri": self._s.oidc_redirect_uri, "scope": self._s.oidc_scopes,
            "state": state, "nonce": nonce, "code_challenge": challenge,
            "code_challenge_method": "S256",
        }  # fmt: skip
        return f"{self.metadata()['authorization_endpoint']}?{urllib.parse.urlencode(params)}"

    def exchange_code(self, code: str, verifier: str) -> dict[str, Any]:
        form = {
            "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
            "redirect_uri": self._s.oidc_redirect_uri or "", "client_id": self._s.oidc_client_id or "",
        }  # fmt: skip
        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        }
        if self._s.oidc_client_secret is not None:
            pair = (
                f"{urllib.parse.quote(self._s.oidc_client_id or '', safe='')}:"
                + urllib.parse.quote(self._s.oidc_client_secret.get_secret_value(), safe="")
            )
            headers["authorization"] = "Basic " + base64.b64encode(pair.encode()).decode()
        url = self.metadata()["token_endpoint"]
        req = urllib.request.Request(  # noqa: S310 - validated in metadata()
            url, data=urllib.parse.urlencode(form).encode(), headers=headers, method="POST"
        )
        doc = _json(self._fetch(req))
        if not isinstance(doc.get("id_token"), str):
            raise OidcError("token response has no id_token")
        return doc

    def end_session_url(self) -> str | None:
        url = self.metadata().get("end_session_endpoint")
        return (
            url if isinstance(url, str) and not oidc_url_problem("end", url, self._s.env) else None
        )
