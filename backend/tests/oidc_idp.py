"""A loopback OIDC identity provider for tests and e2e (ADR-026). Never for real use.

Implements just enough of OIDC core for the BFF: discovery, a JWKS, the authorization endpoint
(an HTML user picker, or ``login_hint`` to sign in immediately), the token endpoint with PKCE S256
and client_secret_basic, and an end-session endpoint. ``mint`` makes tokens, including bad ones.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

USERS: dict[str, dict[str, Any]] = {
    "alice": {"tenant": "tenant-a", "roles": ["project_admin", "assessment_operator"]},
    "bob": {"tenant": "tenant-a", "roles": ["approver"]},
    "carol": {"tenant": "tenant-a", "roles": ["report_reader"]},
    "rita": {"tenant": "tenant-a", "roles": ["reviewer"]},
    "sam": {"tenant": "tenant-a", "roles": ["assessment_operator", "reviewer"]},
    "erin": {"tenant": "tenant-a", "roles": ["auditor"]},
    "dave": {"tenant": "tenant-b", "roles": ["project_admin"]},
}


class MockIdp:
    def __init__(self, redirect_uris: list[str], *, client_id: str = "aisw-console") -> None:
        self.client_id = client_id
        self.client_secret = secrets.token_urlsafe(24)
        self.redirect_uris = redirect_uris
        self.keys: dict[str, rsa.RSAPrivateKey] = {
            "test-1": rsa.generate_private_key(public_exponent=65537, key_size=2048)
        }
        self.active_kid = "test-1"
        self.codes: dict[str, dict[str, Any]] = {}
        self.token_requests = 0
        self.jwks_requests = 0
        self.nonce_override: str | None = None
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.issuer = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> MockIdp:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def start(self) -> MockIdp:
        return self.__enter__()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    # ---- keys and tokens ---------------------------------------------------------------------
    def rotate(self) -> str:
        kid = f"test-{len(self.keys) + 1}"
        self.keys[kid] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.active_kid = kid
        return kid

    def jwks(self) -> dict[str, Any]:
        out = []
        for kid, key in self.keys.items():
            jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
            out.append({**jwk, "kid": kid, "use": "sig", "alg": "RS256"})
        return {"keys": out}

    def mint(
        self, user: str = "alice", *, aud: str | list[str] | None = None, iss: str | None = None,
        ttl: int = 300, nonce: str | None = None, alg: str = "RS256", kid: str | None = None,
        claims: dict[str, Any] | None = None, drop: tuple[str, ...] = (),
    ) -> str:  # fmt: skip
        now = int(time.time())
        info = USERS.get(user, {"tenant": "tenant-a", "roles": []})
        payload: dict[str, Any] = {
            "iss": iss or self.issuer, "sub": user, "aud": aud or self.client_id,
            "iat": now, "exp": now + ttl, "preferred_username": user,
            "tenant": info["tenant"], "roles": info["roles"],
        }  # fmt: skip
        if nonce is not None:
            payload["nonce"] = nonce
        payload.update(claims or {})
        for k in drop:
            payload.pop(k, None)
        kid = kid or self.active_kid
        if alg == "none":
            return jwt.encode(payload, "", algorithm="none", headers={"kid": kid})
        if alg == "HS256":
            return jwt.encode(payload, "x" * 32, algorithm="HS256", headers={"kid": kid})
        key = self.keys.get(kid) or rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return jwt.encode(payload, key, algorithm=alg, headers={"kid": kid})

    # ---- HTTP ----------------------------------------------------------------------------------
    def _handler(self) -> type[BaseHTTPRequestHandler]:
        idp = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: Any) -> None:
                pass

            def _send(self, code: int, body: Any, ctype: str = "application/json") -> None:
                raw = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("content-type", ctype)
                self.send_header("content-length", str(len(raw)))
                self.send_header("cache-control", "no-store")
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                u = urlparse(self.path)
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                if u.path == "/.well-known/openid-configuration":
                    self._send(200, {
                        "issuer": idp.issuer, "authorization_endpoint": f"{idp.issuer}/authorize",
                        "token_endpoint": f"{idp.issuer}/token", "jwks_uri": f"{idp.issuer}/jwks",
                        "end_session_endpoint": f"{idp.issuer}/logout",
                        "response_types_supported": ["code"], "subject_types_supported": ["public"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                        "code_challenge_methods_supported": ["S256"],
                    })  # fmt: skip
                elif u.path == "/jwks":
                    idp.jwks_requests += 1
                    self._send(200, idp.jwks())
                elif u.path == "/authorize":
                    self._authorize(q)
                elif u.path == "/logout":
                    self._send(200, b"<p>Signed out of the mock IdP.</p>", "text/html")
                else:
                    self._send(404, {"error": "not_found"})

            def _authorize(self, q: dict[str, str]) -> None:
                ok = (
                    q.get("client_id") == idp.client_id
                    and q.get("redirect_uri") in idp.redirect_uris
                    and q.get("response_type") == "code"
                    and q.get("code_challenge_method") == "S256"
                    and q.get("code_challenge") and q.get("state") and q.get("nonce")
                    and "openid" in q.get("scope", "").split()
                )  # fmt: skip
                if not ok:
                    self._send(400, {"error": "invalid_request"})
                    return
                user = q.get("login_hint")
                if user not in USERS:
                    rows = "".join(
                        f'<li><a href="/authorize?{html.escape(urlencode({**q, "login_hint": n}))}"'
                        f">{html.escape(n)}</a></li>"
                        for n in USERS
                    )
                    self._send(200, f"<h1>Mock IdP</h1><ul>{rows}</ul>".encode(), "text/html")
                    return
                code = secrets.token_urlsafe(16)
                idp.codes[code] = {"user": user, "nonce": q["nonce"], "challenge": q["code_challenge"],
                                   "redirect_uri": q["redirect_uri"]}  # fmt: skip
                self.send_response(302)
                sep = "&" if "?" in q["redirect_uri"] else "?"
                loc = f"{q['redirect_uri']}{sep}{urlencode({'code': code, 'state': q['state']})}"
                self.send_header("location", loc)
                self.send_header("content-length", "0")
                self.end_headers()

            def do_POST(self) -> None:
                if urlparse(self.path).path != "/token":
                    self._send(404, {"error": "not_found"})
                    return
                idp.token_requests += 1
                n = int(self.headers.get("content-length") or 0)
                form = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}
                basic = base64.b64encode(f"{idp.client_id}:{idp.client_secret}".encode()).decode()
                if self.headers.get("authorization") != f"Basic {basic}":
                    self._send(401, {"error": "invalid_client"})
                    return
                grant = idp.codes.pop(form.get("code", ""), None)  # codes are single use
                verifier = form.get("code_verifier", "")
                challenge = (
                    base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                    .rstrip(b"=")
                    .decode()
                )
                if (
                    form.get("grant_type") != "authorization_code"
                    or grant is None
                    or grant["redirect_uri"] != form.get("redirect_uri")
                    or grant["challenge"] != challenge
                ):
                    self._send(400, {"error": "invalid_grant"})
                    return
                nonce = idp.nonce_override or grant["nonce"]
                self._send(200, {
                    "id_token": idp.mint(grant["user"], nonce=nonce),
                    "access_token": idp.mint(grant["user"]),
                    "token_type": "Bearer", "expires_in": 300,
                })  # fmt: skip

        return Handler
