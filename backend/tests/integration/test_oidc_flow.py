"""The BFF sign-in end to end against a loopback IdP: login, cookies, CSRF, RBAC, logout (ADR-026)."""

from __future__ import annotations

import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from aisw.api.app import create_app
from aisw.core.db import tenant_connection
from aisw.core.session import CookieCodec
from tests.oidc_idp import MockIdp
from tests.unit.test_oidc import REDIRECT, SECRET, oidc_settings

pytestmark = pytest.mark.security


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_: Any, **__: Any) -> None:
        return None


@pytest.fixture(scope="module")
def idp() -> Iterator[MockIdp]:
    with MockIdp([REDIRECT]) as i:
        yield i


def browser(app_engine: Engine, idp: MockIdp, **kw: Any) -> TestClient:
    app = create_app(oidc_settings(idp, **kw), engine=app_engine)
    return TestClient(app, base_url="https://testserver", follow_redirects=False)


def idp_authorize(url: str, user: str) -> str:
    """The user's browser at the IdP: pick a user, get redirected back with a code."""
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))
    try:
        opener.open(f"{url}&login_hint={user}")  # noqa: S310 - loopback test IdP
    except urllib.error.HTTPError as exc:
        assert exc.code == 302
        return str(exc.headers["location"])
    raise AssertionError("IdP did not redirect")


def sign_in(c: TestClient, user: str, return_to: str = "/") -> Any:
    r = c.get("/api/v1/auth/login", params={"return_to": return_to})
    assert r.status_code == 302, r.text
    back = urlparse(idp_authorize(r.headers["location"], user))
    return c.get(f"{back.path}?{back.query}")


def csrf(c: TestClient) -> dict[str, str]:
    return {"X-AISW-CSRF": c.cookies["aisw_csrf"]}


def new_project(c: TestClient, headers: dict[str, str]) -> Any:
    return c.post("/api/v1/projects", json={"name": f"sso-{uuid.uuid4().hex[:8]}",
                  "environment": "test"},
                  headers={**headers, "Idempotency-Key": uuid.uuid4().hex})  # fmt: skip


def test_full_login_sets_hardened_cookies_and_identity(app_engine: Engine, idp: MockIdp) -> None:
    c = browser(app_engine, idp)
    assert c.get("/api/v1/auth/mode").json() == {"mode": "oidc", "users": [], "sso": True}
    assert c.get("/api/v1/me").status_code == 401
    r = sign_in(c, "alice", "/runs/abc?tab=report")
    assert r.status_code == 302 and r.headers["location"] == "/runs/abc?tab=report"
    cookies = {h.split("=", 1)[0]: h.lower() for h in r.headers.get_list("set-cookie")}
    session = cookies["aisw_session"]
    assert "httponly" in session and "secure" in session and "samesite=lax" in session
    assert "path=/api" in session
    assert "httponly" not in cookies["aisw_csrf"] and "samesite=strict" in cookies["aisw_csrf"]
    assert "max-age=0" in cookies["aisw_login"] or 'aisw_login=""' in cookies["aisw_login"]
    me = c.get("/api/v1/me").json()
    assert (me["tenant_id"], me["actor_id"]) == ("tenant-a", "alice")
    assert "project:create" in me["permissions"]
    with tenant_connection(app_engine, "tenant-a") as conn:
        n = conn.execute(text("SELECT count(*) FROM audit_events WHERE action = 'auth.login' "
                              "AND actor = 'alice'")).scalar_one()  # fmt: skip
    assert n >= 1


def test_unsafe_requests_need_the_csrf_token(app_engine: Engine, idp: MockIdp) -> None:
    c = browser(app_engine, idp)
    sign_in(c, "alice")
    assert new_project(c, {}).status_code == 403
    assert new_project(c, {"X-AISW-CSRF": "guess"}).status_code == 403
    assert new_project(c, csrf(c)).status_code == 201
    other = browser(app_engine, idp)  # another session's token does not transfer
    sign_in(other, "alice")
    assert new_project(c, csrf(other)).status_code == 403


def test_logout_revokes_the_session_cookie(app_engine: Engine, idp: MockIdp) -> None:
    c = browser(app_engine, idp)
    sign_in(c, "carol")
    stolen = c.cookies["aisw_session"]
    assert c.post("/api/v1/auth/logout").status_code == 403  # CSRF applies to logout too
    r = c.post("/api/v1/auth/logout", headers=csrf(c))
    assert r.status_code == 200
    assert r.json() == {"signed_out": True, "end_session_url": f"{idp.issuer}/logout"}
    replay = browser(app_engine, idp)
    replay.cookies.set("aisw_session", stolen, domain="testserver", path="/api")
    assert replay.get("/api/v1/me").status_code == 401
    with tenant_connection(app_engine, "tenant-a") as conn:
        actions = {a for (a,) in conn.execute(text(
            "SELECT action FROM audit_events WHERE actor = 'carol'"))}  # fmt: skip
    assert {"auth.login", "auth.logout"} <= actions


def test_expired_or_forged_session_cookie_is_refused(app_engine: Engine, idp: MockIdp) -> None:
    c = browser(app_engine, idp)
    codec = CookieCodec(SECRET)
    claims = {"sid": uuid.uuid4().hex, "tid": "tenant-a", "sub": "bob", "csrf": "x",
              "roles": ["approver"]}  # fmt: skip
    c.cookies.set("aisw_session", codec.dumps("session", claims, expires_at=int(time.time()) - 1),
                  domain="testserver", path="/api")  # fmt: skip
    assert c.get("/api/v1/me").status_code == 401
    forged = CookieCodec("k" * 40).dumps("session", {**claims, "roles": ["project_admin"]},
                                         expires_at=int(time.time()) + 600)  # fmt: skip
    c.cookies.set("aisw_session", forged, domain="testserver", path="/api")
    assert c.get("/api/v1/me").status_code == 401


def test_callback_rejects_bad_state_replayed_code_and_nonce(
    app_engine: Engine, idp: MockIdp
) -> None:
    c = browser(app_engine, idp)
    r = c.get("/api/v1/auth/login")
    back = urlparse(idp_authorize(r.headers["location"], "alice"))
    q = {k: v[0] for k, v in parse_qs(back.query).items()}
    bad = c.get("/api/v1/auth/callback", params={**q, "state": "forged"})
    assert bad.headers["location"] == "/login?error=sso_failed"
    assert "aisw_session" not in c.cookies
    # no login cookie at all (a cross-site callback): refused
    fresh = browser(app_engine, idp)
    assert fresh.get("/api/v1/auth/callback", params=q).headers["location"].endswith("sso_failed")
    # a valid callback, then the same code again: the IdP refuses the replay
    c2 = browser(app_engine, idp)
    r = c2.get("/api/v1/auth/login")
    back = urlparse(idp_authorize(r.headers["location"], "alice"))
    assert c2.get(f"{back.path}?{back.query}").headers["location"] == "/"
    c3 = browser(app_engine, idp)
    c3.cookies.set("aisw_login", "x")
    assert c3.get(f"{back.path}?{back.query}").headers["location"].endswith("sso_failed")
    # an ID token carrying someone else's nonce
    idp.nonce_override = "attacker"
    try:
        assert sign_in(browser(app_engine, idp), "alice").headers["location"].endswith("sso_failed")
    finally:
        idp.nonce_override = None
    err = browser(app_engine, idp)
    err.get("/api/v1/auth/login")
    assert (
        err.get("/api/v1/auth/callback?error=access_denied")
        .headers["location"]
        .endswith("sso_failed")
    )


def test_open_redirects_are_neutralised(app_engine: Engine, idp: MockIdp) -> None:
    for target in ("//evil.example/x", "https://evil.example", "/\\evil.example"):
        assert sign_in(browser(app_engine, idp), "rita", target).headers["location"] == "/"


def test_bearer_tokens_enforce_rbac_and_tenancy(app_engine: Engine, idp: MockIdp) -> None:
    c = browser(app_engine, idp)
    alice = {"Authorization": f"Bearer {idp.mint('alice')}"}
    r = new_project(c, alice)  # bearer callers are not cookie callers: no CSRF needed
    assert r.status_code == 201
    pid = r.json()["project_id"]
    assert new_project(c, {"Authorization": f"Bearer {idp.mint('bob')}"}).status_code == 403
    dave = {"Authorization": f"Bearer {idp.mint('dave')}"}
    assert c.get(f"/api/v1/projects/{pid}", headers=dave).status_code == 404
    assert c.get(f"/api/v1/projects/{pid}", headers=alice).status_code == 200
    for bad in (idp.mint("alice", aud="other"), idp.mint("alice", alg="none"), "dev-alice"):
        assert c.get("/api/v1/me", headers={"Authorization": f"Bearer {bad}"}).status_code == 401
    assert c.get("/api/v1/me", headers={"Authorization": "Basic abc"}).status_code == 401


def test_dev_stub_and_sso_can_coexist_outside_prod(app_engine: Engine, idp: MockIdp) -> None:
    c = browser(app_engine, idp, dev_auth_stub=True)
    mode = c.get("/api/v1/auth/mode").json()
    assert mode["mode"] == "dev_stub" and mode["sso"] is True
    assert (
        c.get("/api/v1/me", headers={"Authorization": "Bearer dev-bob"}).json()["actor_id"] == "bob"
    )
    token = idp.mint("erin")
    assert (
        c.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"}).json()["actor_id"]
        == "erin"
    )


def test_unreachable_idp_fails_closed(app_engine: Engine) -> None:
    with MockIdp([REDIRECT]) as gone:
        settings = oidc_settings(gone)
    c = TestClient(create_app(settings, engine=app_engine), base_url="https://testserver",
                   follow_redirects=False)  # fmt: skip
    assert c.get("/api/v1/auth/login").status_code == 503
    assert c.get("/api/v1/me", headers={"Authorization": "Bearer a.b.c"}).status_code == 401
