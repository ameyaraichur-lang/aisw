"""OIDC token verification, settings validation and the signed-cookie codec (ADR-026)."""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest

from aisw.api.auth import safe_return_to
from aisw.core.config import Settings
from aisw.core.oidc import OidcError, OidcProvider, _default_fetch
from aisw.core.rbac import Role
from aisw.core.session import CookieCodec, SessionError
from tests.oidc_idp import MockIdp

REDIRECT = "https://testserver/api/v1/auth/callback"
SECRET = "s" * 40  # aisw:allow-secret - test-only cookie key


def oidc_settings(idp: MockIdp, **kw: Any) -> Settings:
    base: dict[str, Any] = {
        "env": "test", "oidc_issuer": idp.issuer, "oidc_client_id": idp.client_id,
        "oidc_client_secret": idp.client_secret, "oidc_redirect_uri": REDIRECT,
        "session_secret": SECRET,
    }  # fmt: skip
    return Settings(**{**base, **kw})


@pytest.fixture(scope="module")
def idp() -> Iterator[MockIdp]:
    with MockIdp([REDIRECT]) as i:
        yield i


@pytest.fixture()
def provider(idp: MockIdp) -> OidcProvider:
    return OidcProvider(oidc_settings(idp))


# ---- token verification -----------------------------------------------------------------------
def test_valid_token_maps_tenant_and_roles(idp: MockIdp, provider: OidcProvider) -> None:
    claims = provider.verify(idp.mint("alice", nonce="n1"), audience=idp.client_id, nonce="n1")
    actor = provider.actor(claims)
    assert (actor.tenant_id, actor.actor_id) == ("tenant-a", "alice")
    assert actor.roles == {Role.PROJECT_ADMIN, Role.ASSESSMENT_OPERATOR}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ttl": -3600},  # expired beyond the 60 s leeway
        {"aud": "someone-else"},
        {"iss": "http://127.0.0.1:1"},
        {"alg": "none"},
        {"alg": "HS256"},  # HMAC with a guessable key: algorithm confusion must not work
        {"kid": "not-published"},
        {"drop": ("exp",)},
        {"drop": ("sub",)},
        {"drop": ("iat",)},
        {"claims": {"iat": "yesterday"}},
    ],
)
def test_bad_tokens_are_rejected(idp: MockIdp, provider: OidcProvider, kwargs: Any) -> None:
    with pytest.raises(OidcError):
        provider.verify(idp.mint("alice", **kwargs), audience=idp.client_id)


def test_tampered_and_malformed_tokens(idp: MockIdp, provider: OidcProvider) -> None:
    head, body, sig = idp.mint("bob").split(".")
    forged = json.loads(_unb64(body))
    forged["roles"] = ["project_admin"]
    tampered = ".".join([head, _b64(json.dumps(forged).encode()), sig])
    for token in (tampered, "not-a-jwt", "", "a.b.c"):
        with pytest.raises(OidcError):
            provider.verify(token, audience=idp.client_id)


def test_nonce_and_authorized_party(idp: MockIdp, provider: OidcProvider) -> None:
    with pytest.raises(OidcError, match="nonce"):
        provider.verify(idp.mint(nonce="a"), audience=idp.client_id, nonce="b")
    with pytest.raises(OidcError, match="nonce"):
        provider.verify(idp.mint(), audience=idp.client_id, nonce="b")
    multi = idp.mint(aud=[idp.client_id, "other"])
    with pytest.raises(OidcError, match="another party"):
        provider.verify(multi, audience=idp.client_id)
    ok = idp.mint(aud=[idp.client_id, "other"], claims={"azp": idp.client_id})
    assert provider.verify(ok, audience=idp.client_id)["sub"] == "alice"


def test_key_rotation_refetches_once_then_throttles(idp: MockIdp) -> None:
    clock = [1000.0]
    p = OidcProvider(oidc_settings(idp), clock=lambda: clock[0])
    p.verify(idp.mint(), audience=idp.client_id)
    before = idp.jwks_requests
    old = idp.active_kid
    idp.rotate()
    clock[0] += 60  # past the refresh throttle
    assert p.verify(idp.mint(), audience=idp.client_id)["sub"] == "alice"
    assert idp.jwks_requests == before + 1
    assert p.verify(idp.mint(kid=old), audience=idp.client_id)  # old key still published
    for _ in range(5):  # unknown kids cannot force a fetch per request
        with pytest.raises(OidcError):
            p.verify(idp.mint(kid="bogus"), audience=idp.client_id)
    assert idp.jwks_requests == before + 1
    idp.active_kid = old


def test_tenant_and_roles_come_only_from_verified_claims(idp: MockIdp) -> None:
    p = OidcProvider(oidc_settings(idp, oidc_role_map='{"sec-admins": "project_admin"}'))
    actor = p.actor(p.verify(idp.mint(claims={"roles": ["sec-admins", "approver", 7]}),
                             audience=idp.client_id))  # fmt: skip
    assert actor.roles == {Role.PROJECT_ADMIN}  # unmapped names are dropped, not trusted
    for bad in ("", "Tenant A", "../x", None, ["tenant-a"]):
        with pytest.raises(OidcError, match="tenant"):
            p.actor({"sub": "x", "tenant": bad})
    space = OidcProvider(oidc_settings(idp, oidc_roles_claim="scp"))
    assert space.actor({"sub": "x", "tenant": "t1", "scp": "reviewer auditor"}).roles == {
        Role.REVIEWER, Role.AUDITOR,
    }  # fmt: skip


def test_discovery_must_name_the_configured_issuer(idp: MockIdp) -> None:
    good = _default_fetch

    def lying(req: urllib.request.Request) -> bytes:
        raw = good(req)
        if req.full_url.endswith("openid-configuration"):
            doc = json.loads(raw)
            return json.dumps({**doc, "issuer": "https://evil.example"}).encode()
        return raw

    with pytest.raises(OidcError, match="issuer"):
        OidcProvider(oidc_settings(idp), fetch=lying).metadata()

    def unsafe(req: urllib.request.Request) -> bytes:
        doc = json.loads(good(req))
        return json.dumps({**doc, "jwks_uri": "http://203.0.113.9/jwks"}).encode()

    with pytest.raises(OidcError, match="jwks_uri"):
        OidcProvider(oidc_settings(idp), fetch=unsafe).metadata()


def test_transport_refuses_redirects_and_oversize(idp: MockIdp) -> None:
    with pytest.raises(OidcError):
        _default_fetch(urllib.request.Request(f"{idp.issuer}/nowhere"))  # noqa: S310
    with pytest.raises(OidcError, match="not JSON"):
        OidcProvider(oidc_settings(idp), fetch=lambda _: b"x" * 10).metadata()


def test_authorize_url_uses_pkce_s256(provider: OidcProvider) -> None:
    url = provider.authorize_url(state="st", nonce="nn", verifier="v" * 64)
    assert "code_challenge_method=S256" in url and "code_challenge=" in url
    assert "v" * 64 not in url  # the verifier never leaves the server


# ---- settings ---------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({"oidc_client_id": None}, "oidc_client_id"),
        ({"session_secret": "short"}, "session_secret"),
        ({"session_secret": None}, "session_secret"),
        ({"oidc_issuer": "http://idp.example.com"}, "https"),
        ({"oidc_issuer": "https://u:p@idp.example.com"}, "credentials"),
        ({"oidc_redirect_uri": "https://testserver/elsewhere"}, "callback"),
        ({"oidc_role_map": "[1]"}, "role"),
        ({"oidc_role_map": '{"x": "god"}'}, "role"),
        ({"oidc_role_map": "{nope"}, "JSON"),
    ],
)
def test_settings_refuse_unsafe_oidc(idp: MockIdp, kw: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        oidc_settings(idp, **kw)


def test_loopback_http_issuer_is_refused_in_prod(idp: MockIdp) -> None:
    with pytest.raises(ValueError, match="https"):
        oidc_settings(idp, env="prod")


def test_secrets_never_render(idp: MockIdp) -> None:
    s = oidc_settings(idp)
    assert idp.client_secret not in repr(s) and SECRET not in repr(s)


# ---- signed cookies ---------------------------------------------------------------------------
def test_cookie_codec_roundtrip_tamper_purpose_and_expiry() -> None:
    c = CookieCodec(SECRET)
    v = c.dumps("session", {"sid": "abc", "roles": ["reviewer"]}, expires_at=2000)
    assert c.loads("session", v, now=1000)["sid"] == "abc"
    with pytest.raises(SessionError, match="signature"):
        c.loads("login", v, now=1000)  # a cookie for one purpose is useless for another
    with pytest.raises(SessionError, match="expired"):
        c.loads("session", v, now=2000)
    body, sig = v.split(".")
    forged = _b64(json.dumps({"sid": "abc", "roles": ["project_admin"], "exp": 2000}).encode())
    for bad in (f"{forged}.{sig}", f"{body}.{sig[:-2]}", "", "x", "a.b.c", None):
        with pytest.raises(SessionError):
            c.loads("session", bad, now=1000)
    with pytest.raises(SessionError, match="signature"):
        CookieCodec("t" * 40).loads("session", v, now=1000)
    with pytest.raises(ValueError):
        CookieCodec("short")


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("/runs/abc?tab=report", "/runs/abc?tab=report"),
        ("/", "/"),
        (None, "/"),
        ("//evil.example", "/"),
        ("/\\evil.example", "/"),
        ("https://evil.example", "/"),
        ("javascript:alert(1)", "/"),
        ("/a\r\nset-cookie: x", "/"),
        ("/" + "a" * 600, "/"),
    ],
)
def test_return_to_is_same_origin_only(given: str | None, expected: str) -> None:
    assert safe_return_to(given) == expected


def _b64(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
