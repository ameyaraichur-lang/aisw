"""PASSIVE_HTTP_SMOKE adapter against a LOCAL server only (127.0.0.1) with mocked DNS.

``loopback_only`` is active for every test here: any attempt to connect elsewhere raises, so these
tests cannot contact a public host even if the adapter were wrong.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from aisw.adapters.url_smoke import (
    HTTP2_ONLY,
    NOTICE,
    UrlSmokeAdapter,
    UrlSmokeParams,
    cert_metadata,
    url_asset_id,
)
from aisw.authz.net_guard import (
    CanonicalURL,
    VettedTarget,
    canonicalize_url,
    vet_redirect,
)
from aisw.gateway.registry import AdapterJob, AdapterOutput
from tests.http_server import (
    BODY_MARKER,
    H2_REFUSAL,
    Server,
    bundle,
    loopback_only,
    make_cert,
    start_raw_server,
    start_server,
)

pytestmark = pytest.mark.security

DNS = {"smoke.test": ["127.0.0.1"], "other.test": ["127.0.0.1"]}


def resolver(host: str, port: int) -> list[str]:
    if host not in DNS:
        raise OSError("NXDOMAIN")
    return DNS[host]


@pytest.fixture(autouse=True)
def attempts() -> Iterator[list[tuple[str, int]]]:
    with loopback_only() as a:
        yield a


@pytest.fixture()
def pki(tmp_path: Path) -> dict[str, Any]:
    good = make_cert(tmp_path, "good")
    untrusted = make_cert(tmp_path, "untrusted")
    expired = make_cert(
        tmp_path, "expired", cn="expired.smoke.test", not_before_days=-60, not_after_days=-10
    )
    wrongname = make_cert(tmp_path, "wrongname", cn="elsewhere.test", dns=("elsewhere.test",))
    return {"good": good, "untrusted": untrusted, "expired": expired, "wrongname": wrongname,
            "ca": bundle(tmp_path, "ca", good, expired, wrongname)}  # fmt: skip


@pytest.fixture()
def servers(pki: dict[str, Any]) -> Iterator[dict[str, Server]]:
    s = {
        "ok": start_server(pki["good"]), "untrusted": start_server(pki["untrusted"]),
        "expired": start_server(pki["expired"]), "wrongname": start_server(pki["wrongname"]),
        "http": start_server(None), "tls12": start_server(pki["good"], tls_max=ssl.TLSVersion.TLSv1_2),
    }  # fmt: skip
    yield s
    for x in s.values():
        x.stop()


def adapter(pki: dict[str, Any], inspection: Path | None = None) -> UrlSmokeAdapter:
    return UrlSmokeAdapter(ca_file=pki["ca"], inspection_ca_file=inspection)


def hook_for(*origins: str, ports: list[int]) -> Callable[[CanonicalURL, str, int], VettedTarget]:
    allowed = {canonicalize_url(o).origin for o in origins}

    def hook(cur: CanonicalURL, location: str, hop: int) -> VettedTarget:
        return vet_redirect(
            cur, location, hop=hop, in_scope=lambda u: u.origin in allowed, allowed_ports=ports,
            internal_ranges=["127.0.0.1/32"], resolver=resolver,
        )  # fmt: skip

    return hook


def run(
    pki: dict[str, Any], srv: Server, path: str = "/", params: dict[str, Any] | None = None,
    scope: tuple[str, ...] | None = None, hook: Any = "default", host: str = "smoke.test",
    pinned: tuple[str, ...] = ("127.0.0.1",), inspection: Path | None = None,
) -> AdapterOutput:  # fmt: skip
    url = f"{srv.scheme}://{host}:{srv.port}{path}"
    origins = scope if scope is not None else (f"{srv.scheme}://{host}:{srv.port}",)
    vet = hook_for(*origins, ports=[srv.port]) if hook == "default" else hook
    job = AdapterJob(
        tenant_id="t", project_id="p", run_id="r", task_id="k", profile="PASSIVE_HTTP_SMOKE",
        target_kind="url", target_selector=url, params=params or {}, pinned_addresses=pinned,
        request_budget=10, vet_redirect=vet,
    )  # fmt: skip
    return adapter(pki, inspection).execute(job)


# ---- the happy path ------------------------------------------------------------------------
def test_https_probe_records_dns_tls_http_and_never_the_body(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    srv = servers["ok"]
    out = run(pki, srv, "/ok")
    raw, hop = out.raw, out.raw["hops"][0]
    assert out.status == "SUCCEEDED" and out.warnings == [] and raw["request_count"] == 1
    assert [r["method"] for r in srv.requests] == ["GET"] and srv.paths() == ["/ok"]
    assert srv.requests[0]["host"] == f"smoke.test:{srv.port}"
    h = {k.lower(): v for k, v in srv.requests[0]["headers"].items()}
    assert (
        h["user-agent"].startswith("AISW-PassiveSmoke/")
        and "cookie" not in h
        and "authorization" not in h
    )
    assert (
        raw["dns"][0]["addresses"] == ["127.0.0.1"] and raw["dns"][0]["pinned_by"] == "tool-gateway"
    )
    tls = hop["tls"]
    assert tls["verified"] is True and tls["version"] in {"TLSv1.2", "TLSv1.3"} and tls["cipher"]
    cert = tls["certificate"]
    assert "CN=smoke.test" in cert["subject"] and {"smoke.test", "127.0.0.1"} <= set(cert["san"])
    assert (
        cert["days_remaining"] > 300
        and len(cert["sha256_fingerprint"]) == 64
        and cert["self_signed"]
    )
    assert cert["public_key"].startswith("EC-") and cert["signature_hash"] == "sha256"
    assert hop["response"]["status"] == 200 and hop["response"]["body_bytes_read"] == 0
    assert hop["response"]["headers"]["strict-transport-security"] == "max-age=31536000"
    assert hop["response"]["set_cookie_present"] is True  # presence only
    blob = json.dumps(raw)
    assert BODY_MARKER not in blob and "session=abc123" not in blob and "hunter2" not in blob
    assert "x-debug" not in blob.lower() and "ignore previous rules" not in blob  # not allowlisted
    assert raw["body_stored"] is False and raw["notice"] == NOTICE and raw["limitations"]
    assert raw["redirect_chain"] == [f"https://smoke.test:{srv.port}/ok"]


def test_head_method_and_plain_http(pki: dict[str, Any], servers: dict[str, Server]) -> None:
    out = run(pki, servers["ok"], "/ok", {"method": "HEAD"})
    assert out.status == "SUCCEEDED" and servers["ok"].requests[0]["method"] == "HEAD"
    plain = run(pki, servers["http"], "/ok")
    assert plain.status == "SUCCEEDED" and plain.raw["hops"][0]["tls"] is None
    assert servers["http"].requests[0]["host"] == f"smoke.test:{servers['http'].port}"


def test_negotiated_tls_version_is_reported(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    out = run(pki, servers["tls12"], "/ok")
    assert out.raw["hops"][0]["tls"]["version"] == "TLSv1.2"


def test_only_pinned_addresses_are_used_and_names_are_never_resolved(
    pki: dict[str, Any],
    servers: dict[str, Server],
    monkeypatch: pytest.MonkeyPatch,
    attempts: list[tuple[str, int]],
) -> None:
    real = socket.getaddrinfo

    def no_names(host: Any, *a: Any, **k: Any) -> Any:
        try:
            ipaddress.ip_address(str(host))
        except ValueError:
            raise AssertionError(f"adapter tried to resolve a name: {host}") from None
        return real(host, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", no_names)
    out = run(pki, servers["ok"], "/ok")
    assert out.status == "SUCCEEDED"
    assert {a[0] for a in attempts} == {
        "127.0.0.1"
    }  # SNI/Host say smoke.test; the socket never does


def test_without_pinned_addresses_nothing_is_attempted(
    pki: dict[str, Any], servers: dict[str, Server], attempts: list[tuple[str, int]]
) -> None:
    with pytest.raises(RuntimeError, match="no pinned addresses"):
        run(pki, servers["ok"], "/ok", pinned=())
    assert attempts == [] and servers["ok"].requests == []


def test_a_failed_pinned_address_never_falls_back_to_dns(
    pki: dict[str, Any], servers: dict[str, Server], attempts: list[tuple[str, int]]
) -> None:
    out = run(pki, servers["ok"], "/ok", pinned=("127.0.0.2",))  # nothing listens there
    assert out.status == "FAILED" and out.errors[0].startswith("CONNECT_FAILED")
    assert servers["ok"].requests == [] and {a[0] for a in attempts} == {"127.0.0.2"}


# ---- TLS failures: nothing is sent over an unverified channel ---------------------------------
@pytest.mark.parametrize(
    ("which", "needle"),
    [("untrusted", "self-signed"), ("expired", "expired"), ("wrongname", "mismatch")],
)
def test_tls_verification_failure_sends_no_http_request(
    pki: dict[str, Any], servers: dict[str, Server], which: str, needle: str
) -> None:
    srv = servers[which]
    out = run(pki, srv, "/ok")
    hop = out.raw["hops"][0]
    assert out.status == "PARTIAL" and out.warnings == ["TLS_VERIFY_FAILED"]
    assert srv.requests == []  # ZERO HTTP requests reached the server
    assert hop["tls"]["verified"] is False and needle in hop["tls"]["verify_error"].lower()
    assert (
        hop["request_sent"] is False and hop["response"] is None and out.raw["request_count"] == 0
    )
    assert hop["tls"]["certificate"][
        "sha256_fingerprint"
    ]  # metadata still described the cert we rejected


# ---- TLS inspection: the network re-signs TLS with the organisation's own CA ----------------------
def test_an_inspected_connection_is_reported_and_its_certificate_is_not_judged(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    # "untrusted" stands in for the inspection proxy: outside the trust store, named by the operator.
    srv = servers["untrusted"]
    out = run(pki, srv, "/ok", inspection=pki["untrusted"].cert_path)
    hop = out.raw["hops"][0]
    assert hop["tls"]["inspected"] is True and hop["tls"]["verified"] is False
    assert hop["error"] is None and hop["response"]["status"] == 200 and srv.paths() == ["/ok"]
    assert out.status == "SUCCEEDED" and len(out.warnings) == 1
    assert out.warnings[0].startswith(
        "TLS_INSPECTED:smoke.test: certificate issued by CN=smoke.test"
    )
    observed = {
        o.rule_id: o.value
        for o in adapter(pki).normalize(out, run_id="r", task_id="k").observations
    }
    assert not [
        r for r in observed if r.startswith("tls.")
    ]  # the proxy's certificate is not the target's
    assert observed["http.response_received"] is True and observed["http.hsts_present"] is True


@pytest.mark.parametrize("which", ["untrusted", "wrongname"])
def test_inspection_ca_does_not_excuse_other_tls_failures(
    pki: dict[str, Any], servers: dict[str, Server], which: str
) -> None:
    other_ca = pki["expired"].cert_path if which == "untrusted" else pki["wrongname"].cert_path
    srv = servers[which]  # untrusted: issued by another CA; wrongname: right CA, wrong hostname
    out = run(pki, srv, "/ok", inspection=other_ca)
    hop = out.raw["hops"][0]
    assert out.warnings == ["TLS_VERIFY_FAILED"] and srv.requests == []
    assert "inspected" not in hop["tls"] and hop["request_sent"] is False


def test_expired_certificate_metadata_is_negative(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    out = run(pki, servers["expired"], "/ok")
    assert out.raw["hops"][0]["tls"]["certificate"]["days_remaining"] < 0


# ---- network-level failures ------------------------------------------------------------------
def test_connection_refused_is_a_clean_failure(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    dead = start_server(None)
    dead.stop()
    out = run(pki, dead, "/ok")
    assert (
        out.status == "FAILED"
        and out.errors[0].startswith("CONNECT_FAILED")
        and out.raw["request_count"] == 0
    )


def test_read_timeout_is_partial_not_a_hang(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    out = run(pki, servers["ok"], "/slow", {"timeout_seconds": 1})
    assert out.status == "PARTIAL" and out.warnings == ["READ_TIMEOUT"]
    assert (
        out.raw["hops"][0]["tls"]["verified"] is True and out.raw["hops"][0]["request_sent"] is True
    )


def test_oversized_response_headers_are_a_protocol_error(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    out = run(pki, servers["ok"], "/huge-header")
    assert out.status == "PARTIAL" and out.warnings[0].startswith("HTTP_PROTOCOL_ERROR")
    assert "AAAA" not in json.dumps(out.raw)


def test_untrusted_header_values_are_bounded_and_kept_as_data(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    out = run(pki, servers["ok"], "/long-header")
    server_header = out.raw["hops"][0]["response"]["headers"]["server"]
    assert len(server_header) == 512 and set(server_header) == {"S"}
    hostile = run(pki, servers["ok"], "/ok")  # default Server header
    assert hostile.raw["hops"][0]["response"]["headers"]["server"] == "test-server/1.0"
    assert out.raw["hops"][0]["response"]["header_count"] >= 5


# ---- redirects ---------------------------------------------------------------------------------
def test_same_origin_redirect_is_followed_and_chained(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    srv = servers["ok"]
    out = run(pki, srv, "/redir-same")
    assert (
        out.status == "SUCCEEDED"
        and out.raw["request_count"] == 2
        and srv.paths() == ["/redir-same", "/ok"]
    )
    assert out.raw["redirect_chain"] == [
        f"https://smoke.test:{srv.port}/redir-same",
        f"https://smoke.test:{srv.port}/ok",
    ]


def test_cross_host_redirect_only_when_that_host_is_in_scope(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    srv = servers["ok"]
    blocked = run(pki, srv, "/redir-abs-other-host")
    assert blocked.status == "PARTIAL" and blocked.warnings == [
        "REDIRECT_BLOCKED:REDIRECT_OUT_OF_SCOPE"
    ]
    assert srv.paths() == ["/redir-abs-other-host"]  # never followed
    srv.requests.clear()
    scope = (f"https://smoke.test:{srv.port}", f"https://other.test:{srv.port}")
    allowed = run(pki, srv, "/redir-abs-other-host", scope=scope)
    assert allowed.status == "SUCCEEDED" and srv.requests[-1]["host"] == f"other.test:{srv.port}"


@pytest.mark.parametrize(
    ("path", "code"),
    [
        ("/redir-private", "REDIRECT_OUT_OF_SCOPE"),
        ("/redir-metadata", "REDIRECT_OUT_OF_SCOPE"),
        ("/redir-other-port", "REDIRECT_OUT_OF_SCOPE"),
        ("/redir-downgrade", "REDIRECT_OUT_OF_SCOPE"),
        ("/redir-file", "UNSUPPORTED_SCHEME"),
        ("/redir-userinfo", "USERINFO_NOT_ALLOWED"),
        ("/redir-ip-decimal", "AMBIGUOUS_IP_FORMAT"),
    ],
)
def test_hostile_redirects_are_blocked_without_any_connection(
    pki: dict[str, Any],
    servers: dict[str, Server],
    attempts: list[tuple[str, int]],
    path: str,
    code: str,
) -> None:
    srv = servers["ok"]
    out = run(pki, srv, path)
    assert out.status == "PARTIAL" and out.warnings == [f"REDIRECT_BLOCKED:{code}"]
    assert srv.paths() == [path] and out.raw["request_count"] == 1
    assert {a for a in attempts} == {
        ("127.0.0.1", srv.port)
    }  # no attempt toward 10.0.0.5, 169.254.x or file
    assert out.raw["hops"][0]["redirect_blocked"] == code


def test_redirect_budget_loop_and_missing_location(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    srv = servers["ok"]
    loop = run(pki, srv, "/redir-loop", {"max_redirects": 3})
    assert (
        loop.status == "PARTIAL"
        and loop.warnings == ["TOO_MANY_REDIRECTS"]
        and loop.raw["request_count"] == 4
    )
    srv.requests.clear()
    none = run(pki, srv, "/redir-same", {"max_redirects": 0})
    assert none.warnings == ["TOO_MANY_REDIRECTS"] and srv.paths() == ["/redir-same"]
    srv.requests.clear()
    chain = run(pki, srv, "/redir-chain/2", {"max_redirects": 3})
    assert chain.status == "SUCCEEDED" and chain.raw["request_count"] == 4
    srv.requests.clear()
    noloc = run(pki, srv, "/redir-nolocation")
    assert noloc.status == "PARTIAL" and noloc.warnings == ["REDIRECT_WITHOUT_LOCATION"]


def test_without_a_vetting_hook_redirects_are_never_followed(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    srv = servers["ok"]
    out = run(pki, srv, "/redir-same", hook=None)
    assert out.warnings == ["REDIRECT_BLOCKED:REDIRECT_VETTING_UNAVAILABLE"] and srv.paths() == [
        "/redir-same"
    ]


def test_a_redirect_into_a_name_that_resolves_to_a_blocked_address_is_refused(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    srv = servers["ok"]
    DNS["rebind.test"] = ["10.0.0.9"]
    try:
        scope = (f"https://smoke.test:{srv.port}", f"https://rebind.test:{srv.port}")
        # point the hostile redirect at the in-scope-but-private-resolving host
        srv.root = "/redir-abs-other-host"
        hook = hook_for(*scope, ports=[srv.port])

        def tweak(cur: CanonicalURL, loc: str, hop: int) -> VettedTarget:
            return hook(cur, loc.replace("other.test", "rebind.test"), hop)

        out = run(pki, srv, "/", scope=scope, hook=tweak)
        assert out.warnings == ["REDIRECT_BLOCKED:BLOCKED_ADDRESS_PRIVATE"] and srv.paths() == ["/"]
    finally:
        DNS.pop("rebind.test", None)


# ---- parameters, budget, identity --------------------------------------------------------------
@pytest.mark.parametrize(
    "bad",
    [
        {"method": "POST"},
        {"method": "get"},
        {"max_redirects": 6},
        {"max_redirects": -1},
        {"timeout_seconds": 0},
        {"timeout_seconds": 99},
        {"body": "x"},
        {"headers": {"X": "y"}},
        {"url": "http://evil"},
    ],
)
def test_parameters_cannot_widen_the_probe(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        UrlSmokeParams.model_validate(bad)


def test_request_budget_estimate_and_capability(pki: dict[str, Any]) -> None:
    a = adapter(pki)
    assert a.estimate_requests({}) == 4 and a.estimate_requests({"max_redirects": 0}) == 1
    cap = a.capability
    assert cap.target_kinds == {"url"} and not cap.mutates_infrastructure
    assert [p.value for p in cap.profiles.values()] == ["READ_ONLY"] and set(cap.profiles) == {
        "PASSIVE_HTTP_SMOKE"
    }


def test_asset_identity_is_per_origin() -> None:
    a = url_asset_id(canonicalize_url("https://Example.com/a?x=1"))
    assert a == url_asset_id(canonicalize_url("https://example.com:443/b")) and a.startswith("url-")
    assert (
        a
        != url_asset_id(canonicalize_url("https://example.com:8443/a"))
        != url_asset_id(canonicalize_url("http://example.com/a"))
    )


def test_cert_metadata_describes_a_certificate(pki: dict[str, Any]) -> None:
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    der = x509.load_pem_x509_certificate(pki["good"].pem).public_bytes(serialization.Encoding.DER)
    m = cert_metadata(der, dt.datetime.now(dt.UTC))
    assert 360 <= m["days_remaining"] <= 365 and m["issuer"] == m["subject"]


# ---- normalization ------------------------------------------------------------------------------
def norm(pki: dict[str, Any], out: AdapterOutput) -> tuple[Any, dict[str, Any]]:
    b = adapter(pki).normalize(out, run_id="r", task_id="t")
    return b, {o.rule_id: o.value for o in b.observations}


def test_normalization_of_a_healthy_target(pki: dict[str, Any], servers: dict[str, Server]) -> None:
    b, o = norm(pki, run(pki, servers["ok"], "/ok"))
    assert (
        b.assets[0].status == "SCANNED"
        and b.assets[0].asset_type == "url"
        and b.assets[0].attrs == {"scheme": "https"}
    )
    assert (
        o["tls.verified"] is True
        and o["tls.protocol"] in {"TLSv1.2", "TLSv1.3"}
        and o["tls.cert_days_remaining"] > 300
    )
    assert (
        o["http.response_received"] is True
        and o["http.hsts_present"] is True
        and o["http.x_content_type_options"] == "nosniff"
    )
    assert "http.redirects_within_scope" not in o  # no redirect happened: nothing to claim


def test_normalization_reports_missing_headers_and_blocked_redirects(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    _, o = norm(pki, run(pki, servers["ok"], "/bare"))
    assert o["http.hsts_present"] is False and o["http.x_content_type_options"] == "absent"
    _, o2 = norm(pki, run(pki, servers["ok"], "/redir-private"))
    assert o2["http.redirects_within_scope"] is False
    _, o3 = norm(pki, run(pki, servers["ok"], "/redir-same"))
    assert o3["http.redirects_within_scope"] is True


def test_normalization_of_tls_failure_and_unreachable_targets(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    b, o = norm(pki, run(pki, servers["untrusted"], "/ok"))
    assert (
        o["tls.verified"] is False
        and o["tls.cert_days_remaining"] > 300
        and "http.response_received" not in o
    )
    dead = start_server(None)
    dead.stop()
    b2, o2 = norm(pki, run(pki, dead, "/ok"))
    assert b2.assets[0].status == "UNREACHABLE" and o2 == {}  # unknown, never "passing"


def test_non_https_targets_get_no_tls_observations(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    _, o = norm(pki, run(pki, servers["http"], "/ok"))
    assert (
        not any(k.startswith("tls.") or k == "http.hsts_present" for k in o)
        and o["http.response_received"] is True
    )


# ---- network edge cases: IPv6-only, HTTP/2-only, proxies (loopback only) -----------------------
def test_an_ipv6_only_target_is_probed_over_its_pinned_ipv6_address(
    pki: dict[str, Any], attempts: list[tuple[str, int]]
) -> None:
    srv = start_server(pki["good"], bind="::1")
    try:
        out = run(pki, srv, "/ok", pinned=("::1",))
        hop = out.raw["hops"][0]
        assert out.status == "SUCCEEDED" and hop["connect"] == {"ip": "::1", "port": srv.port}
        assert (
            hop["tls"]["verified"] is True and srv.requests[0]["host"] == f"smoke.test:{srv.port}"
        )

        out2 = run(pki, srv, "/ok", pinned=("127.0.0.1", "::1"))  # nothing listens on IPv4
        assert out2.status == "SUCCEEDED" and out2.raw["hops"][0]["connect"]["ip"] == "::1"
        assert ("127.0.0.1", srv.port) in attempts and ("::1", srv.port) in attempts
    finally:
        srv.stop()


def test_an_ipv6_literal_url_sends_a_bracketed_host_header(pki: dict[str, Any]) -> None:
    srv = start_server(None, bind="::1")
    try:
        out = run(pki, srv, "/ok", host="[::1]", pinned=("::1",))
        assert out.status == "SUCCEEDED" and srv.requests[0]["host"] == f"[::1]:{srv.port}"
        assert out.raw["target"] == f"http://[::1]:{srv.port}/ok"
    finally:
        srv.stop()


def _h2_only(pki: dict[str, Any], tls: bool) -> tuple[AdapterOutput, Any]:
    srv = start_raw_server(H2_REFUSAL, pki["good"] if tls else None, alpn=["h2"])
    try:
        scheme = "https" if tls else "http"
        url = f"{scheme}://smoke.test:{srv.port}/ok"
        job = AdapterJob(
            tenant_id="t", project_id="p", run_id="r", task_id="k", profile="PASSIVE_HTTP_SMOKE",
            target_kind="url", target_selector=url, params={}, pinned_addresses=("127.0.0.1",),
            request_budget=10, vet_redirect=hook_for(f"{scheme}://smoke.test:{srv.port}", ports=[srv.port]),
        )  # fmt: skip
        return adapter(pki).execute(job), srv
    finally:
        srv.stop()


@pytest.mark.parametrize("tls", [True, False])
def test_an_http2_only_server_is_reported_as_unsupported_not_as_silent(
    pki: dict[str, Any], tls: bool
) -> None:
    out, srv = _h2_only(pki, tls)
    hop = out.raw["hops"][0]
    assert out.status == "PARTIAL" and out.warnings == [HTTP2_ONLY] and hop["error"] == HTTP2_ONLY
    assert srv.received and srv.received[0].startswith(b"GET /ok HTTP/1.1\r\n")  # one request
    if tls:
        assert srv.alpn == [None] and hop["tls"]["verified"] is True and hop["tls"]["alpn"] is None
    _, o = norm(pki, out)
    assert "http.response_received" not in o  # the probe could not ask, so nothing is claimed
    assert (o.get("tls.verified") is True) is tls


def test_a_server_that_refuses_http1_during_the_handshake_is_unsupported(
    pki: dict[str, Any], servers: dict[str, Server], monkeypatch: pytest.MonkeyPatch
) -> None:
    class Refusing(ssl.SSLContext):
        def wrap_socket(self, *a: Any, **kw: Any) -> ssl.SSLSocket:
            raise ssl.SSLError(
                1, "[SSL: TLSV1_ALERT_NO_APPLICATION_PROTOCOL] no application protocol"
            )

    monkeypatch.setattr(
        UrlSmokeAdapter, "_context", lambda self, verify: Refusing(ssl.PROTOCOL_TLS_CLIENT)
    )
    out = run(pki, servers["ok"], "/ok")
    assert out.status == "PARTIAL" and out.raw["hops"][0]["error"] == HTTP2_ONLY
    assert out.raw["request_count"] == 0 and servers["ok"].requests == []


def test_the_negotiated_alpn_protocol_is_recorded(
    pki: dict[str, Any], servers: dict[str, Server]
) -> None:
    hop = run(pki, servers["ok"], "/ok").raw["hops"][0]
    assert hop["tls"]["alpn"] is None  # the test server does not negotiate ALPN; offered http/1.1


@pytest.mark.parametrize("var", ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "ALL_PROXY"])
def test_proxy_settings_in_the_environment_are_never_used(
    pki: dict[str, Any], servers: dict[str, Server], monkeypatch: pytest.MonkeyPatch, var: str
) -> None:
    proxy = start_raw_server(b"HTTP/1.1 200 Connection established\r\n\r\n")
    try:
        monkeypatch.setenv(var, f"http://127.0.0.1:{proxy.port}")
        for srv in (servers["ok"], servers["http"]):
            out = run(pki, srv, "/ok")
            assert out.status == "SUCCEEDED" and out.raw["hops"][0]["connect"]["port"] == srv.port
        assert proxy.received == []
    finally:
        proxy.stop()
