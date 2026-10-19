"""Egress allow-list derivation, firewall rendering, host probes and scan-zone enforcement (ADR-028)."""

from __future__ import annotations

import importlib.util
import json
import socket
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from aisw.authz.net_guard import (
    NetGuardError,
    canonicalize_url,
    parse_egress_zones,
    resolve_and_vet,
)
from aisw.core import egress
from aisw.core.config import Settings
from aisw.core.oidc import OidcError, OidcProvider, _default_fetch
from tests.oidc_idp import MockIdp
from tests.unit.test_oidc import REDIRECT, oidc_settings

REPO = Path(__file__).resolve().parents[3]
DB = "postgresql+psycopg://aisw_app:x@db.internal:5433/aisw"  # aisw:allow-secret - placeholder


def full_settings(**kw: Any) -> Settings:
    base: dict[str, Any] = {
        "env": "test", "database_url": DB,
        "worker_database_url": "postgresql+psycopg://aisw_worker:x@db.internal/aisw",  # aisw:allow-secret
        "egress_dns_servers": "10.0.0.2", "egress_scan_cidrs": "10.20.0.0/16,2001:db8:20::/48",
        "egress_scan_ports": "443,8443", "ai_enabled": True, "model_provider": "astra",
        "model_id": "gpt-x", "model_license": "proprietary",
        "astra_endpoint": "https://warden-dev.openai.azure.com", "astra_api_key": "k" * 20,
        "astra_data_approval_ref": "SYNTHETIC-ONLY",
    }  # fmt: skip
    return Settings(**{**base, **kw})


def by_purpose(dests: list[egress.Destination]) -> dict[str, list[egress.Destination]]:
    out: dict[str, list[egress.Destination]] = {}
    for d in dests:
        out.setdefault(d.purpose, []).append(d)
    return out


def test_destinations_cover_every_configured_endpoint_by_role() -> None:
    d = by_purpose(egress.destinations(full_settings()))
    assert [(x.host, x.ports, x.roles) for x in d["database"]] == [
        ("db.internal", (5433,), ("api",)), ("db.internal", (5432,), ("worker",)),
    ]  # fmt: skip
    assert d["astra"][0].host == "warden-dev.openai.azure.com" and d["astra"][0].roles == (
        "worker",
    )
    assert {x.proto for x in d["dns"]} == {"udp", "tcp"}
    assert [x.host for x in d["scan-zone"]] == ["10.20.0.0/16", "2001:db8:20::/48"]
    assert d["scan-zone"][0].ports == (443, 8443) and d["scan-zone"][0].roles == ("worker",)


def test_proxy_replaces_the_model_endpoint_and_loopback_or_sockets_need_nothing() -> None:
    s = full_settings(astra_proxy="http://proxy.internal:3128",
                      database_url="postgresql+psycopg://u@/aisw?host=/tmp/pg",  # aisw:allow-secret
                      worker_database_url=None, egress_scan_cidrs=None)  # fmt: skip
    d = by_purpose(egress.destinations(s))
    assert "astra" not in d and d["astra-proxy"][0].host == "proxy.internal"
    assert "database" not in d and "scan-zone" not in d
    local = Settings(
        env="test", database_url="postgresql+psycopg://u@127.0.0.1/aisw"
    )  # aisw:allow-secret
    assert egress.destinations(local) == []


def test_idp_and_kms_destinations(tmp_path: Path) -> None:
    tok = tmp_path / "t"
    tok.write_text("t")
    with MockIdp([REDIRECT]) as idp:
        s = oidc_settings(idp, egress_allowed_hosts="keys.idp.example,jwks.example:8443")
    d = by_purpose(egress.destinations(s))
    assert "idp" not in d  # the mock IdP is on loopback
    assert [(x.host, x.ports) for x in d["idp-extra"]] == [("keys.idp.example", (443,)),
                                                          ("jwks.example", (8443,))]  # fmt: skip
    s = Settings(env="test", signing_backend="transit", kms_addr="https://kms.internal:8200",
                 kms_key="k", kms_token_file=tok, oidc_issuer=None)  # fmt: skip
    kms = by_purpose(egress.destinations(s))["kms"][0]
    assert (kms.host, kms.ports, kms.roles) == ("kms.internal", (8200,), ("api", "worker"))


def resolver(host: str, port: int) -> list[str]:
    return {"db.internal": ["10.1.2.3"], "warden-dev.openai.azure.com": ["20.1.2.3", "2603:1::5"]}[
        host
    ]


def test_nftables_rules_filter_only_the_service_user_and_fail_closed() -> None:
    dests = egress.destinations(full_settings())
    rules = egress.render(dests, "nftables", role="worker", user="aisw")
    assert 'meta skuid != "aisw" accept' in rules
    assert "ip daddr 10.20.0.0/16 tcp dport { 443, 8443 } accept  # scan-zone" in rules
    assert "ip6 daddr 2001:db8:20::/48 tcp dport { 443, 8443 } accept" in rules
    assert "ip daddr 10.0.0.2/32 udp dport { 53 } accept  # dns" in rules
    assert "# UNRESOLVED warden-dev.openai.azure.com:443 (astra)" in rules  # not resolved: left out
    assert rules.rstrip().endswith('counter log prefix "aisw-egress-deny " drop\n  }\n}'.rstrip())
    resolved = egress.render(dests, "nftables", role="worker", resolver=resolver)
    assert "ip daddr 20.1.2.3/32 tcp dport { 443 } accept  # astra" in resolved
    assert "ip6 daddr 2603:1::5/128 tcp dport { 443 } accept  # astra" in resolved
    api = egress.render(dests, "nftables", role="api", resolver=resolver)
    assert "astra" not in api.split("UNRESOLVED")[0] and "scan-zone" not in api


def test_iptables_rules_split_by_family() -> None:
    dests = egress.destinations(full_settings())
    v4 = egress.render(dests, "iptables", role="worker", resolver=resolver)
    v6 = egress.render(dests, "ip6tables", role="worker", resolver=resolver)
    assert "-A OUTPUT -m owner --uid-owner aisw -j AISW_EGRESS" in v4
    assert "-d 10.20.0.0/16 -p tcp -m multiport --dports 443,8443" in v4 and "2001:db8" not in v4
    assert "-d 2001:db8:20::/48" in v6 and "10.20.0.0" not in v6
    assert v4.rstrip().endswith("-A AISW_EGRESS -j DROP\nCOMMIT")
    with pytest.raises(ValueError, match="account name"):
        egress.render(dests, "iptables", role="worker", user="aisw; rm -rf /")


@pytest.fixture()
def listener() -> Iterator[int]:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    yield s.getsockname()[1]
    s.close()


def closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def test_probe_detects_a_missing_firewall(listener: int) -> None:
    results = egress.probe([("127.0.0.1", listener)], [("127.0.0.1", listener), ("127.0.0.1", closed_port())],
                           connect=socket.create_connection, timeout=1)  # fmt: skip
    assert [(r.expect, r.observed, r.passed) for r in results] == [
        ("allow", "connected", True),
        ("deny", "connected", False),  # reachable although it should be denied: no firewall
        ("deny", "refused", True),
    ]


# ---- scan zones (app level) --------------------------------------------------------------------
def test_scan_zones_restrict_resolved_addresses() -> None:
    url = canonicalize_url("https://app.internal")
    ok = resolve_and_vet(url, allowed_ports=[443], internal_ranges=["10.20.0.0/16"],
                         resolver=lambda h, p: ["10.20.1.5"], egress_zones=["10.20.0.0/16"])  # fmt: skip
    assert ok.addresses == ("10.20.1.5",)
    with pytest.raises(NetGuardError) as exc:
        resolve_and_vet(canonicalize_url("https://example.com"), allowed_ports=[443],
                        resolver=lambda h, p: ["93.184.216.34"], egress_zones=["10.20.0.0/16"])  # fmt: skip
    assert exc.value.code == "BLOCKED_ADDRESS_OUTSIDE_EGRESS_ZONE"


@pytest.mark.parametrize(
    ("zone", "code"),
    [("0.0.0.0/0", "EGRESS_ZONE_TOO_BROAD"), ("169.254.0.0/16", "EGRESS_ZONE_COVERS_METADATA"),
     ("10.0.0.1/8", "INVALID_EGRESS_ZONE"), ("::/8", "EGRESS_ZONE_TOO_BROAD"), ("nope", "INVALID_EGRESS_ZONE")],
)  # fmt: skip
def test_unsafe_scan_zones_are_refused(zone: str, code: str) -> None:
    with pytest.raises(NetGuardError) as exc:
        parse_egress_zones([zone])
    assert exc.value.code == code
    with pytest.raises(ValueError, match="egress_scan_cidrs"):
        Settings(env="test", egress_scan_cidrs=zone)


@pytest.mark.parametrize(
    "kw",
    [{"egress_scan_ports": "0"}, {"egress_allowed_hosts": "bad host"},
     {"egress_allowed_hosts": "h.example:http"}, {"egress_dns_servers": "dns.example"}],
)  # fmt: skip
def test_egress_settings_are_validated(kw: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        Settings(env="test", **kw)


def test_idp_endpoints_on_other_hosts_need_an_explicit_allowance() -> None:
    with MockIdp([REDIRECT]) as idp:

        def moved(req: urllib.request.Request) -> bytes:
            raw = _default_fetch(req)
            if req.full_url.endswith("openid-configuration"):
                return json.dumps(
                    {**json.loads(raw), "jwks_uri": "https://keys.idp.example/jwks"}
                ).encode()
            return raw

        with pytest.raises(OidcError, match="egress allow-list"):
            OidcProvider(oidc_settings(idp), fetch=moved).metadata()
        allowed = OidcProvider(
            oidc_settings(idp, egress_allowed_hosts="keys.idp.example"), fetch=moved
        )
        assert allowed.metadata()["jwks_uri"] == "https://keys.idp.example/jwks"


# ---- CLI and committed examples ------------------------------------------------------------------
def load_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "egress_check", REPO / "tools" / "egress_check.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_cli_plan_render_verify(
    tmp_path: Path, listener: int, capsys: pytest.CaptureFixture[str]
) -> None:
    tool = load_tool()
    env = tmp_path / "e.env"
    env.write_text(
        "AISW_ENV=test\nAISW_EGRESS_SCAN_CIDRS=10.20.0.0/16\nAISW_EGRESS_DNS_SERVERS=10.0.0.2\n"
    )
    assert tool.main(["plan", "--env-file", str(env)]) == 0
    assert '"scan-zone"' in capsys.readouterr().out
    out = tmp_path / "w.nft"
    assert tool.main(["render", "--env-file", str(env), "--role", "worker", "--out", str(out)]) == 0
    assert "10.20.0.0/16" in out.read_text()
    assert tool.main(["verify", "--env-file", str(env), "--deny", f"127.0.0.1:{listener}"]) == 1
    assert (
        tool.main(["verify", "--env-file", str(env), "--deny", f"127.0.0.1:{closed_port()}"]) == 0
    )
    bad = tmp_path / "bad.env"
    bad.write_text("AISW_ENV=test\nAISW_EGRESS_SCAN_CIDRS=0.0.0.0/0\n")
    assert tool.main(["plan", "--env-file", str(bad)]) == 2


@pytest.mark.parametrize(("role", "fmt", "name"), [
    ("worker", "nftables", "worker.nft"), ("api", "nftables", "api.nft"),
    ("worker", "iptables", "worker.iptables"), ("worker", "ip6tables", "worker.ip6tables"),
])  # fmt: skip
def test_committed_firewall_examples_match_the_renderer(role: Any, fmt: Any, name: str) -> None:
    base = REPO / "deploy" / "egress"
    s = Settings(_env_file=base / "example.env")
    expected = egress.render(egress.destinations(s), fmt, role=role, resolver=example_resolver)
    assert (base / f"{name}.example").read_text() == expected, (
        f"regenerate deploy/egress/{name}.example"
    )


def example_resolver(host: str, port: int) -> list[str]:
    """Documentation addresses (RFC 5737 / 3849) so the examples never name a real host."""
    table = {"db.aisw.example": ["192.0.2.10"], "idp.example.com": ["192.0.2.20"],
             "kms.aisw.example": ["192.0.2.30"], "egress-proxy.aisw.example": ["192.0.2.40"]}  # fmt: skip
    return table[host]
