"""SSRF / URL safety matrix (blueprint J.6). Resolution is faked: no network is touched."""

from __future__ import annotations

import ipaddress

import pytest

from aisw.authz.net_guard import (
    CanonicalURL,
    NetGuardError,
    block_reason,
    canonicalize_url,
    parse_internal_ranges,
    resolve_and_vet,
    vet_redirect,
)

pytestmark = pytest.mark.security


def fake(mapping: dict[str, list[str]]):  # type: ignore[no-untyped-def]
    def resolver(host: str, port: int) -> list[str]:
        if host not in mapping:
            raise OSError("NXDOMAIN")
        return mapping[host]

    return resolver


# ---- canonicalisation ----------------------------------------------------------------------
def test_canonical_forms() -> None:
    u = canonicalize_url("HTTPS://Example.COM:443/Path?q=1")
    assert (u.scheme, u.host, u.port, u.path, u.query) == (
        "https",
        "example.com",
        443,
        "/Path",
        "q=1",
    )
    assert u.origin == "https://example.com"
    assert canonicalize_url("http://example.com").port == 80
    assert canonicalize_url("https://example.com.").host == "example.com"  # trailing dot
    assert canonicalize_url("https://bücher.example/").host == "xn--bcher-kva.example"  # IDNA
    assert (
        canonicalize_url("https://[2606:4700::1111]:8443/").origin
        == "https://[2606:4700::1111]:8443"
    )


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("ftp://example.com/", "UNSUPPORTED_SCHEME"),
        ("file:///etc/passwd", "UNSUPPORTED_SCHEME"),
        ("gopher://example.com", "UNSUPPORTED_SCHEME"),
        ("javascript:alert(1)", "UNSUPPORTED_SCHEME"),
        ("//example.com", "UNSUPPORTED_SCHEME"),
        ("example.com", "UNSUPPORTED_SCHEME"),
        ("https://user:pw@example.com/", "USERINFO_NOT_ALLOWED"),
        ("https://user@example.com/", "USERINFO_NOT_ALLOWED"),
        ("https://example.com@evil.test/", "USERINFO_NOT_ALLOWED"),
        ("https://", "EMPTY_HOST"),
        ("https:///path", "EMPTY_HOST"),
        ("https://exa mple.com", "MALFORMED_URL"),
        ("https://example.com/\nHost: evil", "MALFORMED_URL"),
        ("https://example.com\\@evil.test", "MALFORMED_URL"),
        ("https://example.com:99999/", "MALFORMED_URL"),
        ("https://example.com:abc/", "MALFORMED_URL"),
        ("https://-bad-.example/", "MALFORMED_HOST"),
        ("https://exa_mple.com/", "MALFORMED_HOST"),
        ("", "MALFORMED_URL"),
        ("https://" + "a" * 64 + ".example/", "MALFORMED_HOST"),
    ],
)
def test_malformed_urls_rejected(raw: str, code: str) -> None:
    with pytest.raises(NetGuardError) as e:
        canonicalize_url(raw)
    assert e.value.code == code


@pytest.mark.parametrize(
    "raw",
    [
        "http://2130706433/",  # decimal 127.0.0.1
        "http://0x7f000001/",  # hex
        "http://0x7f.0.0.1/",
        "http://017700000001/",  # octal
        "http://0177.0.0.1/",
        "http://127.1/",  # short form
        "http://127.0.1/",
        "http://010.010.010.010/",  # leading zeros are ambiguous (octal)
        "http://1.2.3.04/",
        "http://256.1.1.1/",
    ],
)
def test_ambiguous_ipv4_spellings_rejected(raw: str) -> None:
    with pytest.raises(NetGuardError) as e:
        canonicalize_url(raw)
    assert e.value.code in {"AMBIGUOUS_IP_FORMAT", "MALFORMED_HOST"}


# ---- address classification ----------------------------------------------------------------
BLOCKED = {
    "127.0.0.1": "LOOPBACK", "127.255.255.254": "LOOPBACK", "::1": "LOOPBACK",
    "10.0.0.1": "PRIVATE", "172.16.5.4": "PRIVATE", "192.168.1.1": "PRIVATE", "fd12:3456::1": "PRIVATE",
    "169.254.1.1": "LINK_LOCAL", "fe80::1": "LINK_LOCAL",
    "224.0.0.1": "MULTICAST", "ff02::1": "MULTICAST", "ff0e::1": "MULTICAST",
    "0.0.0.0": "UNSPECIFIED", "::": "UNSPECIFIED",  # noqa: S104
    "240.0.0.1": "PRIVATE", "255.255.255.255": "PRIVATE",
    "100.64.0.1": "NON_ROUTABLE", "198.18.0.1": "PRIVATE", "fec0::1": "NON_ROUTABLE",
    "169.254.169.254": "CLOUD_METADATA", "fd00:ec2::254": "CLOUD_METADATA",
    "100.100.100.200": "CLOUD_METADATA", "169.254.170.2": "CLOUD_METADATA",
    "::ffff:127.0.0.1": "EMBEDDED_LOOPBACK", "::ffff:10.0.0.5": "EMBEDDED_PRIVATE",
    "::ffff:169.254.169.254": "EMBEDDED_CLOUD_METADATA",
    "2002:7f00:1::": "EMBEDDED_LOOPBACK",  # 6to4 wrapping 127.0.0.1
    "2002:c0a8:0101::": "EMBEDDED_PRIVATE",  # 6to4 wrapping 192.168.1.1
    "64:ff9b::7f00:1": "EMBEDDED_LOOPBACK",  # NAT64 wrapping 127.0.0.1 (is_global lies here)
    "64:ff9b::a9fe:a9fe": "EMBEDDED_CLOUD_METADATA",
    "64:ff9b:1::1": "NAT64_LOCAL_USE",
    "2001:db8::1": "PRIVATE",
}  # fmt: skip


@pytest.mark.parametrize(("addr", "reason"), list(BLOCKED.items()))
def test_blocked_address_matrix(addr: str, reason: str) -> None:
    assert block_reason(ipaddress.ip_address(addr)) == reason


@pytest.mark.parametrize("addr", ["8.8.8.8", "93.184.216.34", "2606:4700::1111", "::ffff:8.8.8.8"])
def test_public_addresses_allowed(addr: str) -> None:
    assert block_reason(ipaddress.ip_address(addr)) is None


def test_internal_authorisation_opens_only_that_range_and_never_metadata() -> None:
    nets = parse_internal_ranges(["10.20.0.0/16"])
    assert block_reason(ipaddress.ip_address("10.20.1.5"), nets) is None
    assert block_reason(ipaddress.ip_address("10.21.0.1"), nets) == "PRIVATE"
    assert block_reason(ipaddress.ip_address("127.0.0.1"), nets) == "LOOPBACK"
    assert block_reason(ipaddress.ip_address("::ffff:10.20.1.5"), nets) is None
    meta = parse_internal_ranges(["169.254.0.0/16"])
    assert block_reason(ipaddress.ip_address("169.254.169.254"), meta) == "CLOUD_METADATA"
    loop = parse_internal_ranges(["127.0.0.1/32"])
    assert (
        block_reason(ipaddress.ip_address("127.0.0.1"), loop) is None
    )  # explicit local test target


@pytest.mark.parametrize("bad", ["0.0.0.0/0", "::/0", "10.0.0.0/7", "not-a-cidr", "10.0.0.1/8"])
def test_overbroad_or_invalid_internal_authorisation_rejected(bad: str) -> None:
    with pytest.raises(NetGuardError):
        parse_internal_ranges([bad])


# ---- resolution ----------------------------------------------------------------------------
def url(raw: str = "https://example.com/") -> CanonicalURL:
    return canonicalize_url(raw)


def test_resolve_pins_public_addresses_and_sorts() -> None:
    r = resolve_and_vet(
        url(),
        allowed_ports=[443],
        resolver=fake({"example.com": ["93.184.216.34", "2606:2800::1"]}),
    )
    assert r.addresses == ("2606:2800::1", "93.184.216.34") or set(r.addresses) == {
        "93.184.216.34",
        "2606:2800::1",
    }


@pytest.mark.parametrize(
    ("answers", "code"),
    [
        (["127.0.0.1"], "BLOCKED_ADDRESS_LOOPBACK"),
        (["10.0.0.7"], "BLOCKED_ADDRESS_PRIVATE"),
        (["93.184.216.34", "10.0.0.7"], "BLOCKED_ADDRESS_PRIVATE"),  # ONE bad answer denies all
        (["169.254.169.254"], "BLOCKED_ADDRESS_CLOUD_METADATA"),
        (["::ffff:7f00:1"], "BLOCKED_ADDRESS_EMBEDDED_LOOPBACK"),
        (["::1"], "BLOCKED_ADDRESS_LOOPBACK"),
        ([], "DNS_NO_ANSWER"),
        (["not-an-ip"], "DNS_INVALID_ANSWER"),
    ],
)
def test_blocked_dns_answers_deny_the_target(answers: list[str], code: str) -> None:
    with pytest.raises(NetGuardError) as e:
        resolve_and_vet(url(), allowed_ports=[443], resolver=fake({"example.com": answers}))
    assert e.value.code == code


def test_nxdomain_and_unapproved_port() -> None:
    with pytest.raises(NetGuardError) as e:
        resolve_and_vet(url(), allowed_ports=[443], resolver=fake({}))
    assert e.value.code == "DNS_RESOLUTION_FAILED"
    with pytest.raises(NetGuardError) as e2:
        resolve_and_vet(
            url("https://example.com:8443/"),
            allowed_ports=[443],
            resolver=fake({"example.com": ["8.8.8.8"]}),
        )
    assert e2.value.code == "PORT_NOT_APPROVED"
    with pytest.raises(NetGuardError):  # empty approval list approves nothing
        resolve_and_vet(url(), allowed_ports=[], resolver=fake({"example.com": ["8.8.8.8"]}))


def test_ip_literal_targets_are_vetted_without_dns() -> None:
    def boom(host: str, port: int) -> list[str]:
        raise AssertionError("resolver must not be called for literals")

    with pytest.raises(NetGuardError) as e:
        resolve_and_vet(url("http://127.0.0.1/"), allowed_ports=[80], resolver=boom)
    assert e.value.code == "BLOCKED_ADDRESS_LOOPBACK"
    ok = resolve_and_vet(
        url("http://127.0.0.1:3000/"),
        allowed_ports=[3000],
        internal_ranges=["127.0.0.1/32"],
        resolver=boom,
    )
    assert ok.addresses == ("127.0.0.1",)


def test_dns_rebinding_between_preflight_and_dispatch() -> None:
    pre = resolve_and_vet(
        url(), allowed_ports=[443], resolver=fake({"example.com": ["93.184.216.34"]})
    )
    with pytest.raises(NetGuardError) as e:  # answer flips into a blocked range
        resolve_and_vet(
            url(), allowed_ports=[443], resolver=fake({"example.com": ["127.0.0.1"]}), previous=pre
        )
    assert e.value.code == "BLOCKED_ADDRESS_LOOPBACK"
    moved = resolve_and_vet(
        url(), allowed_ports=[443], resolver=fake({"example.com": ["8.8.4.4"]}), previous=pre
    )
    assert moved.warnings == (
        "DNS_ANSWER_CHANGED_SINCE_PREFLIGHT",
    )  # public->public: allowed, flagged


# ---- redirects -----------------------------------------------------------------------------
def scope_of(*origins: str):  # type: ignore[no-untyped-def]
    allowed = {canonicalize_url(o).origin for o in origins}
    return lambda u: u.origin in allowed


R = fake(
    {
        "example.com": ["93.184.216.34"],
        "www.example.com": ["93.184.216.35"],
        "evil.test": ["8.8.8.8"],
        "rebind.test": ["10.0.0.9"],
    }
)


def test_same_origin_redirect_ok_and_relative_resolved() -> None:
    cur = url("https://example.com/a")
    ok = vet_redirect(
        cur,
        "/b?x=1",
        hop=1,
        in_scope=scope_of("https://example.com"),
        allowed_ports=[443],
        resolver=R,
    )
    assert str(ok.url) == "https://example.com/b?x=1"


@pytest.mark.parametrize(
    ("location", "code"),
    [
        ("https://evil.test/", "REDIRECT_OUT_OF_SCOPE"),  # different host, not in scope
        ("https://www.example.com/", "REDIRECT_OUT_OF_SCOPE"),
        ("https://example.com:8443/", "REDIRECT_OUT_OF_SCOPE"),  # different port
        ("http://example.com/", "REDIRECT_OUT_OF_SCOPE"),  # scheme downgrade changes origin
        ("http://127.0.0.1/admin", "REDIRECT_OUT_OF_SCOPE"),
        ("http://169.254.169.254/latest/meta-data", "REDIRECT_OUT_OF_SCOPE"),
        ("file:///etc/passwd", "UNSUPPORTED_SCHEME"),
        ("//evil.test/x", "REDIRECT_OUT_OF_SCOPE"),
        ("https://user:pw@example.com/", "USERINFO_NOT_ALLOWED"),
        ("https://example.com/\r\nX: y", "MALFORMED_REDIRECT"),
    ],
)
def test_unsafe_redirects_denied(location: str, code: str) -> None:
    with pytest.raises(NetGuardError) as e:
        vet_redirect(
            url("https://example.com/"),
            location,
            hop=1,
            in_scope=scope_of("https://example.com"),
            allowed_ports=[443, 80, 8443],
            resolver=R,
        )
    assert e.value.code == code


def test_in_scope_cross_host_redirect_still_gets_egress_checked() -> None:
    scope = scope_of("https://example.com", "https://rebind.test")  # explicitly authorised host...
    with pytest.raises(NetGuardError) as e:  # ...that now resolves to a private address
        vet_redirect(
            url("https://example.com/"),
            "https://rebind.test/",
            hop=1,
            in_scope=scope,
            allowed_ports=[443],
            resolver=R,
        )
    assert e.value.code == "BLOCKED_ADDRESS_PRIVATE"
    ok = vet_redirect(
        url("https://example.com/"),
        "https://evil.test/",
        hop=1,
        in_scope=scope_of("https://example.com", "https://evil.test"),
        allowed_ports=[443],
        resolver=R,
    )
    assert ok.url.host == "evil.test"


def test_redirect_hop_limit() -> None:
    with pytest.raises(NetGuardError) as e:
        vet_redirect(
            url(),
            "/x",
            hop=6,
            in_scope=scope_of("https://example.com"),
            allowed_ports=[443],
            resolver=R,
        )
    assert e.value.code == "TOO_MANY_REDIRECTS"
