from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aisw.authz import scope as S
from aisw.authz.policy import GatePolicy
from aisw.contracts.manifest import ScopeManifestBody, ScopeTarget


def body(
    targets: list[dict[str, str]], exclusions: list[dict[str, str]] | None = None
) -> ScopeManifestBody:
    return ScopeManifestBody.model_validate(
        {
            "tenant_id": "t", "project_id": "p", "targets": targets, "exclusions": exclusions or [],
            "domains": ["d"], "allowed_adapters": ["a"],
            "profiles": {"a": {"profile_id": "P", "profile_class": "READ_ONLY"}},
            "evidence_retention_days": 1, "policy_version": "v",
            "expires_at": datetime(2030, 1, 1, tzinfo=UTC) + timedelta(0),
        }
    )  # fmt: skip


@pytest.mark.parametrize(
    ("req", "expected"),
    [
        ("https://example.com", True),
        ("https://example.com/a/b", True),
        ("http://example.com", False),  # scheme differs
        ("https://example.com:8443", False),  # port differs
        ("https://www.example.com", False),  # host differs
        ("https://example.com.evil.test", False),
    ],
)
def test_url_matching(req: str, expected: bool) -> None:
    assert (
        S.in_scope(body([{"kind": "url", "selector": "https://example.com"}]), "url", req)
        is expected
    )


def test_url_path_prefix_respects_segment_boundaries() -> None:
    b = body([{"kind": "url", "selector": "https://example.com/app"}])
    assert S.in_scope(b, "url", "https://example.com/app")
    assert S.in_scope(b, "url", "https://example.com/app/x")
    assert not S.in_scope(b, "url", "https://example.com/application")
    assert not S.in_scope(b, "url", "https://example.com/")


def test_cidr_request_must_be_inside_never_broader() -> None:
    b = body([{"kind": "cidr", "selector": "192.0.2.0/24"}])
    assert S.in_scope(b, "cidr", "192.0.2.0/25")
    assert S.in_scope(b, "host", "192.0.2.9")  # a host inside a scoped CIDR is in scope
    assert not S.in_scope(b, "host", "192.0.3.9")
    assert not S.in_scope(b, "cidr", "192.0.0.0/16")
    assert not S.in_scope(b, "cidr", "2001:db8::/32")


def test_exclusions_win_across_kinds() -> None:
    b = body(
        [
            {"kind": "cidr", "selector": "192.0.2.0/24"},
            {"kind": "url", "selector": "https://example.com"},
        ],
        [
            {"kind": "cidr", "selector": "192.0.2.128/25"},
            {"kind": "host", "selector": "example.com"},
        ],
    )
    assert S.in_scope(b, "cidr", "192.0.2.0/25")
    assert not S.in_scope(b, "cidr", "192.0.2.0/24")  # overlaps the excluded half
    assert not S.in_scope(b, "url", "https://example.com/x")  # host excluded


def test_other_kinds_are_exact() -> None:
    b = body([{"kind": "cloud_account", "selector": "123456789012"}])
    assert S.in_scope(b, "cloud_account", "123456789012")
    assert not S.in_scope(b, "cloud_account", "123456789013")
    assert not S.in_scope(b, "region", "123456789012")


@pytest.mark.parametrize(
    ("kind", "sel", "reason"),
    [
        ("cidr", "0.0.0.0/0", "WILDCARD_SCOPE"),  # noqa: S104
        ("cidr", "10.0.0.0/8", "CIDR_TOO_BROAD"),
        ("cidr", "192.0.2.0/24", None),
        ("cidr", "garbage", "INVALID_CIDR"),
        ("host", "*.example.com", "WILDCARD_SCOPE"),
        ("asset_group", "any", "WILDCARD_SCOPE"),
        ("url", "https://example.com", None),
    ],
)
def test_wildcard_detection(kind: str, sel: str, reason: str | None) -> None:
    t = ScopeTarget.model_validate({"kind": kind, "selector": sel})
    assert S.wildcard_reason(t, GatePolicy()) == reason
