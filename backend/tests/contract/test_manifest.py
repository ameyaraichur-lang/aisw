from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from aisw.contracts.enums import Decision, ManifestStatus
from aisw.contracts.manifest import (
    AuthorizationDecision,
    ExecutionPermit,
    ScopeManifest,
    ScopeManifestBody,
)

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)


def body_dict(**over: Any) -> dict[str, Any]:
    b: dict[str, Any] = {
        "tenant_id": "tenant-a", "project_id": "proj-1",
        "targets": [{"kind": "url", "selector": "https://example.com"}],
        "domains": ["url"], "allowed_adapters": ["url_smoke"],
        "profiles": {"url_smoke": {"profile_id": "PASSIVE_HTTP_SMOKE", "profile_class": "READ_ONLY"}}, "allowed_ports": [443],
        "evidence_retention_days": 30, "policy_version": "baseline-1",
        "expires_at": (NOW + timedelta(days=1)).isoformat(),
    }  # fmt: skip
    b.update(over)
    return b


def make_manifest(status: str = "DRAFT", **over: Any) -> dict[str, Any]:
    body = ScopeManifestBody.model_validate(body_dict())
    m: dict[str, Any] = {
        "manifest_id": "m-1", "version": 1, "status": status, "body": body.model_dump(mode="json"),
        "canonical_hash": body.hash(), "created_by": "alice",
    }  # fmt: skip
    m.update(over)
    return m


def test_hash_is_deterministic_and_content_sensitive() -> None:
    a = ScopeManifestBody.model_validate(body_dict())
    b = ScopeManifestBody.model_validate(body_dict())
    assert a.hash() == b.hash()
    c = ScopeManifestBody.model_validate(body_dict(allowed_ports=[443, 80]))
    assert a.hash() != c.hash()


@pytest.mark.security
def test_tampered_body_fails_hash_check() -> None:
    m = make_manifest()
    m["body"]["allowed_ports"] = [443, 22]  # attacker widens scope after hashing
    with pytest.raises(ValidationError, match="canonical_hash"):
        ScopeManifest.model_validate(m)


@pytest.mark.parametrize(
    "over",
    [
        {"targets": []},
        {"allowed_ports": [0]},
        {"allowed_ports": [443, 443]},
        {
            "profiles": {"nmap": {"profile_id": "p", "profile_class": "ACTIVE"}}
        },  # adapter not allowlisted
        {"targets": [{"kind": "url", "selector": "a"}, {"kind": "url", "selector": "a"}]},
        {"expires_at": "2026-10-16T12:00:00"},
        {"surprise": True},
    ],
)
def test_invalid_bodies_rejected(over: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ScopeManifestBody.model_validate(body_dict(**over))


def test_active_profile_detection() -> None:
    b = ScopeManifestBody.model_validate(
        body_dict(
            allowed_adapters=["zap"],
            profiles={"zap": {"profile_id": "ACTIVE_SCAN", "profile_class": "ACTIVE"}},
        )
    )
    assert b.has_active_profile()


@pytest.mark.security
def test_approved_manifest_rules() -> None:
    with pytest.raises(ValidationError):  # unsigned
        ScopeManifest.model_validate(make_manifest("APPROVED", approved_by=["bob"]))
    signed = {"signature": "sig", "key_id": "key-1"}
    with pytest.raises(ValidationError):  # no approver
        ScopeManifest.model_validate(make_manifest("APPROVED", **signed))
    with pytest.raises(ValidationError, match="own manifest"):  # self-approval
        ScopeManifest.model_validate(make_manifest("APPROVED", approved_by=["alice"], **signed))
    ok = ScopeManifest.model_validate(make_manifest("APPROVED", approved_by=["bob"], **signed))
    assert ok.status is ManifestStatus.APPROVED


def permit(**over: Any) -> ExecutionPermit:
    d: dict[str, Any] = {
        "permit_id": "p-1", "tenant_id": "tenant-a", "project_id": "proj-1", "run_id": "run-1",
        "manifest_hash": "sha256:" + "a" * 64, "allowed_task_types": ["discovery"],
        "issued_at": NOW.isoformat(), "expires_at": (NOW + timedelta(minutes=10)).isoformat(),
        "policy_version": "baseline-1",
    }  # fmt: skip
    d.update(over)
    return ExecutionPermit.model_validate(d)


@pytest.mark.security
def test_permit_validity_matrix() -> None:
    p = permit()
    h = "sha256:" + "a" * 64
    assert p.is_valid_at(NOW + timedelta(minutes=1), manifest_hash=h, task_type="discovery")
    assert not p.is_valid_at(NOW + timedelta(minutes=10), manifest_hash=h, task_type="discovery")
    assert not p.is_valid_at(NOW - timedelta(seconds=1), manifest_hash=h, task_type="discovery")
    assert not p.is_valid_at(NOW, manifest_hash="sha256:" + "b" * 64, task_type="discovery")
    assert not p.is_valid_at(NOW, manifest_hash=h, task_type="nmap_scan")
    with pytest.raises(ValidationError):
        permit(expires_at=NOW.isoformat())


def test_decision_rules() -> None:
    with pytest.raises(ValidationError):
        AuthorizationDecision(decision=Decision.ALLOW, reason_codes=["ok"])  # no hash
    with pytest.raises(ValidationError):
        AuthorizationDecision(decision=Decision.DENY, reason_codes=[])
    assert AuthorizationDecision(decision=Decision.DENY, reason_codes=["HASH_MISMATCH"])
