"""Agent 0 minimum acceptance matrix (Appendix G): every rejection must cause ZERO tool dispatch,
leave a DENIED audit event, and keep the tenant's audit chain valid."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text

from aisw.authz.service import ScopeDenied
from aisw.contracts.enums import Decision, ManifestStatus
from aisw.core.db import tenant_connection
from aisw.core.idempotency import IdempotencyConflict
from aisw.core.rbac import Forbidden, Role
from aisw.gateway.gateway import GatewayDenied
from tests.support import Env

pytestmark = pytest.mark.security


def audit_count(env: Env, result: str) -> int:
    with tenant_connection(env.engine, env.tenant) as c:
        return int(
            c.execute(
                text("SELECT count(*) FROM audit_events WHERE result=:r"), {"r": result}
            ).scalar_one()
        )


# ---- happy path ----------------------------------------------------------------------------
def test_full_lifecycle_and_single_dispatch(env: Env) -> None:
    draft = env.draft()
    assert draft.status is ManifestStatus.DRAFT and draft.version == 1
    assert draft.body.targets[0].resolved_asset_id == "src-1"  # resolved against inventory
    outcome = env.service.preflight(env.operator, draft.manifest_id, cid="t")
    assert outcome.decision.decision is Decision.APPROVAL_REQUIRED  # valid but unapproved
    m = env.service.approve(env.approver, draft.manifest_id, cid="t")
    assert m.status is ManifestStatus.APPROVED and m.signature and m.approved_by == ("bob",)
    auth = env.launch(m)
    assert env.total_dispatched == 0  # authorising a run executes nothing
    res = env.gateway.dispatch(env.request(auth, m))
    assert res.adapter_result["ok"] and env.url_adapter.executed[0].pinned_addresses == (
        "93.184.216.34",
    )
    assert env.total_dispatched == 1
    assert audit_count(env, "DENIED") == 0


# ---- identity, roles, separation of duties --------------------------------------------------
def test_cross_tenant_requests_rejected_before_anything_is_stored(env: Env) -> None:
    from tests.support import make_env

    other = make_env(env.engine)  # a second tenant with its own project
    mallory = other.actor("mallory", Role.ASSESSMENT_OPERATOR, Role.APPROVER)
    with pytest.raises(ScopeDenied) as e:  # tenant B actor drafts a manifest for tenant A's project
        other.service.create_draft(mallory, env.project_id, env.body(), cid="t")
    assert {"CROSS_TENANT", "PROJECT_NOT_FOUND"} <= set(e.value.reason_codes)
    with tenant_connection(env.engine, env.tenant) as c:
        assert c.execute(text("SELECT count(*) FROM scope_manifests")).scalar_one() == 0
    m = env.approved()
    with pytest.raises(ScopeDenied) as e2:  # tenant B cannot even see tenant A's manifest
        other.service.approve(mallory, m.manifest_id, cid="t")
    assert e2.value.reason_codes == ["MANIFEST_NOT_FOUND"]
    with pytest.raises(ScopeDenied):
        other.service.authorize_launch(
            mallory, project_id=env.project_id, manifest_id=m.manifest_id,
            manifest_hash=m.canonical_hash, task_types=None, idempotency_key="k", cid="t",
        )  # fmt: skip
    assert env.total_dispatched == 0 and other.total_dispatched == 0
    assert audit_count(other, "DENIED") >= 3  # recorded in the ATTACKER's own tenant chain


def test_roles_are_enforced_and_denials_audited(env: Env) -> None:
    reader = env.actor("carol", Role.REPORT_READER)
    with pytest.raises(Forbidden):
        env.service.create_draft(reader, env.project_id, env.body(), cid="t")
    m = env.draft()
    with pytest.raises(Forbidden):  # operators cannot approve
        env.service.approve(env.operator, m.manifest_id, cid="t")
    with pytest.raises(Forbidden):  # approvers cannot launch
        env.service.authorize_launch(
            env.approver, project_id=env.project_id, manifest_id=m.manifest_id,
            manifest_hash=m.canonical_hash, task_types=None, idempotency_key="k", cid="t",
        )  # fmt: skip
    assert audit_count(env, "DENIED") == 3 and env.total_dispatched == 0


def test_self_approval_rejected(env: Env) -> None:
    both = env.actor("alice", Role.ASSESSMENT_OPERATOR, Role.APPROVER)
    m = env.draft()
    env.service.preflight(both, m.manifest_id, cid="t")
    with pytest.raises(ScopeDenied) as e:
        env.service.approve(both, m.manifest_id, cid="t")
    assert e.value.reason_codes == ["SELF_APPROVAL"]
    with pytest.raises(ScopeDenied) as e2:
        env.launch(m)
    assert e2.value.reason_codes == ["MANIFEST_NOT_APPROVED"]


def test_approval_requires_preflight_first(env: Env) -> None:
    m = env.draft()
    with pytest.raises(ScopeDenied) as e:
        env.service.approve(env.approver, m.manifest_id, cid="t")
    assert e.value.reason_codes == ["MANIFEST_NOT_PREFLIGHTED"]


# ---- scope content --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("targets", "code"),
    [
        ([{"kind": "cidr", "selector": "0.0.0.0/0"}], "WILDCARD_SCOPE"),  # noqa: S104
        ([{"kind": "cidr", "selector": "10.0.0.0/8"}], "CIDR_TOO_BROAD"),
        ([{"kind": "cidr", "selector": "::/0"}], "WILDCARD_SCOPE"),
        ([{"kind": "url", "selector": "https://*.example.com"}], "WILDCARD_SCOPE"),
        ([{"kind": "host", "selector": "*"}], "WILDCARD_SCOPE"),
        ([{"kind": "asset_group", "selector": "all"}], "WILDCARD_SCOPE"),
        ([{"kind": "url", "selector": "https://example.org"}], "TARGET_NOT_IN_INVENTORY"),
        ([{"kind": "url", "selector": "ftp://example.com"}], "UNSUPPORTED_SCHEME"),
        ([{"kind": "url", "selector": "https://u:p@example.com"}], "USERINFO_NOT_ALLOWED"),
        ([{"kind": "url", "selector": "http://127.0.0.1"}], "TARGET_NOT_IN_INVENTORY"),
        ([{"kind": "region", "selector": "eu-west-1"}], "NO_ADAPTER_FOR_TARGET"),
    ],
)
def test_wildcard_and_unresolvable_scope_denied(
    env: Env, targets: list[dict[str, str]], code: str
) -> None:
    with pytest.raises(ScopeDenied) as e:
        env.service.create_draft(env.operator, env.project_id, env.body(targets=targets), cid="t")
    assert code in e.value.reason_codes
    assert env.total_dispatched == 0 and audit_count(env, "DENIED") == 1


def test_excluded_target_denied(env: Env) -> None:
    body = env.body(exclusions=[{"kind": "url", "selector": "https://example.com"}])
    with pytest.raises(ScopeDenied) as e:
        env.service.create_draft(env.operator, env.project_id, body, cid="t")
    assert "TARGET_EXCLUDED" in e.value.reason_codes


def test_exclusion_enforced_at_dispatch_with_segment_boundaries(env: Env) -> None:
    m = env.approved(
        env.body(exclusions=[{"kind": "url", "selector": "https://example.com/admin"}])
    )
    auth = env.launch(m)
    for path in ("/admin", "/admin/users", "/admin/"):
        with pytest.raises(GatewayDenied) as e:
            env.gateway.dispatch(env.request(auth, m, target_selector=f"https://example.com{path}"))
        assert e.value.reason_codes == ["TARGET_OUT_OF_SCOPE"]
    assert env.total_dispatched == 0
    env.gateway.dispatch(env.request(auth, m, target_selector="https://example.com/administrator"))
    assert env.total_dispatched == 1  # "/administrator" is not under "/admin"


@pytest.mark.parametrize(
    ("over", "code"),
    [
        (
            {"profiles": {"url_smoke": {"profile_id": "FUZZ", "profile_class": "READ_ONLY"}}},
            "UNSUPPORTED_PROFILE",
        ),
        (
            {
                "profiles": {
                    "url_smoke": {"profile_id": "PASSIVE_HTTP_SMOKE", "profile_class": "ACTIVE"}
                }
            },
            "PROFILE_CLASS_MISMATCH",
        ),
        (
            {
                "allowed_adapters": ["url_smoke", "nmap"],
                "profiles": {
                    "url_smoke": {"profile_id": "PASSIVE_HTTP_SMOKE", "profile_class": "READ_ONLY"},
                    "nmap": {"profile_id": "x", "profile_class": "READ_ONLY"},
                },
            },
            "UNKNOWN_ADAPTER",
        ),
        ({"domains": ["cloud"]}, "UNSUPPORTED_DOMAIN"),
        ({"expires_at": "2026-10-15T11:00:00+00:00"}, "MANIFEST_EXPIRED"),
        ({"expires_at": "2026-12-31T00:00:00+00:00"}, "VALIDITY_EXCEEDS_POLICY"),
        ({"quotas": {"max_concurrency": 8}}, "CONCURRENCY_EXCEEDS_POLICY"),
        ({"quotas": {"max_requests": 10**6}}, "REQUEST_BUDGET_EXCEEDS_POLICY"),
        ({"quotas": {"max_duration_seconds": 80000}}, "DURATION_EXCEEDS_POLICY"),
        ({"evidence_retention_days": 100000}, "RETENTION_EXCEEDS_POLICY"),
        ({"allowed_ports": []}, "PORT_NOT_APPROVED"),
        ({"allowed_ports": [8443]}, "PORT_NOT_APPROVED"),
    ],
)
def test_policy_violations_denied(env: Env, over: dict[str, Any], code: str) -> None:
    with pytest.raises(ScopeDenied) as e:
        env.service.create_draft(env.operator, env.project_id, env.body(**over), cid="t")
    assert code in e.value.reason_codes
    assert env.total_dispatched == 0


def test_denied_connector_blocks_manifest_and_later_dispatch(env: Env) -> None:
    env.url_adapter.capability = type(env.url_adapter.capability)(
        **{**env.url_adapter.capability.__dict__, "permission_ok": False}
    )
    with pytest.raises(ScopeDenied) as e:
        env.draft()
    assert "CONNECTOR_DENIED" in e.value.reason_codes
    # approved earlier, connector permission revoked afterwards: gateway must refuse too
    env.url_adapter.capability = type(env.url_adapter.capability)(
        **{**env.url_adapter.capability.__dict__, "permission_ok": True}
    )
    m = env.approved()
    auth = env.launch(m)
    env.url_adapter.capability = type(env.url_adapter.capability)(
        **{**env.url_adapter.capability.__dict__, "enabled": False}
    )
    with pytest.raises(GatewayDenied) as e2:
        env.gateway.dispatch(env.request(auth, m))
    assert e2.value.reason_codes == ["CONNECTOR_DENIED"] and env.total_dispatched == 0


# ---- network safety at draft time ----------------------------------------------------------
@pytest.mark.parametrize(
    ("answers", "code"),
    [(["127.0.0.1"], "BLOCKED_ADDRESS_LOOPBACK"), (["10.1.2.3"], "BLOCKED_ADDRESS_PRIVATE"),
     (["169.254.169.254"], "BLOCKED_ADDRESS_CLOUD_METADATA"), ([], "DNS_NO_ANSWER")],
)  # fmt: skip
def test_blocked_dns_at_preflight_denies_manifest(env: Env, answers: list[str], code: str) -> None:
    env.dns["example.com"] = answers
    with pytest.raises(ScopeDenied) as e:
        env.draft()
    assert code in e.value.reason_codes


def test_dns_rebinding_after_approval_is_stopped_at_dispatch(env: Env) -> None:
    m = env.approved()
    auth = env.launch(m)
    env.dns["example.com"] = ["127.0.0.1"]  # attacker flips the record after approval
    with pytest.raises(GatewayDenied) as e:
        env.gateway.dispatch(env.request(auth, m))
    assert e.value.reason_codes == ["BLOCKED_ADDRESS_LOOPBACK"] and env.total_dispatched == 0
    with pytest.raises(
        ScopeDenied
    ) as e2:  # and a fresh launch re-runs policy, so it is refused too
        env.launch(m)
    assert "BLOCKED_ADDRESS_LOOPBACK" in e2.value.reason_codes


def test_internal_range_authorisation_is_explicit_and_hash_bound(env: Env) -> None:
    env.dns["lab.test"] = ["10.20.0.5"]
    env.inventory.entries[(env.tenant, env.project_id, "url", "https://lab.test")] = "src-2"
    plain = env.body(targets=[{"kind": "url", "selector": "https://lab.test"}])
    with pytest.raises(ScopeDenied):
        env.service.create_draft(env.operator, env.project_id, plain, cid="t")
    authorised = env.body(
        targets=[{"kind": "url", "selector": "https://lab.test"}],
        internal_range_authorization=["10.20.0.0/16"],
    )
    m = env.approved(authorised)
    assert m.body.internal_range_authorization == ["10.20.0.0/16"]
    assert m.canonical_hash != env.body().hash()


# ---- active profiles -----------------------------------------------------------------------
def active_body(env: Env) -> Any:
    env.inventory.entries[(env.tenant, env.project_id, "url", "https://example.com")] = "src-1"
    return env.body(
        allowed_adapters=["zap"],
        profiles={"zap": {"profile_id": "ACTIVE_SCAN", "profile_class": "ACTIVE"}},
    )


def test_active_profile_needs_explicit_acknowledgement(env: Env) -> None:
    m = env.draft(active_body(env))
    env.service.preflight(env.operator, m.manifest_id, cid="t")
    with pytest.raises(ScopeDenied) as e:
        env.service.approve(env.approver, m.manifest_id, cid="t")
    assert "ACTIVE_PROFILE_REQUIRES_APPROVAL" in e.value.reason_codes
    with pytest.raises(ScopeDenied):
        env.launch(m)  # still unapproved
    approved = env.service.approve(
        env.approver, m.manifest_id, acknowledge_active_adapters=frozenset({"zap"}), cid="t"
    )
    auth = env.launch(approved)
    env.gateway.dispatch(
        env.request(auth, approved, task_type="zap", adapter_id="zap", profile="ACTIVE_SCAN")
    )
    assert len(env.active_adapter.executed) == 1


def test_read_only_approval_cannot_be_used_to_run_the_active_profile(env: Env) -> None:
    m = env.approved(env.body(allowed_adapters=["url_smoke", "zap"], profiles={
        "url_smoke": {"profile_id": "PASSIVE_HTTP_SMOKE", "profile_class": "READ_ONLY"},
        "zap": {"profile_id": "BASELINE", "profile_class": "READ_ONLY"}}))  # fmt: skip
    auth = env.launch(m)
    with pytest.raises(GatewayDenied) as e:
        env.gateway.dispatch(
            env.request(auth, m, task_type="zap", adapter_id="zap", profile="ACTIVE_SCAN")
        )
    assert e.value.reason_codes == ["PROFILE_NOT_IN_MANIFEST"] and env.total_dispatched == 0


# ---- stale hash, versions, expiry, replay ---------------------------------------------------
def test_stale_hash_and_superseded_versions(env: Env) -> None:
    v1 = env.approved()
    v2 = env.approved(env.body(allowed_ports=[443, 8443]))
    assert v2.version == 2
    with pytest.raises(ScopeDenied) as e:  # v1 was superseded on v2's approval
        env.launch(v1)
    assert e.value.reason_codes == ["MANIFEST_NOT_APPROVED"]
    with pytest.raises(ScopeDenied) as e2:  # request built against v1's hash but pointing at v2
        env.launch(v2, manifest_hash=v1.canonical_hash)
    assert e2.value.reason_codes == ["STALE_HASH"]
    assert env.total_dispatched == 0


def test_launch_with_unlisted_task_type_denied(env: Env) -> None:
    m = env.approved()
    with pytest.raises(ScopeDenied) as e:
        env.launch(m, task_types=["url_smoke", "nmap_scan"])
    assert e.value.reason_codes == ["TASK_TYPE_NOT_ALLOWED"]


def test_expired_manifest_and_permit(env: Env) -> None:
    m = env.approved()
    auth = env.launch(m)
    env.now += timedelta(minutes=16)  # permit TTL is 15 minutes
    with pytest.raises(GatewayDenied) as e:
        env.gateway.dispatch(env.request(auth, m))
    assert e.value.reason_codes == ["PERMIT_EXPIRED_OR_TASK_NOT_ALLOWED"]
    env.now += timedelta(days=2)
    with pytest.raises(ScopeDenied) as e2:
        env.launch(m)
    assert e2.value.reason_codes == ["MANIFEST_EXPIRED"]
    with pytest.raises(GatewayDenied) as e3:
        env.gateway.dispatch(env.request(auth, m))
    assert e3.value.reason_codes == ["MANIFEST_EXPIRED"]
    assert env.total_dispatched == 0


def test_replayed_launch_returns_same_run_and_permit_once(env: Env) -> None:
    m = env.approved()
    first = env.launch(m, key="launch-1")
    again = env.launch(m, key="launch-1")
    assert not first.replayed and again.replayed
    assert first.run_id == again.run_id and first.permit == again.permit
    with tenant_connection(env.engine, env.tenant) as c:
        assert c.execute(text("SELECT count(*) FROM execution_permits")).scalar_one() == 1
    with pytest.raises(IdempotencyConflict):  # same key, different request
        env.launch(m, key="launch-1", task_types=["url_smoke"])
    other = env.launch(m, key="launch-2")
    assert other.run_id != first.run_id  # a new key is a new run with its own permit
