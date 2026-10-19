"""Configuration importers feeding the Rego pack: each fixture's facts are judged by the real OPA
server, and hostile or ambiguous input is refused or named, never guessed. Nothing is contacted."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from aisw.adapters.config_imports import (
    AwsIamImportAdapter,
    DirectoryImportAdapter,
    FirewallImportAdapter,
    KubescapeImportAdapter,
)
from aisw.adapters.imports_base import ImportAdapter
from aisw.gateway.registry import AdapterJob, AdapterOutput
from aisw.policy.engine import PackRegistry
from aisw.policy.opa import OpaClient, OpaEvaluator
from tests.http_server import loopback_only

pytestmark = pytest.mark.security
GOLD = Path(__file__).resolve().parents[1] / "fixtures" / "golden"
NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
PACK = PackRegistry.builtin().get("config-baseline:1.0.0")
FW, K8S = FirewallImportAdapter(clock=lambda: NOW), KubescapeImportAdapter(clock=lambda: NOW)
DIR, IAM = DirectoryImportAdapter(clock=lambda: NOW), AwsIamImportAdapter(clock=lambda: NOW)
ACCOUNT = "123456789012"


@pytest.fixture(scope="module")
def opa(opa_url: str) -> OpaEvaluator:
    return OpaEvaluator(OpaClient(opa_url))


@pytest.fixture(autouse=True)
def no_network(request: pytest.FixtureRequest) -> Iterator[None]:
    if "opa" in request.fixturenames:  # the OPA server is the one loopback peer allowed
        yield
        return
    with loopback_only() as attempts:
        yield
        assert attempts == [], "an import adapter touched the network"


def run(a: ImportAdapter, text: str, kind: str, selector: str) -> AdapterOutput:
    data = text.encode()
    return a.execute(AdapterJob(
        tenant_id="t", project_id="p", run_id="r", task_id="k", profile=next(iter(a.profiles)),
        target_kind=kind, target_selector=selector, params={"import_id": "imp-" + "a" * 20},
        read_import=lambda i, k: data, in_scope=None,
    ))  # fmt: skip


def judged(opa: OpaEvaluator, a: ImportAdapter, out: AdapterOutput) -> dict[tuple[str, str], str]:
    """(asset name, rule) -> outcome, every observation evaluated by OPA against its asset."""
    assert PACK is not None
    b = a.normalize(out, run_id="r", task_id="k")
    assets = {x.asset_id: x for x in b.assets}
    res: dict[tuple[str, str], str] = {}
    for o in b.observations:
        asset = assets[o.asset_id]
        outcome = opa.evaluate_observation(
            PACK, rule_id=o.rule_id, value=o.value, attrs=asset.attrs
        )
        assert outcome is not None, f"{o.rule_id} does not apply to {asset.attrs}"
        res[(asset.hostname, o.rule_id.split(".")[1])] = outcome.value
    return res


def gold(name: str) -> str:
    return (GOLD / name).read_text()


# ---- firewall ------------------------------------------------------------------------------------
def test_security_groups_are_account_scoped_and_judged_per_ingress_rule(opa: OpaEvaluator) -> None:
    out = run(FW, gold("aws_security_groups.json"), "cloud_account", ACCOUNT)
    assert out.status == "SUCCEEDED" and out.warnings == ["OUT_OF_SCOPE_RECORDS_DROPPED:1"]
    assert "someone-elses-group" not in str(out.raw)
    r = judged(opa, FW, out)
    assert r == {
        ("web-frontend ingress #1", "no_admin_ports_from_internet"): "PASS",  # 443 from anyone
        ("web-frontend ingress #1", "no_any_any_allow"): "PASS",
        ("web-frontend ingress #2", "no_admin_ports_from_internet"): "FAIL",  # 22 from anyone
        ("web-frontend ingress #2", "no_any_any_allow"): "PASS",
        ("web-frontend ingress #3", "no_admin_ports_from_internet"): "PASS",  # ICMP
        ("web-frontend ingress #3", "no_any_any_allow"): "PASS",
        ("db-private ingress #1", "no_admin_ports_from_internet"): "PASS",  # from a group
        ("db-private ingress #1", "no_any_any_allow"): "PASS",
        ("db-private ingress #2", "no_admin_ports_from_internet"): "PASS",  # 22 from 10.20/16
        ("db-private ingress #2", "no_any_any_allow"): "PASS",
        ("debug-open ingress #1", "no_admin_ports_from_internet"): "FAIL",
        ("debug-open ingress #1", "no_any_any_allow"): "FAIL",
    }


def test_iptables_input_chain_with_a_final_drop_is_default_deny(opa: OpaEvaluator) -> None:
    out = run(FW, gold("iptables.rules"), "host", "web-01")
    assert out.status == "SUCCEEDED" and out.warnings == []
    r = judged(opa, FW, out)
    assert r[("web-01 INPUT policy", "default_deny")] == "PASS"
    assert r[("web-01 INPUT line 15", "no_admin_ports_from_internet")] == "FAIL"  # 3389 from anyone
    assert r[("web-01 INPUT line 13", "no_admin_ports_from_internet")] == "PASS"  # 22 internal only
    assert {k[0] for k in r} == {"web-01 INPUT policy"} | {
        f"web-01 INPUT line {n}" for n in (13, 14, 15, 16)
    }


def test_iptables_accept_policy_without_a_final_drop_fails_default_deny(opa: OpaEvaluator) -> None:
    text = gold("iptables.rules").replace("-A INPUT -j DROP\n", "")
    assert (
        judged(opa, FW, run(FW, text, "host", "web-01"))[("web-01 INPUT policy", "default_deny")]
        == "FAIL"
    )


def test_iptables_rules_it_cannot_model_are_named_and_make_the_import_partial() -> None:
    text = gold("iptables.rules").replace(
        "-A INPUT -p icmp -j ACCEPT",
        "-A INPUT ! -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT\n-A INPUT -m recent --rcheck -j ACCEPT\n"
        "-A INPUT -p tcp --dport 8443 -j CUSTOM",
    )
    out = run(FW, text, "host", "web-01")
    assert out.status == "PARTIAL"
    assert [w.split(": ", 1)[1] for w in out.warnings if w.startswith("UNMODELLED_RULE")] == [
        "negated match", "match recent", "target CUSTOM"]  # fmt: skip


def test_iptables_accepts_after_a_deny_are_flagged_as_order_dependent() -> None:
    text = gold("iptables.rules").replace(
        "-A INPUT -i lo -j ACCEPT", "-A INPUT -i lo -j ACCEPT\n-A INPUT -p tcp --dport 23 -j DROP"
    )
    assert "ORDER_DEPENDENT_RULES:4" in run(FW, text, "host", "web-01").warnings


@pytest.mark.parametrize(
    ("text", "kind", "code"),
    [
        (gold("aws_security_groups.json"), "host", "TARGET_KIND_MISMATCH"),
        (gold("iptables.rules"), "cloud_account", "TARGET_KIND_MISMATCH"),
        ('{"Groups": []}', "cloud_account", "UNSUPPORTED_FORMAT"),
        ("*nat\nCOMMIT\n", "host", "UNSUPPORTED_FORMAT"),
        ("{not json", "cloud_account", "MALFORMED_JSON"),
    ],
)
def test_firewall_import_fails_closed(text: str, kind: str, code: str) -> None:
    out = run(FW, text, kind, ACCOUNT if kind == "cloud_account" else "web-01")
    assert out.status == "FAILED" and out.errors == [code]


# ---- Kubernetes RBAC ------------------------------------------------------------------------------
def test_kubescape_rbac_objects_are_judged_and_platform_defaults_skipped(opa: OpaEvaluator) -> None:
    out = run(K8S, gold("kubescape.json"), "asset_group", "prod-cluster-1")
    assert out.status == "SUCCEEDED" and out.warnings == ["PLATFORM_DEFAULTS_SKIPPED:1"]
    assert judged(opa, K8S, out) == {
        ("ClusterRoleBinding/ci-deployer-admin", "no_cluster_admin_for_service_accounts"): "FAIL",
        ("ClusterRoleBinding/ci-deployer-admin", "no_anonymous_bindings"): "PASS",
        ("ClusterRoleBinding/platform-admins", "no_cluster_admin_for_service_accounts"): "PASS",
        ("ClusterRoleBinding/platform-admins", "no_anonymous_bindings"): "PASS",
        (
            "RoleBinding/web/public-status",
            "no_cluster_admin_for_service_accounts",
        ): "NOT_APPLICABLE",
        ("RoleBinding/web/public-status", "no_anonymous_bindings"): "FAIL",
        ("ClusterRole/ops-everything", "no_wildcard_roles"): "FAIL",
        ("Role/web/status-reader", "no_wildcard_roles"): "PASS",
    }


def test_a_kubectl_list_gives_the_same_facts_as_kubescape(opa: OpaEvaluator) -> None:
    import json

    objs = [r["object"] for r in json.loads(gold("kubescape.json"))["resources"]]
    out = run(
        K8S,
        json.dumps({"apiVersion": "v1", "kind": "List", "items": objs}),
        "asset_group",
        "prod-cluster-1",
    )
    ks = run(K8S, gold("kubescape.json"), "asset_group", "prod-cluster-1")
    assert judged(opa, K8S, out) == judged(opa, K8S, ks)


def test_a_report_for_another_cluster_is_refused() -> None:
    out = run(K8S, gold("kubescape.json"), "asset_group", "staging-cluster")
    assert out.status == "FAILED" and out.errors == ["CLUSTER_MISMATCH"]


# ---- directory --------------------------------------------------------------------------------------
@pytest.mark.parametrize("fixture", ["ad_users.csv", "directory.ldif"])
def test_directory_exports_judge_staleness_and_leave_admin_mfa_unknown(
    opa: OpaEvaluator, fixture: str
) -> None:
    out = run(DIR, gold(fixture), "asset_group", "corp.example.com")
    assert out.status == "SUCCEEDED"
    assert out.warnings == ["OUT_OF_SCOPE_RECORDS_DROPPED:1", "MFA_STATE_NOT_IN_DIRECTORY_EXPORT"]
    r = judged(opa, DIR, out)
    assert r[("adm.jsmith", "admin_requires_mfa")] == "UNKNOWN"  # a directory never says
    assert r[("adm.jsmith", "no_stale_accounts")] == "PASS"
    assert r[("svc-backup-old", "no_stale_accounts")] == "FAIL"  # 228 days idle
    assert r[("leaver.m", "no_stale_accounts")] == "NOT_APPLICABLE"  # disabled
    names = {k[0] for k in r}
    assert not names & {"partner.x", "stray", "WS-0042$"}  # out of domain, or a computer


def test_ad_csv_never_logged_on_accounts_age_from_creation(opa: OpaEvaluator) -> None:
    r = judged(opa, DIR, run(DIR, gold("ad_users.csv"), "asset_group", "corp.example.com"))
    assert r[("contractor.k", "no_stale_accounts")] == "FAIL"
    assert r[("jdoe", "admin_requires_mfa")] == "NOT_APPLICABLE"


def test_ldif_decodes_base64_and_folded_lines_and_refuses_url_values() -> None:
    out = run(DIR, gold("directory.ldif"), "asset_group", "corp.example.com")
    ids = {i["name"]: i for i in out.raw["identities"]}
    assert ids["adm.jsmith"]["fact"]["admin"] is True  # memberOf was folded over two lines
    assert "zoe.ops" in ids
    bad = gold("directory.ldif").replace(
        "displayName:: Wm/DqyBPcHM=", "jpegPhoto:< file:///etc/passwd"
    )
    assert run(DIR, bad, "asset_group", "corp.example.com").errors == ["LDIF_URL_VALUE_REFUSED"]
    assert run(DIR, "dn: x\nnot-an-attribute\n", "asset_group", "corp").errors == ["MALFORMED_LDIF"]


# ---- AWS IAM credential report ------------------------------------------------------------------------
def test_credential_report_judges_keys_staleness_and_root_mfa(opa: OpaEvaluator) -> None:
    out = run(IAM, gold("aws_credential_report.csv"), "cloud_account", ACCOUNT)
    assert out.warnings == [
        "OUT_OF_SCOPE_RECORDS_DROPPED:1",
        "ADMIN_MEMBERSHIP_NOT_IN_CREDENTIAL_REPORT",
    ]
    assert "guest" not in str(out.raw)
    assert judged(opa, IAM, out) == {
        ("<root_account>", "admin_requires_mfa"): "FAIL",
        ("<root_account>", "access_keys_rotated"): "PASS",
        ("<root_account>", "no_stale_accounts"): "PASS",
        ("ops.alice", "access_keys_rotated"): "PASS",
        ("ops.alice", "no_stale_accounts"): "PASS",
        ("ci-legacy", "access_keys_rotated"): "FAIL",  # active key, 532 days old
        ("ci-legacy", "no_stale_accounts"): "PASS",
        ("old.bob", "access_keys_rotated"): "PASS",  # the old key is inactive
        ("old.bob", "no_stale_accounts"): "FAIL",
    }


def test_credential_report_without_its_columns_is_refused() -> None:
    out = run(IAM, "user,arn\nx,arn:aws:iam::123456789012:user/x\n", "cloud_account", ACCOUNT)
    assert out.status == "FAILED" and out.errors == ["UNSUPPORTED_FORMAT"]


def test_every_emitted_rule_exists_in_the_pack_and_applies_to_its_resource_type() -> None:
    assert PACK is not None
    cases: list[tuple[ImportAdapter, str, str, str]] = [
        (FW, "aws_security_groups.json", "cloud_account", ACCOUNT), (FW, "iptables.rules", "host", "h"),
        (K8S, "kubescape.json", "asset_group", "prod-cluster-1"), (DIR, "ad_users.csv", "asset_group", "corp.example.com"),
        (DIR, "directory.ldif", "asset_group", "corp.example.com"), (IAM, "aws_credential_report.csv", "cloud_account", ACCOUNT),
    ]  # fmt: skip
    seen: set[str] = set()
    for a, f, kind, sel in cases:
        b = a.normalize(run(a, gold(f), kind, sel), run_id="r", task_id="k")
        attrs: dict[str, Any] = {x.asset_id: x.attrs for x in b.assets}
        for o in b.observations:
            rule = PACK.rule(o.rule_id)
            assert rule is not None and rule.applies(attrs[o.asset_id]), (
                o.rule_id,
                attrs[o.asset_id],
            )
            seen.add(o.rule_id)
    assert {
        r.rule_id
        for r in PACK.rules
        if r.category in {"network_exposure", "identity", "kubernetes_rbac"}
    } == seen
