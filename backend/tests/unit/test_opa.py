"""OPA engine (ADR-031): agrees with the Python engine on every check, refuses a server running
other policy, fails closed when unreachable, and runs the config-baseline domain rules."""

from __future__ import annotations

import json
import random
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from aisw.contracts.enums import PolicyOutcome as O
from aisw.core.config import Settings
from aisw.policy.engine import PackRegistry, PolicyPack, PythonRuleEvaluator
from aisw.policy.opa import OpaClient, OpaError, OpaEvaluator, bundle_hash, rego_sources
from tests.opa_server import opa_server

SCALARS: list[Any] = [None, True, False, 0, 1, 1.0, 12, 12.5, -3, "a", "b", "", "no", "yes"]


def value(rng: random.Random, depth: int = 0) -> Any:
    kind = rng.randrange(4 if depth < 2 else 1)
    if kind == 0:
        return rng.choice(SCALARS)
    if kind == 1:
        return [value(rng, depth + 1) for _ in range(rng.randrange(4))]
    if kind == 2:
        return {k: value(rng, depth + 1) for k in rng.sample(["a", "b", "c"], rng.randrange(3))}
    return rng.choice([3, 12.0, "a"])


def case(rng: random.Random) -> tuple[dict[str, Any], Any, dict[str, Any]]:
    op = rng.choice(["equals", "gte", "lte", "in", "disjoint"])
    if op in {"gte", "lte"}:
        expected: Any = rng.choice([0, 5, 12, 12.5, -1])
    elif op in {"in", "disjoint"}:
        expected = [value(rng, 1) for _ in range(rng.randrange(1, 4))]
    else:
        expected = value(rng)
    applies = rng.choice(
        [{}, {"os_family": ["linux"]}, {"os_family": ["linux", "None"], "tier": ["1"]}]
    )
    attrs: dict[str, Any] = rng.choice([{}, {"os_family": "linux"}, {"os_family": "windows", "tier": "1"},
                        {"os_family": None, "tier": 1}])  # fmt: skip
    r: dict[str, Any] = {"rule_id": "r", "control_id": "C", "title": "t", "category": "c", "severity": "LOW",
         "applies_to": applies, "check": {"op": op, "value": expected}}  # fmt: skip
    return r, value(rng), attrs


def test_engines_agree_on_generated_checks(opa_url: str) -> None:
    rng = random.Random(20261016)  # noqa: S311 - a fixed seed keeps the cases reproducible
    py, opa = PythonRuleEvaluator(), OpaEvaluator(OpaClient(opa_url))
    base = PackRegistry.builtin().get("fixture-baseline:1.0.0")
    assert base is not None
    seen: set[O | None] = set()
    for _ in range(400):
        r, observed, attrs = case(rng)
        pack = PolicyPack.model_validate({**base.model_dump(mode="json"), "rules": [r]})
        a = py.evaluate_observation(pack, rule_id="r", value=observed, attrs=attrs)
        b = opa.evaluate_observation(pack, rule_id="r", value=observed, attrs=attrs)
        assert a is b, (r, observed, attrs)
        assert [x.rule_id for x in py.applicable_rules(pack, attrs)] == [
            x.rule_id for x in opa.applicable_rules(pack, attrs)
        ]
        seen.add(a)
    assert {O.PASS, O.FAIL, O.UNKNOWN, O.ERROR, None} <= seen  # the generator reaches every outcome


def test_server_running_other_policy_is_refused(tmp_path: Path) -> None:
    for name, text in rego_sources().items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    (tmp_path / "policy.rego").write_text(
        (tmp_path / "policy.rego").read_text() + '\nbackdoor := "PASS"\n'
    )
    with opa_server(tmp_path) as url, pytest.raises(OpaError, match="refusing to evaluate"):
        OpaEvaluator(OpaClient(url))


def test_packaged_sources_exclude_tests_and_hash_matches_server(opa_url: str) -> None:
    names = set(rego_sources())
    assert "policy.rego" in names and "domains/iam.rego" in names
    assert not any(n.endswith("_test.rego") for n in names)
    assert OpaClient(opa_url).policies_hash() == bundle_hash()


def test_unreachable_opa_fails_closed() -> None:
    def down(req: urllib.request.Request, timeout: float, max_bytes: int) -> bytes:
        raise OpaError("connection refused")

    ev = OpaEvaluator(OpaClient("http://127.0.0.1:9", fetch=down), verify=False)
    pack = PackRegistry.builtin().get("fixture-baseline:1.0.0")
    assert pack is not None
    with pytest.raises(OpaError):
        ev.evaluate_observation(pack, rule_id="ssh.permit_root_login", value="no",
                                attrs={"os_family": "linux"})  # fmt: skip
    with pytest.raises(OpaError):
        ev.applicable_rules(pack, {"os_family": "linux"})


def test_non_json_values_are_errors_not_guesses(opa_url: str) -> None:
    ev = OpaEvaluator(OpaClient(opa_url))
    pack = PackRegistry.builtin().get("fixture-baseline:1.0.0")
    assert pack is not None
    r = next(x for x in pack.rules if x.check.op in {"gte", "lte"})
    assert ev.evaluate_observation(pack, rule_id=r.rule_id, value=float("nan"), attrs={}) is O.ERROR


SAMPLES: list[tuple[str, str, Any, O]] = [
    ("network.no_admin_ports_from_internet", "firewall_rule",
     {"direction": "ingress", "action": "allow", "sources": ["0.0.0.0/0"], "ports": [3389]}, O.FAIL),
    ("network.default_deny", "firewall_policy", {"default_action": "deny"}, O.PASS),
    ("storage.not_public", "storage_bucket", {"public_access": True}, O.FAIL),
    ("logging.retention_sufficient", "log_config", {"retention_days": 400}, O.PASS),
    ("logging.retention_sufficient", "log_config", {"retention_days": 90}, O.FAIL),  # min 365
    ("logging.tls_minimum", "endpoint", {"tls_min_version": "1.1"}, O.FAIL),
    ("iam.admin_requires_mfa", "identity", {"admin": True, "mfa_enabled": False}, O.FAIL),
    ("iam.admin_requires_mfa", "identity", {"admin": False}, O.NOT_APPLICABLE),
    ("iam.access_keys_rotated", "identity", {"access_keys": [{"active": True, "age_days": 91}]}, O.FAIL),
    ("lifecycle.supported", "host", {"eol_date": "2024-06-30", "as_of": "2026-10-16"}, O.FAIL),
    ("hardening.ssh_root_login_disabled", "host", {"ssh_permit_root_login": "no"}, O.PASS),
    ("k8s_rbac.no_wildcard_roles", "k8s_role", {"kind": "ClusterRole", "rules": [{"verbs": ["*"], "resources": ["*"]}]}, O.FAIL),
    ("storage.encrypted_at_rest", "storage_bucket", {}, O.UNKNOWN),  # facts missing
]  # fmt: skip


@pytest.mark.parametrize(("rule_id", "rtype", "facts", "outcome"), SAMPLES)
def test_config_baseline_domain_rules(
    opa_url: str, rule_id: str, rtype: str, facts: Any, outcome: O
) -> None:
    pack = PackRegistry.builtin().get("config-baseline:1.0.0")
    assert pack is not None and pack.needs_opa
    ev = OpaEvaluator(OpaClient(opa_url))
    attrs = {"resource_type": rtype}
    assert ev.evaluate_observation(pack, rule_id=rule_id, value=facts, attrs=attrs) is outcome
    assert (
        PythonRuleEvaluator().evaluate_observation(pack, rule_id=rule_id, value=facts, attrs=attrs)
        is O.ERROR
    )  # never a guessed outcome without the engine
    assert ev.evaluate_observation(pack, rule_id=rule_id, value=facts,
                                   attrs={"resource_type": "printer"}) is None  # fmt: skip


def test_config_baseline_rules_all_resolve_to_domain_rules() -> None:
    pack = PackRegistry.builtin().get("config-baseline:1.0.0")
    assert pack is not None
    text = "\n".join(rego_sources().values())
    for r in pack.rules:
        domain, name = r.check.value["rule"].split(".")
        assert f"package aisw.domains.{domain}" in text and f"\n{name} :=" in text, r.rule_id
        assert r.mappings and all(m.mapping_status == "NEEDS_REVIEW" for m in r.mappings)
        assert {m.framework for m in r.mappings} == {
            "NIST-SP-800-53",
            "ISO-IEC-27001",
            "CIS-Controls",
        }


@pytest.mark.parametrize(
    ("url", "ok"),
    [("http://127.0.0.1:8181", True), ("http://opa:8181", True), ("https://opa.internal:8181", True),
     ("http://opa.example.com:8181", False), ("http://u:p@127.0.0.1:8181", False),
     ("http://127.0.0.1:8181/v1/data", False)],
)  # fmt: skip
def test_opa_url_validation(url: str, ok: bool) -> None:
    if ok:
        assert Settings(env="test", policy_engine="opa", opa_url=url).opa_url == url
    else:
        with pytest.raises(ValueError, match="opa_url"):
            Settings(env="test", policy_engine="opa", opa_url=url)
    with pytest.raises(ValueError, match="requires opa_url"):
        Settings(env="test", policy_engine="opa")


def test_opa_is_an_egress_destination_for_both_roles() -> None:
    from aisw.core.egress import destinations

    dests = destinations(Settings(env="test", policy_engine="opa", opa_url="http://opa:8181"))
    assert [(d.purpose, d.host, d.ports, d.roles) for d in dests] == [
        ("policy-engine", "opa", (8181,), ("api", "worker"))
    ]
    loop = destinations(Settings(env="test", policy_engine="opa", opa_url="http://127.0.0.1:8181"))
    assert loop == []  # loopback is always allowed


def test_rule_docs_sent_to_opa_carry_no_titles_or_mappings(opa_url: str) -> None:
    sent: list[dict[str, Any]] = []
    client = OpaClient(opa_url)
    real = client._fetch

    def spy(req: urllib.request.Request, timeout: float, max_bytes: int) -> bytes:
        if req.data:
            sent.append(json.loads(req.data))  # type: ignore[arg-type]
        return real(req, timeout, max_bytes)

    client._fetch = spy
    pack = PackRegistry.builtin().get("config-baseline:1.0.0")
    assert pack is not None
    OpaEvaluator(client).evaluate_observation(
        pack, rule_id="storage.not_public", value={"public_access": False},
        attrs={"resource_type": "storage_bucket"},
    )  # fmt: skip
    assert set(sent[0]["input"]["rule"]) == {"rule_id", "applies_to", "check"}
