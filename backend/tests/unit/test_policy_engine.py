from __future__ import annotations

from typing import Any

import pytest

from aisw.contracts.enums import PolicyOutcome as O
from aisw.policy.engine import (
    PackRegistry,
    PackRule,
    PolicyEvaluator,
    PolicyPack,
    PythonRuleEvaluator,
)
from aisw.policy.opa import OpaClient, OpaEvaluator
from aisw.policy.results import dedupe_key, finding_id, rollup


def _load() -> PolicyPack:
    pack = PackRegistry.builtin().get("fixture-baseline:1.0.0")
    assert pack is not None
    return pack


PACK = _load()


@pytest.fixture(params=["python", "opa"])
def ev(request: pytest.FixtureRequest) -> PolicyEvaluator:
    """Both engines must pass the same suite (ADR-003)."""
    if request.param == "python":
        return PythonRuleEvaluator()
    return OpaEvaluator(OpaClient(request.getfixturevalue("opa_url")))


def one_rule_pack(r: PackRule) -> PolicyPack:
    return PolicyPack.model_validate(
        {**PACK.model_dump(mode="json"), "rules": [r.model_dump(mode="json")]}
    )


def rule(op: str, value: Any, applies: dict[str, list[str]] | None = None) -> PackRule:
    return PackRule.model_validate(
        {
            "rule_id": "r",
            "control_id": "C",
            "title": "t",
            "category": "c",
            "severity": "LOW",
            "applies_to": applies or {},
            "check": {"op": op, "value": value},
        }  # fmt: skip
    )


@pytest.mark.parametrize(
    ("op", "expected", "observed", "outcome"),
    [
        ("equals", "no", "no", O.PASS), ("equals", "no", "yes", O.FAIL),
        ("equals", True, True, O.PASS), ("equals", True, False, O.FAIL),
        ("gte", 12, 12, O.PASS), ("gte", 12, 11, O.FAIL), ("gte", 12, 14.5, O.PASS),
        ("lte", 5, 5, O.PASS), ("lte", 5, 6, O.FAIL),
        ("in", ["a", "b"], "a", O.PASS), ("in", ["a", "b"], "c", O.FAIL),
        ("equals", "no", None, O.UNKNOWN),  # missing evidence is never pass or fail
        ("gte", 12, None, O.UNKNOWN),
        ("gte", 12, "fourteen", O.ERROR),  # check cannot execute on this type
        ("gte", 12, True, O.ERROR),  # booleans are not numbers
        ("lte", 5, [1], O.ERROR),
        ("equals", True, 1, O.FAIL),  # JSON equality: true is not 1
        ("equals", 12, 12.0, O.PASS),
        ("in", [True], 1, O.FAIL),
        ("equals", {"a": [1, 2]}, {"a": [1, 2]}, O.PASS),
        ("disjoint", ["telnet"], ["ssh"], O.PASS), ("disjoint", ["telnet"], ["telnet"], O.FAIL),
        ("disjoint", ["telnet"], "telnet", O.ERROR),
        ("rego", {"rule": "storage.not_public"}, {"public_access": True}, None),  # engine-specific
    ],
)  # fmt: skip
def test_rule_semantics(
    ev: PolicyEvaluator, op: str, expected: Any, observed: Any, outcome: O | None
) -> None:
    r = rule(op, expected)
    got = ev.evaluate_observation(one_rule_pack(r), rule_id="r", value=observed, attrs={})
    if op == "rego":  # only OPA runs domain rules; the Python engine refuses rather than guesses
        assert got is (O.FAIL if ev.runs_rego else O.ERROR)
    else:
        assert got is outcome
        assert r.evaluate_value(observed) is outcome


@pytest.mark.parametrize(
    ("op", "value", "error"),
    [("gte", "12", "numeric"), ("gte", True, "numeric"), ("in", "ab", "list"),
     ("rego", "storage.not_public", "rego needs"), ("rego", {"rule": "../x"}, "rego needs"),
     ("rego", {"rule": "a.b", "extra": 1}, "rego needs")],
)  # fmt: skip
def test_check_values_are_typed_at_load(op: str, value: Any, error: str) -> None:
    with pytest.raises(ValueError, match=error):
        rule(op, value)


def test_applicability_requires_proof_of_the_attribute() -> None:
    r = rule("equals", "no", {"os_family": ["linux"]})
    assert r.applies({"os_family": "linux"})
    assert not r.applies({"os_family": "windows"})
    assert not r.applies({})  # unknown OS: the rule does not silently apply... or pass
    assert not r.applies({"os_family": None})


def test_evaluator_unknown_or_inapplicable_rules_return_none(ev: PolicyEvaluator) -> None:
    assert ev.evaluate_observation(PACK, rule_id="nope", value=1, attrs={}) is None
    assert (
        ev.evaluate_observation(
            PACK, rule_id="ssh.permit_root_login", value="no", attrs={"os_family": "windows"}
        )
        is None
    )
    assert (
        ev.evaluate_observation(
            PACK, rule_id="ssh.permit_root_login", value="no", attrs={"os_family": "linux"}
        )
        is O.PASS
    )
    assert (
        ev.evaluate_observation(
            PACK,
            rule_id="ssh.permit_root_login",
            value="no; rm -rf /",
            attrs={"os_family": "linux"},
        )
        is O.FAIL
    )


def test_applicable_rules_by_os(ev: PolicyEvaluator) -> None:
    linux = {r.rule_id for r in ev.applicable_rules(PACK, {"os_family": "linux"})}
    win = {r.rule_id for r in ev.applicable_rules(PACK, {"os_family": "windows"})}
    assert linux - win == {"ssh.permit_root_login"} and win < linux


@pytest.mark.parametrize(
    ("outcomes", "expected"),
    [
        ([O.PASS, O.PASS], O.PASS),
        ([O.PASS, O.FAIL], O.FAIL),
        ([O.PASS, O.UNKNOWN], O.UNKNOWN),  # one unknown prevents PASS
        ([O.PASS, O.NOT_ASSESSED], O.NOT_ASSESSED),
        ([O.PASS, O.ERROR], O.ERROR),
        ([O.UNKNOWN, O.ERROR, O.NOT_ASSESSED], O.ERROR),
        ([O.FAIL, O.ERROR, O.UNKNOWN], O.FAIL),
        ([], O.NOT_APPLICABLE),
        ([O.NOT_APPLICABLE], O.NOT_APPLICABLE),
        ([O.PASS, O.NOT_APPLICABLE], O.PASS),
    ],
)  # fmt: skip
def test_rollup_precedence_never_upgrades_to_pass(outcomes: list[O], expected: O) -> None:
    assert rollup(outcomes) is expected


def test_pack_identity_hash_and_stable_ids() -> None:
    assert PACK.key == "fixture-baseline:1.0.0" and PACK.control_ids() == {"FB-1", "FB-2", "FB-3"}
    assert PACK.pack_hash.startswith("sha256:")
    changed = PolicyPack.model_validate({**PACK.model_dump(mode="json"), "version": "1.0.1"})
    assert changed.pack_hash != PACK.pack_hash  # any change is a different, separately pinned pack
    assert dedupe_key(PACK, "r", "a") == dedupe_key(PACK, "r", "a") != dedupe_key(PACK, "r", "b")
    assert finding_id(PACK, "r", "a").startswith("f-") and len(finding_id(PACK, "r", "a")) == 22


def test_registry_only_serves_registered_packs() -> None:
    reg = PackRegistry.builtin()
    assert reg.get("fixture-baseline:1.0.0") and reg.get("fixture-baseline:9.9.9") is None
    assert reg.get("../../etc/passwd") is None and reg.keys() == [
        "config-baseline:1.0.0",
        "fixture-baseline:1.0.0",
        "image-baseline:1.0.0",
        "import-baseline:1.0.0",
        "url-smoke-baseline:1.0.0",
    ]
