from __future__ import annotations

from typing import Any

import pytest

from aisw.contracts.enums import PolicyOutcome as O
from aisw.policy.engine import PackRegistry, PackRule, PolicyPack, PythonRuleEvaluator
from aisw.policy.results import dedupe_key, finding_id, rollup


def _load() -> PolicyPack:
    pack = PackRegistry.builtin().get("fixture-baseline:1.0.0")
    assert pack is not None
    return pack


PACK = _load()
EV = PythonRuleEvaluator()


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
    ],
)  # fmt: skip
def test_rule_semantics(op: str, expected: Any, observed: Any, outcome: O) -> None:
    assert rule(op, expected).evaluate_value(observed) is outcome


def test_applicability_requires_proof_of_the_attribute() -> None:
    r = rule("equals", "no", {"os_family": ["linux"]})
    assert r.applies({"os_family": "linux"})
    assert not r.applies({"os_family": "windows"})
    assert not r.applies({})  # unknown OS: the rule does not silently apply... or pass
    assert not r.applies({"os_family": None})


def test_evaluator_unknown_or_inapplicable_rules_return_none() -> None:
    assert EV.evaluate_observation(PACK, rule_id="nope", value=1, attrs={}) is None
    assert (
        EV.evaluate_observation(
            PACK, rule_id="ssh.permit_root_login", value="no", attrs={"os_family": "windows"}
        )
        is None
    )
    assert (
        EV.evaluate_observation(
            PACK, rule_id="ssh.permit_root_login", value="no", attrs={"os_family": "linux"}
        )
        is O.PASS
    )
    assert (
        EV.evaluate_observation(
            PACK,
            rule_id="ssh.permit_root_login",
            value="no; rm -rf /",
            attrs={"os_family": "linux"},
        )
        is O.FAIL
    )


def test_applicable_rules_by_os() -> None:
    linux = {r.rule_id for r in EV.applicable_rules(PACK, {"os_family": "linux"})}
    win = {r.rule_id for r in EV.applicable_rules(PACK, {"os_family": "windows"})}
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
        "fixture-baseline:1.0.0",
        "import-baseline:1.0.0",
        "url-smoke-baseline:1.0.0",
    ]
