"""The curated framework-mapping catalog is well formed and agrees with the packs (ADR-032)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from aisw.policy import mappings
from aisw.policy.engine import PackRegistry

FRAMEWORKS = {"NIST-CSF", "CIS-Controls", "NIST-SP-800-53", "ISO-IEC-27001", "MITRE-ATTACK"}
UNMAPPED = {"US-4"}  # "the endpoint answered" is a reachability precondition, not a control


def raw() -> dict[str, Any]:
    return dict(json.loads(mappings.CATALOG_PATH.read_text(encoding="utf-8")))


def pack_controls() -> dict[str, set[str]]:
    reg = PackRegistry.builtin()
    out: dict[str, set[str]] = {}
    for k in reg.keys():  # noqa: SIM118 - PackRegistry.keys() is not a dict
        pack = reg.get(k)
        assert pack is not None
        out[k] = {r.control_id for r in pack.rules}
    return out


def test_catalog_covers_every_framework_and_every_pack_control() -> None:
    cat = mappings.builtin()
    assert {f.framework for f in cat.frameworks} == FRAMEWORKS
    assert {m.framework for m in cat.mappings} == FRAMEWORKS
    controls = set().union(*pack_controls().values())
    mapped = {m.pack_control for m in cat.mappings}
    assert mapped == controls - UNMAPPED  # and no mapping for a control no pack has
    for ctrl in controls - UNMAPPED:
        assert {m.framework for m in cat.for_control(ctrl)} >= {"NIST-CSF", "NIST-SP-800-53"}


def test_pack_embedded_mappings_are_all_in_the_catalog() -> None:
    reg = PackRegistry.builtin()
    pack = reg.get("config-baseline:1.0.0")
    assert pack is not None
    cat = mappings.builtin()
    for rule in pack.rules:
        keys = {m.key for m in cat.for_control(rule.control_id)}
        for m in rule.mappings:
            assert f"{rule.control_id}|{m.framework}|{m.control_id}" in keys
            assert cat.framework(m.framework).version == m.version


def test_every_control_title_is_used_and_lookups_work() -> None:
    cat = mappings.builtin()
    used = {(m.framework, m.control_id) for m in cat.mappings}
    assert used == {(fw, c) for fw, titles in cat.controls.items() for c in titles}
    m = cat.get("CB-NET-1|NIST-SP-800-53|SC-7")
    assert m is not None and cat.title(m) == "Boundary protection"
    assert cat.get("CB-NET-1|NIST-SP-800-53|SC-99") is None


@pytest.mark.parametrize(
    ("framework", "bad_id"),
    [("NIST-CSF", "PR.AC-1"), ("CIS-Controls", "4"), ("NIST-SP-800-53", "SC7"),
     ("ISO-IEC-27001", "A.9.1"), ("MITRE-ATTACK", "T190")],
)  # fmt: skip
def test_control_ids_must_match_the_framework_format(framework: str, bad_id: str) -> None:
    d = raw()
    d["controls"][framework][bad_id] = "x"
    d["mappings"].append({"pack_control": "FB-1", "framework": framework, "control_id": bad_id})
    with pytest.raises(ValidationError, match="format"):
        mappings.Catalog.model_validate(d)


def test_catalog_refuses_duplicates_and_unknown_controls() -> None:
    d = raw()
    d["mappings"].append(dict(d["mappings"][0]))
    with pytest.raises(ValidationError, match="duplicate"):
        mappings.Catalog.model_validate(d)
    d = raw()
    d["mappings"].append(
        {"pack_control": "FB-1", "framework": "NIST-CSF", "control_id": "PR.AA-02"}
    )
    with pytest.raises(ValidationError, match="unknown framework control"):
        mappings.Catalog.model_validate(d)
    d = raw()
    d["controls"].pop("MITRE-ATTACK")
    with pytest.raises(ValidationError, match="same unique frameworks"):
        mappings.Catalog.model_validate(d)
