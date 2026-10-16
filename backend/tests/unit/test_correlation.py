from __future__ import annotations

import pytest
from pydantic import ValidationError

from aisw.agents.correlation import build_scenarios, scenario_id
from aisw.contracts.analysis import ChainLink, CorrelationScenario, RiskAssessment
from aisw.contracts.enums import EdgeBasis
from aisw.policy.rubric import assess, builtin
from tests.unit.analysis_support import factors, finding

R = builtin()


def risks(*specs: tuple[str, str | None]) -> dict[str, RiskAssessment]:
    return {fid: assess(fid, factors(criticality=c), R) for fid, c in specs}


def test_single_finding_is_not_a_scenario() -> None:
    assert build_scenarios([finding("f1")], risks(("f1", "high"))) == []


def test_two_findings_on_one_asset_make_an_observed_only_scenario() -> None:
    fs = [finding("f2"), finding("f1")]
    out = build_scenarios(fs, risks(("f1", "high"), ("f2", "low")))
    assert len(out) == 1
    s = out[0]
    assert s.finding_ids == ["f1", "f2"]
    assert all(c.basis is EdgeBasis.OBSERVED for c in s.chain)
    assert {c.evidence_ref for c in s.chain} == {"ev-f1", "ev-f2"}
    assert s.basis == "COMPLETE"
    assert s.tier == "P1"  # worst of 3+2+2=7 and 3+0+2=5
    assert s.assumptions and s.validation_steps


def test_scenario_is_not_complete_when_any_criticality_is_unknown() -> None:
    fs = [finding("f1"), finding("f2")]
    s = build_scenarios(fs, risks(("f1", "high"), ("f2", None)))[0]
    assert (s.basis, s.tier) == ("NEEDS_POLICY_REVIEW", None)
    assert any("criticality" in m for m in s.missing_evidence)


def test_scenarios_do_not_span_assets() -> None:
    fs = [finding("f1", asset="a"), finding("f2", asset="b")]
    assert build_scenarios(fs, risks(("f1", "high"), ("f2", "high"))) == []


def test_scenario_id_is_stable_and_order_independent() -> None:
    assert scenario_id(["b", "a"]) == scenario_id(["a", "b"])
    assert scenario_id(["a", "b"]) != scenario_id(["a", "c"])


def test_confidence_drops_with_stale_evidence() -> None:
    fs = [finding("f1"), finding("f2")]
    rs = {f.finding_id: assess(f.finding_id, factors(fresh=False), R) for f in fs}
    assert build_scenarios(fs, rs)[0].confidence.value == "LOW"


def test_contract_rejects_inferred_link_without_note_and_mismatched_chain() -> None:
    with pytest.raises(ValidationError):
        ChainLink(finding_id="f1", evidence_ref="e", basis=EdgeBasis.INFERRED)
    s = build_scenarios([finding("f1"), finding("f2")], risks(("f1", "high"), ("f2", "high")))[0]
    with pytest.raises(ValidationError):
        CorrelationScenario(**{**s.model_dump(), "finding_ids": ["f1", "f3"]})
    with pytest.raises(ValidationError):
        CorrelationScenario(**{**s.model_dump(), "tier": None})
