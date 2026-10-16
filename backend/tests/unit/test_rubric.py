from __future__ import annotations

import pytest
from pydantic import ValidationError

from aisw.contracts.analysis import RiskAssessment
from aisw.policy.rubric import TierOrder, assess, builtin, exposure_for, normalize_criticality
from tests.unit.analysis_support import factors

R = builtin()


def test_complete_assessment_uses_documented_arithmetic() -> None:
    a = assess("f1", factors("CRITICAL", "critical", "VERIFIED"), R)  # 4+3+2 = 9
    assert (a.basis, a.tier, a.rubric_version) == ("COMPLETE", "P0", "1.0.0")
    assert "= 9 -> P0" in a.rationale


@pytest.mark.parametrize(
    ("sev", "crit", "exp", "tier"),
    [
        ("HIGH", "high", "VERIFIED", "P1"),  # 3+2+2 = 7
        ("HIGH", "high", "UNKNOWN", "P2"),  # 3+2+0 = 5
        ("MEDIUM", "medium", "CONFIGURED", "P2"),  # 2+1+1 = 4
        ("LOW", "low", "UNKNOWN", "P3"),  # 1
        ("CRITICAL", "high", "VERIFIED", "P0"),  # 8 is the boundary
        ("CRITICAL", "high", "CONFIGURED", "P1"),  # 7
        ("HIGH", "medium", "VERIFIED", "P1"),  # 6 is the P1 boundary
        ("MEDIUM", "low", "VERIFIED", "P2"),  # 4 is the P2 boundary
        ("LOW", "low", "VERIFIED", "P3"),  # 3
        ("CRITICAL", "critical", "UNKNOWN", "P1"),  # 7: unverified exposure keeps it below P0
    ],
)
def test_thresholds(sev: str, crit: str, exp: str, tier: str) -> None:
    assert assess("f", factors(sev, crit, exp), R).tier == tier


def test_unknown_criticality_never_fabricates_a_tier() -> None:
    a = assess("f", factors("CRITICAL", None, "VERIFIED"), R)
    assert a.tier is None
    assert a.basis == "NEEDS_POLICY_REVIEW"
    assert a.provisional_tier == "P1"  # severity-only indication, labelled as such
    assert any("criticality" in m for m in a.missing_evidence)


@pytest.mark.parametrize("raw", ["tier-1", "", "  ", "HIGHEST", "important", None])
def test_free_text_criticality_is_unknown(raw: str | None) -> None:
    assert normalize_criticality(raw, R) is None


def test_known_labels_are_case_insensitive() -> None:
    assert normalize_criticality(" High ", R) == "high"


def test_unknown_exposure_and_stale_evidence_are_disclosed() -> None:
    a = assess("f", factors(exposure="UNKNOWN", fresh=False), R)
    assert len(a.missing_evidence) == 2


def test_exposure_comes_from_category_table_not_guesswork() -> None:
    assert exposure_for("network_exposure", R) == "VERIFIED"
    assert exposure_for("cloud_posture", R) == "CONFIGURED"
    assert exposure_for("host_configuration", R) == "UNKNOWN"
    assert exposure_for("something_new", R) == "UNKNOWN"


def test_unknown_severity_is_rejected() -> None:
    with pytest.raises(ValueError, match="not in rubric"):
        assess("f", factors("EXTREME", "high"), R)


def test_assessment_is_deterministic() -> None:
    assert assess("f", factors(), R) == assess("f", factors(), R)


def test_contract_refuses_a_tier_without_criticality() -> None:
    good = assess("f", factors(), R)
    with pytest.raises(ValidationError):
        RiskAssessment(**{**good.model_dump(), "factors": factors(criticality=None).model_dump()})
    with pytest.raises(ValidationError):
        RiskAssessment(**{**good.model_dump(), "basis": "NEEDS_POLICY_REVIEW"})
    with pytest.raises(ValidationError):
        RiskAssessment(**{**good.model_dump(), "tier": None})


def test_worst_tier_ordering() -> None:
    assert TierOrder.worst(["P3", "P1", "P2"]) == "P1"
