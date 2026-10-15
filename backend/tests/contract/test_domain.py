from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from aisw.contracts.assurance import AssuranceResult, ReportBundle
from aisw.contracts.domain import (
    Asset,
    ControlAssessment,
    CoverageLedger,
    Finding,
    Recommendation,
    Relationship,
    RiskException,
)

T = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
H = "sha256:" + "c" * 64


def finding(**over: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "finding_id": "f-1", "stable_dedupe_key": "k", "tenant_id": "tenant-a",
        "project_id": "proj-1", "run_id": "run-1", "title": "t", "category": "network",
        "severity": "HIGH", "severity_source": "prowler", "confidence": "MEDIUM",
        "outcome": "FAIL", "affected_assets": ["a-1"],
        "evidence_refs": ["evidence://tenant-a/proj-1/run-1/x"], "policy_version": "p-1",
        "first_observed": T.isoformat(), "last_observed": T.isoformat(),
    }  # fmt: skip
    d.update(over)
    return d


def test_finding_valid_and_dimensions_separate() -> None:
    f = Finding.model_validate(finding())
    assert f.business_risk is None  # never fabricated without an approved rubric
    assert f.lifecycle.value == "NEW" and f.outcome.value == "FAIL"


@pytest.mark.parametrize(
    "over",
    [
        {"evidence_refs": []},  # untraceable
        {"affected_assets": []},
        {"outcome": "PASS"},  # PASS is not a finding
        {"status": "OPEN"},  # legacy conflated field (gap G6)
        {"last_observed": (T - timedelta(days=1)).isoformat()},
    ],
)
def test_invalid_findings(over: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate(finding(**over))


@pytest.mark.security
def test_pass_requires_evidence_missing_is_never_pass() -> None:
    base: dict[str, Any] = {
        "tenant_id": "t", "run_id": "r", "framework": "CIS", "version": "8.1",
        "control_id": "1.1", "applicability": "yes", "outcome": "PASS", "policy_version": "p",
    }  # fmt: skip
    with pytest.raises(ValidationError):
        ControlAssessment.model_validate(base)
    ControlAssessment.model_validate({**base, "outcome": "UNKNOWN"})
    ControlAssessment.model_validate({**base, "evidence_refs": ["evidence://t/p/r/x"]})


def rel(**over: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "relationship_id": "r-1", "tenant_id": "t", "source_asset_id": "a", "target_asset_id": "b",
        "relationship_type": "connects_to", "basis": "OBSERVED", "confidence": "HIGH",
        "evidence_ref": "evidence://t/p/r/e", "observed_at": T.isoformat(),
    }  # fmt: skip
    d.update(over)
    return d


def test_relationship_basis_rules() -> None:
    Relationship.model_validate(rel())
    with pytest.raises(ValidationError):
        Relationship.model_validate(rel(evidence_ref=None))
    with pytest.raises(ValidationError):  # inferred must say how to validate
        Relationship.model_validate(rel(basis="INFERRED", evidence_ref=None))
    Relationship.model_validate(
        rel(basis="INFERRED", evidence_ref=None, validation_steps=["confirm routing"])
    )


def test_asset_provenance_rules() -> None:
    base: dict[str, Any] = {
        "asset_id": "a", "tenant_id": "t", "project_id": "p", "asset_type": "host",
        "native_ids": {"cmdb": "123"}, "first_seen": T.isoformat(), "last_seen": T.isoformat(),
        "match_confidence": "HIGH",
    }  # fmt: skip
    assert Asset.model_validate(base).owner is None  # unknown stays unknown
    with pytest.raises(ValidationError):
        Asset.model_validate({**base, "owner": "team-x"})  # owner needs a source
    with pytest.raises(ValidationError):
        Asset.model_validate({**base, "native_ids": {}})


def ledger(**over: Any) -> CoverageLedger:
    d: dict[str, Any] = {
        "tenant_id": "t", "run_id": "r", "segment": "acct-1/us-east-1", "expected_count": 10,
        "discovered_count": 10, "reconciled_count": 10, "excluded_count": 0,
        "unsupported_count": 0, "unknown_count": 0, "source_ok": True,
    }  # fmt: skip
    d.update(over)
    return CoverageLedger.model_validate(d)


@pytest.mark.security
def test_coverage_completeness_is_derived_not_asserted() -> None:
    assert ledger().is_complete
    assert not ledger(unknown_count=1).is_complete
    assert not ledger(unsupported_count=2).is_complete
    assert not ledger(reconciled_count=8).is_complete  # missing expected assets
    assert not ledger(source_ok=False, reasons=["collector offline"]).is_complete
    with pytest.raises(ValidationError):
        ledger(source_ok=False)  # failed source must state why
    with pytest.raises(ValidationError):
        ledger(reconciled_count=11)
    with pytest.raises(ValidationError):
        CoverageLedger.model_validate({**ledger().model_dump(mode="json"), "is_complete": True})


def test_recommendation_traceability_and_estimates() -> None:
    base: dict[str, Any] = {"recommendation_id": "r", "tenant_id": "t", "action": "restrict",
                            "finding_refs": ["f-1"]}  # fmt: skip
    assert Recommendation.model_validate(base).effort.value is None  # UNKNOWN by default
    with pytest.raises(ValidationError):
        Recommendation.model_validate({**base, "finding_refs": []})
    with pytest.raises(ValidationError):
        Recommendation.model_validate({**base, "effort": {"value": "3 weeks"}})  # no basis
    Recommendation.model_validate({**base, "effort": {"value": "3 weeks", "basis": "owner est."}})


def test_exception_expiry_and_separation() -> None:
    d: dict[str, Any] = {
        "exception_id": "e", "tenant_id": "t", "finding_ref": "f", "rationale": "r",
        "owner": "o", "approver": "a", "approved_at": T.isoformat(),
        "expires_at": (T + timedelta(days=30)).isoformat(),
    }  # fmt: skip
    RiskException.model_validate(d)
    with pytest.raises(ValidationError):
        RiskException.model_validate({**d, "expires_at": T.isoformat()})
    with pytest.raises(ValidationError):
        RiskException.model_validate({**d, "approver": "o"})


@pytest.mark.security
def test_assurance_verdict_consistency() -> None:
    d: dict[str, Any] = {
        "tenant_id": "t", "run_id": "r", "item_ref": "finding:f-1", "verdict": "ACCEPT",
        "validation_version": "1.0.0", "validated_at": T.isoformat(),
    }  # fmt: skip
    AssuranceResult.model_validate(d)
    with pytest.raises(ValidationError):
        AssuranceResult.model_validate({**d, "defect_codes": ["MISSING_EVIDENCE"]})
    with pytest.raises(ValidationError):
        AssuranceResult.model_validate({**d, "stale_refs": ["evidence://t/p/r/old"]})
    with pytest.raises(ValidationError):
        AssuranceResult.model_validate({**d, "verdict": "REJECT"})
    AssuranceResult.model_validate({**d, "verdict": "REJECT", "defect_codes": ["BROKEN_HASH"]})


def test_report_partial_banner_required() -> None:
    d: dict[str, Any] = {
        "report_id": "rep", "tenant_id": "t", "project_id": "p", "run_id": "r",
        "scope_manifest_hash": H, "policy_versions": ["p-1"], "coverage_complete": False,
        "finding_counts": {"FAIL": 1}, "evidence_manifest_hash": H, "report_hash": H,
        "generated_at": T.isoformat(),
    }  # fmt: skip
    with pytest.raises(ValidationError):
        ReportBundle.model_validate(d)
    ReportBundle.model_validate({**d, "limitations": ["2 sources unavailable"]})
