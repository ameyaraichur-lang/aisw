from __future__ import annotations

from datetime import timedelta

from aisw.agents.architecture import build_recommendations, builtin_catalog
from aisw.agents.assurance import (
    AssuranceContext,
    assess_narrative,
    assess_recommendation,
    assess_risk,
    assess_scenario,
    assess_scenarios,
)
from aisw.agents.correlation import build_scenarios
from aisw.contracts.analysis import ChainLink, CorrelationScenario
from aisw.contracts.domain import Finding, Recommendation
from aisw.contracts.enums import AssuranceVerdict as V
from aisw.contracts.enums import EdgeBasis, RecommendationStatus
from aisw.llm.gateway import NarrativeResult
from aisw.llm.subject import scenario_subject
from aisw.policy.rubric import assess, builtin
from tests.unit.analysis_support import T0, factors, finding

R = builtin()
CAT = builtin_catalog()
CTX = AssuranceContext(
    tenant_id="ten-1", project_id="prj-1", run_id="run-1", policy_version="p-1",
    pack_control_ids=frozenset(), pack_framework="X", now=T0, freshness=timedelta(days=30),
    artifact=lambda _r: None, evidence_ok=lambda _m: True, asset_exists=lambda _a: True,
)  # fmt: skip


def world(crit: str | None = "high") -> tuple[dict[str, Finding], dict[str, V], dict]:  # type: ignore[type-arg]
    fs = {f.finding_id: f for f in (finding("f1"), finding("f2"))}
    risks = {i: assess(i, factors(criticality=crit), R) for i in fs}
    return fs, {i: V.ACCEPT for i in fs}, risks


def scenario(fs, risks) -> CorrelationScenario:  # type: ignore[no-untyped-def]
    return build_scenarios(list(fs.values()), risks)[0]


def rec(fs, risks, **over) -> Recommendation:  # type: ignore[no-untyped-def]
    r = build_recommendations(
        tenant_id="ten-1", findings=list(fs.values()), risks=risks,
        assets={"asset-a": ("team", "high")}, catalog=CAT,
    )[0]  # fmt: skip
    return r.model_copy(update=over)


def test_valid_scenario_and_recommendation_are_accepted() -> None:
    fs, vs, rs = world()
    assert assess_scenario(scenario(fs, rs), fs, vs, rs, CTX).verdict is V.ACCEPT
    assert assess_recommendation(rec(fs, rs), fs, vs, rs, CAT, CTX).verdict is V.ACCEPT


def test_rejected_constituent_rejects_parents() -> None:
    fs, vs, rs = world()
    vs["f2"] = V.REJECT
    a = assess_scenario(scenario(fs, rs), fs, vs, rs, CTX)
    b = assess_recommendation(rec(fs, rs), fs, vs, rs, CAT, CTX)
    assert a.verdict is b.verdict is V.REJECT and "CONSTITUENT_REJECTED" in a.defect_codes


def test_review_constituent_sends_parents_to_review() -> None:
    fs, vs, rs = world()
    vs["f1"] = V.NEEDS_REVIEW
    assert assess_scenario(scenario(fs, rs), fs, vs, rs, CTX).verdict is V.NEEDS_REVIEW
    assert assess_recommendation(rec(fs, rs), fs, vs, rs, CAT, CTX).verdict is V.NEEDS_REVIEW


def test_scenario_defects() -> None:
    fs, vs, rs = world()
    s = scenario(fs, rs)

    def codes(x: CorrelationScenario) -> set[str]:
        return set(assess_scenario(x, fs, vs, rs, CTX).defect_codes)

    assert "SCENARIO_TIER_MISMATCH" in codes(s.model_copy(update={"tier": "P3"}))
    assert "ASSET_MISMATCH" in codes(s.model_copy(update={"asset_id": "asset-other"}))
    bad_chain = [
        ChainLink(finding_id="f1", evidence_ref="ev-nope", basis=EdgeBasis.OBSERVED),
        s.chain[1],
    ]
    assert "CHAIN_EVIDENCE_NOT_IN_FINDING" in codes(s.model_copy(update={"chain": bad_chain}))
    assert "PROHIBITED_EXECUTABLE_CONTENT" in codes(
        s.model_copy(update={"title": "run `rm -rf /`"})
    )
    unknown = s.model_copy(
        update={
            "finding_ids": ["f1", "f9"],
            "chain": [
                s.chain[0],
                ChainLink(finding_id="f9", evidence_ref="e", basis=EdgeBasis.OBSERVED),
            ],
        }
    )
    assert "UNKNOWN_FINDING" in codes(unknown)


def test_inferred_link_needs_review() -> None:
    fs, vs, rs = world()
    s = scenario(fs, rs)
    inferred = ChainLink(
        finding_id="f2", evidence_ref="ev-f2", basis=EdgeBasis.INFERRED, note="assumed"
    )
    r = assess_scenario(s.model_copy(update={"chain": [s.chain[0], inferred]}), fs, vs, rs, CTX)
    assert r.verdict is V.NEEDS_REVIEW


def test_duplicate_scenarios_are_rejected() -> None:
    fs, vs, rs = world()
    s = scenario(fs, rs)
    out = assess_scenarios([s, s], fs, vs, rs, CTX)
    assert [o.verdict for o in out] == [V.ACCEPT, V.REJECT]
    assert "DUPLICATE_SCENARIO" in out[1].defect_codes


def test_unknown_criticality_scenario_has_no_tier_and_is_consistent() -> None:
    fs, vs, rs = world(crit=None)
    s = scenario(fs, rs)
    assert s.tier is None
    assert assess_scenario(s, fs, vs, rs, CTX).verdict is V.ACCEPT  # honest "needs review" basis
    fabricated = s.model_copy(update={"tier": "P1", "basis": "COMPLETE"})
    assert "SCENARIO_TIER_MISMATCH" in assess_scenario(fabricated, fs, vs, rs, CTX).defect_codes


def test_recommendation_defects() -> None:
    fs, vs, rs = world()

    def codes(**over: object) -> set[str]:
        return set(assess_recommendation(rec(fs, rs, **over), fs, vs, rs, CAT, CTX).defect_codes)

    assert "UNKNOWN_CATALOG_PATTERN" in codes(catalog_ref="AC-FAKE-9@1.0.0")
    assert "UNKNOWN_CATALOG_PATTERN" in codes(catalog_ref=None)
    assert "PATTERN_NOT_APPLICABLE" in codes(catalog_ref="AC-NET-1@1.0.0")
    assert "MISSING_ROLLBACK" in codes(rollback=None)
    assert "MISSING_ACCEPTANCE_TEST" in codes(acceptance_test=None)
    assert "MISSING_VALIDATION_STEPS" in codes(validation_steps=[])
    assert "ASSET_NOT_IN_FINDINGS" in codes(affected_assets=["asset-a", "asset-zzz"])
    assert "UNEXPECTED_STATUS" in codes(status=RecommendationStatus.APPROVED_FOR_PLANNING)
    assert "RECOMMENDATION_TIER_MISMATCH" in codes(risk_tier="P3")
    assert "UNKNOWN_FINDING" in codes(finding_refs=["f1", "f404"])
    assert "UNSOURCED_LIFECYCLE_CLAIM" in codes(action="Replace it, it is end of life")
    assert "PROHIBITED_EXECUTABLE_CONTENT" in codes(action="Run sudo reboot")
    assert "UNSUPPORTED_COMPLIANCE_CLAIM" in codes(acceptance_test="The host is fully compliant")
    assert "SCOPE_MISMATCH" in codes(tenant_id="ten-other")


def test_effort_estimate_is_not_permitted_from_the_pipeline() -> None:
    from aisw.contracts.domain import EffortEstimate

    fs, vs, rs = world()
    eff = EffortEstimate(value="3 days", basis="guess")
    r = assess_recommendation(rec(fs, rs, effort=eff), fs, vs, rs, CAT, CTX)
    assert "EFFORT_ESTIMATE_NOT_PERMITTED" in r.defect_codes


def test_risk_recomputation_catches_tampering() -> None:
    f = finding("f1", category="network_exposure")
    ok = assess("f1", factors(), R)
    assert assess_risk(ok, f, R, CTX).verdict is V.ACCEPT
    unbacked = assess_risk(ok, finding("f1"), R, CTX)  # host finding: exposure needs stored edges
    assert "EXPOSURE_NOT_SUPPORTED" in unbacked.defect_codes
    tampered = ok.model_copy(update={"tier": "P0"})
    assert "RISK_NOT_REPRODUCIBLE" in assess_risk(tampered, f, R, CTX).defect_codes
    wrong_sev = ok.model_copy(update={"factors": factors(severity="LOW")})
    assert "SEVERITY_FACTOR_MISMATCH" in assess_risk(wrong_sev, f, R, CTX).defect_codes
    old = ok.model_copy(update={"rubric_version": "0.9.0"})
    assert "RUBRIC_VERSION_MISMATCH" in assess_risk(old, f, R, CTX).defect_codes
    assert "UNKNOWN_FINDING" in assess_risk(ok, None, R, CTX).defect_codes


def _validated(subject, **over) -> NarrativeResult:  # type: ignore[no-untyped-def]
    from aisw.llm.schema import NarrativeOutput
    from tests.evaluation.stub import good_output

    out = NarrativeOutput.model_validate_json(good_output(subject, **over))
    return NarrativeResult(
        status="VALIDATED", output=out, input_hash="sha256:" + "0" * 64, output_hash="h", attempts=1
    )


def test_narrative_assurance() -> None:
    fs, _, rs = world()
    subject = scenario_subject(scenario(fs, rs), fs)
    good = _validated(subject)
    assert assess_narrative(good, subject, V.ACCEPT, CTX).verdict is V.ACCEPT  # type: ignore[union-attr]
    # a parent that is not accepted never publishes a narrative
    assert assess_narrative(good, subject, V.NEEDS_REVIEW, CTX).verdict is V.NEEDS_REVIEW  # type: ignore[union-attr]
    # stored output is re-validated independently of the gateway's earlier verdict
    tampered = _validated(subject, summary="See CVE-2099-1 now")
    r = assess_narrative(tampered, subject, V.ACCEPT, CTX)
    assert r is not None and r.verdict is V.REJECT
    rejected = NarrativeResult(
        status="REJECTED", defects=["UNGROUNDED_CVE:X"], input_hash="sha256:" + "0" * 64
    )
    assert assess_narrative(rejected, subject, V.ACCEPT, CTX).verdict is V.REJECT  # type: ignore[union-attr]
    flagged = good.model_copy(update={"input_flags": ["PROMPT_INJECTION_PATTERN"]})
    assert assess_narrative(flagged, subject, V.ACCEPT, CTX).verdict is V.NEEDS_REVIEW  # type: ignore[union-attr]
    unavailable = NarrativeResult(
        status="UNAVAILABLE", defects=["AI_DISABLED"], input_hash="sha256:" + "0" * 64
    )
    assert assess_narrative(unavailable, subject, V.ACCEPT, CTX) is None
