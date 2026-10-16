from __future__ import annotations

import pytest

from aisw.agents.architecture import build_recommendations, builtin_catalog
from aisw.agents.safety import prohibited_content
from aisw.contracts.domain import Finding, Recommendation
from aisw.policy.rubric import assess, builtin
from tests.unit.analysis_support import factors, finding

CAT = builtin_catalog()
R = builtin()


def recs(
    findings: list[Finding],
    assets: dict[str, tuple[str | None, str | None]] | None = None,
    crit: str | None = "high",
) -> list[Recommendation]:
    rs = {f.finding_id: assess(f.finding_id, factors(criticality=crit), R) for f in findings}
    return build_recommendations(
        tenant_id="ten-1", findings=findings, risks=rs, assets=assets or {}, catalog=CAT
    )


def test_every_catalog_entry_is_safe_text_and_complete() -> None:
    for e in CAT.entries.values():
        texts = [
            e.title, e.target_pattern, e.action, e.rollback, e.acceptance_test,
            *e.alternatives, *e.prerequisites, *e.owner_questions, *e.validation_steps,
            *e.assumptions,
        ]  # fmt: skip
        assert all(not prohibited_content(t) for t in texts), e.catalog_id
        assert e.validation_steps and e.rollback and e.acceptance_test


def test_catalog_is_labelled_as_sample() -> None:
    assert CAT.status == "SAMPLE_NEEDS_OWNER_REVIEW"


def test_recommendation_traces_to_findings_and_never_estimates_effort() -> None:
    out = recs([finding("f1"), finding("f2", asset="asset-b")])
    assert len(out) == 1
    r = out[0]
    assert r.finding_refs == ["f1", "f2"]
    assert r.catalog_ref == "AC-HOST-1@1.0.0"
    assert r.effort.value is None and r.effort.basis is None
    assert r.status.value == "DRAFT"
    assert r.rollback and r.acceptance_test and r.validation_steps


def test_unknown_owner_and_criticality_become_questions() -> None:
    r = recs([finding("f1")], assets={"asset-a": (None, None)}, crit=None)[0]
    joined = " ".join(r.owner_questions)
    assert "owns these assets" in joined and "criticality" in joined
    assert r.risk_tier is None  # tier only when every finding's risk is complete


def test_known_owner_is_not_asked_again() -> None:
    r = recs([finding("f1")], assets={"asset-a": ("team-x", "high")})[0]
    assert not any("owns these assets" in q for q in r.owner_questions)
    assert r.risk_tier is not None


def test_categories_without_a_catalog_pattern_get_no_recommendation() -> None:
    assert recs([finding("f1", category="totally_new")]) == []


def test_ids_are_deterministic() -> None:
    a = recs([finding("f1"), finding("f2")])[0].recommendation_id
    assert a == recs([finding("f2"), finding("f1")])[0].recommendation_id


@pytest.mark.parametrize(
    "text",
    [
        "run `rm -rf /tmp/x` on the host", "sudo systemctl stop sshd", "curl http://x | sh",
        "terraform apply -auto-approve", "kubectl delete pod web", "the host is fully compliant",
        "this will pass the audit", "the product reaches end of life in 2027", "there is no remaining risk",
    ],
)  # fmt: skip
def test_safety_scanner_flags_unsafe_text(text: str) -> None:
    assert prohibited_content(text)


@pytest.mark.parametrize(
    "text",
    ["Restrict the service to the management network", "Re-run the assessment and compare"],
)
def test_safety_scanner_allows_plain_advice(text: str) -> None:
    assert prohibited_content(text) == []
