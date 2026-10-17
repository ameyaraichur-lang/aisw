"""Independent assurance gate (Agent 7, M3 subset). Deterministic; no model involved.

Every candidate finding is checked against stored evidence; only ACCEPT results may enter the
authoritative report dataset. Rejected candidates are preserved with their defect codes. If the
evidence store is unavailable the verdict is NEEDS_REVIEW, never an implicit approval.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from aisw.agents.architecture import Catalog
from aisw.agents.safety import prohibited_content
from aisw.contracts.analysis import INTERNET, CorrelationScenario, ReachEdge, RiskAssessment
from aisw.contracts.assurance import AssuranceResult
from aisw.contracts.domain import Finding, Recommendation
from aisw.contracts.enums import AssuranceVerdict, EdgeBasis, RecommendationStatus
from aisw.contracts.refs import RefError, require_in_scope
from aisw.llm.gateway import NarrativeResult
from aisw.llm.schema import NarrativeSubject
from aisw.llm.validator import validate_narrative
from aisw.policy.rubric import Rubric, TierOrder, assess, exposure_for

VALIDATION_VERSION = "1.0.0"


@dataclass(frozen=True)
class ArtifactMeta:
    tenant_id: str
    project_id: str
    run_id: str
    content_hash: str
    collected_at: datetime


@dataclass(frozen=True)
class AssuranceContext:
    tenant_id: str
    project_id: str
    run_id: str
    policy_version: str
    pack_control_ids: frozenset[str]
    pack_framework: str
    now: datetime
    freshness: timedelta
    artifact: Callable[[str], ArtifactMeta | None]
    evidence_ok: Callable[[ArtifactMeta], bool]  # raises OSError if the store is unavailable
    asset_exists: Callable[[str], bool]


def assess_finding(finding: Finding, ctx: AssuranceContext) -> AssuranceResult:
    defects: set[str] = set()
    missing: list[str] = []
    stale: list[str] = []
    needs_review = False

    try:
        require_in_scope(finding.evidence_refs, tenant_id=ctx.tenant_id, project_id=ctx.project_id)
    except RefError:
        defects.add("CROSS_SCOPE_REFERENCE")
    if (finding.tenant_id, finding.project_id, finding.run_id) != (
        ctx.tenant_id, ctx.project_id, ctx.run_id,
    ):  # fmt: skip
        defects.add("SCOPE_MISMATCH")
    for ref in finding.evidence_refs:
        meta = ctx.artifact(ref)
        if meta is None or (meta.tenant_id, meta.project_id, meta.run_id) != (
            ctx.tenant_id, ctx.project_id, ctx.run_id,
        ):  # fmt: skip
            missing.append(ref)
            continue
        try:
            if not ctx.evidence_ok(meta):
                defects.add("EVIDENCE_HASH_MISMATCH")
        except OSError:
            defects.add("EVIDENCE_STORE_UNAVAILABLE")
            needs_review = True
        if ctx.now - meta.collected_at > ctx.freshness:
            stale.append(ref)
    for asset in finding.affected_assets:
        if not ctx.asset_exists(asset):
            defects.add("ASSET_UNKNOWN")
    if finding.policy_version != ctx.policy_version:
        defects.add("POLICY_VERSION_MISMATCH")
    for m in finding.control_mappings:
        if (
            m.framework == ctx.pack_framework
            and m.mapping_status == "APPROVED"
            and m.control_id not in ctx.pack_control_ids
        ):
            defects.add("UNKNOWN_CONTROL")
    if missing:
        defects.add("EVIDENCE_NOT_FOUND")
    if stale:
        defects.add("EVIDENCE_STALE")

    hard = defects - {"EVIDENCE_STALE", "EVIDENCE_STORE_UNAVAILABLE"}
    if hard:
        verdict = AssuranceVerdict.REJECT
    elif defects or needs_review:
        verdict = AssuranceVerdict.NEEDS_REVIEW
    else:
        verdict = AssuranceVerdict.ACCEPT
    return AssuranceResult(
        tenant_id=ctx.tenant_id, run_id=ctx.run_id, item_ref=f"finding:{finding.finding_id}",
        verdict=verdict, defect_codes=sorted(defects), missing_refs=missing, stale_refs=stale,
        validation_version=VALIDATION_VERSION, validated_at=ctx.now,
    )  # fmt: skip


# ---- Agent 7 (M7): validation of everything built on top of findings -------------------------


def _result(
    ctx: AssuranceContext, item_ref: str, defects: set[str], *, review: set[str] | None = None
) -> AssuranceResult:
    review = review or set()
    verdict = (
        AssuranceVerdict.REJECT
        if defects
        else AssuranceVerdict.NEEDS_REVIEW
        if review
        else AssuranceVerdict.ACCEPT
    )
    return AssuranceResult(
        tenant_id=ctx.tenant_id, run_id=ctx.run_id, item_ref=item_ref, verdict=verdict,
        defect_codes=sorted(defects | review), validation_version=VALIDATION_VERSION,
        validated_at=ctx.now,
    )  # fmt: skip


def _constituents(
    refs: Sequence[str],
    findings: Mapping[str, Finding],
    verdicts: Mapping[str, AssuranceVerdict],
    defects: set[str],
    review: set[str],
) -> list[Finding]:
    if len(set(refs)) != len(refs):
        defects.add("DUPLICATE_FINDING_REF")
    out: list[Finding] = []
    for ref in dict.fromkeys(refs):
        f = findings.get(ref)
        if f is None:
            defects.add("UNKNOWN_FINDING")
            continue
        out.append(f)
        v = verdicts.get(ref)
        if v is AssuranceVerdict.REJECT:
            defects.add("CONSTITUENT_REJECTED")
        elif v is not AssuranceVerdict.ACCEPT:
            review.add("CONSTITUENT_NOT_ACCEPTED")
    return out


def _exposure_supported(
    risk: RiskAssessment, finding: Finding, rubric: Rubric, edges: Mapping[str, ReachEdge]
) -> bool:
    """Exposure above the category's own level must be backed by stored internet edges."""
    claimed, own = risk.factors.exposure, exposure_for(finding.category, rubric)
    if claimed == own:
        return not risk.factors.exposure_basis
    if own == "VERIFIED" or claimed == "UNKNOWN" or not risk.factors.exposure_basis:
        return False
    want = EdgeBasis.OBSERVED if claimed == "VERIFIED" else EdgeBasis.CONFIGURED
    for eid in risk.factors.exposure_basis:
        e = edges.get(eid)
        if (
            e is None
            or e.src != INTERNET
            or e.dst not in finding.affected_assets
            or e.basis is not want
        ):
            return False
    return True


def assess_risk(
    risk: RiskAssessment,
    finding: Finding | None,
    rubric: Rubric,
    ctx: AssuranceContext,
    edges: Mapping[str, ReachEdge] | None = None,
) -> AssuranceResult:
    """Recompute the tier from the stored factors with the pinned rubric; any difference rejects."""
    defects: set[str] = set()
    if finding is None:
        defects.add("UNKNOWN_FINDING")
    elif risk.factors.severity.upper() != finding.severity.value:
        defects.add("SEVERITY_FACTOR_MISMATCH")
    if finding is not None and not _exposure_supported(risk, finding, rubric, edges or {}):
        defects.add("EXPOSURE_NOT_SUPPORTED")
    if risk.rubric_version != rubric.version:
        defects.add("RUBRIC_VERSION_MISMATCH")
    else:
        try:
            again = assess(risk.finding_id, risk.factors, rubric)
        except ValueError:
            defects.add("RISK_NOT_REPRODUCIBLE")
        else:
            if (again.tier, again.basis, again.provisional_tier) != (
                risk.tier, risk.basis, risk.provisional_tier,
            ):  # fmt: skip
                defects.add("RISK_NOT_REPRODUCIBLE")
    return _result(ctx, f"risk:{risk.finding_id}", defects)


def _tier_of(refs: Sequence[str], risks: Mapping[str, RiskAssessment]) -> str | None:
    rs = [risks.get(r) for r in refs]
    if not rs or any(r is None or r.tier is None for r in rs):
        return None
    return TierOrder.worst([r.tier for r in rs if r is not None and r.tier is not None])


def assess_scenario(
    s: CorrelationScenario,
    findings: Mapping[str, Finding],
    verdicts: Mapping[str, AssuranceVerdict],
    risks: Mapping[str, RiskAssessment],
    ctx: AssuranceContext,
    edges: Mapping[str, ReachEdge] | None = None,
) -> AssuranceResult:
    defects: set[str] = set()
    review: set[str] = set()
    for hop in s.path:
        if (edges or {}).get(hop.edge_id) != hop:
            defects.add("PATH_EDGE_NOT_RECORDED")
    members = _constituents(s.finding_ids, findings, verdicts, defects, review)
    by_id = {f.finding_id: f for f in members}
    for f in members:
        if s.asset_id not in f.affected_assets:
            defects.add("ASSET_MISMATCH")
    for link in s.chain:
        member = by_id.get(link.finding_id)
        if member is not None and link.evidence_ref not in member.evidence_refs:
            defects.add("CHAIN_EVIDENCE_NOT_IN_FINDING")
        if link.basis is EdgeBasis.INFERRED:
            review.add("INFERRED_LINK_NEEDS_REVIEW")
    if _tier_of(s.finding_ids, risks) != s.tier or (s.basis == "COMPLETE") != (s.tier is not None):
        defects.add("SCENARIO_TIER_MISMATCH")
    text = [s.title, *s.assumptions, *s.missing_evidence, *s.validation_steps]
    for t in text:
        defects.update(prohibited_content(t))
    return _result(ctx, f"scenario:{s.scenario_id}", defects, review=review)


def assess_scenarios(
    scenarios: Sequence[CorrelationScenario],
    findings: Mapping[str, Finding],
    verdicts: Mapping[str, AssuranceVerdict],
    risks: Mapping[str, RiskAssessment],
    ctx: AssuranceContext,
    edges: Mapping[str, ReachEdge] | None = None,
) -> list[AssuranceResult]:
    seen: dict[tuple[frozenset[str], tuple[str, ...]], int] = {}
    out: list[AssuranceResult] = []
    for s in scenarios:
        r = assess_scenario(s, findings, verdicts, risks, ctx, edges)
        key = (frozenset(s.finding_ids), tuple(e.edge_id for e in s.path))
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            r = _result(ctx, r.item_ref, {*r.defect_codes, "DUPLICATE_SCENARIO"})
        out.append(r)
    return out


def assess_recommendation(
    r: Recommendation,
    findings: Mapping[str, Finding],
    verdicts: Mapping[str, AssuranceVerdict],
    risks: Mapping[str, RiskAssessment],
    catalog: Catalog,
    ctx: AssuranceContext,
) -> AssuranceResult:
    defects: set[str] = set()
    review: set[str] = set()
    members = _constituents(r.finding_refs, findings, verdicts, defects, review)
    if r.tenant_id != ctx.tenant_id:
        defects.add("SCOPE_MISMATCH")
    entry = catalog.by_ref(r.catalog_ref) if r.catalog_ref else None
    if entry is None:
        defects.add("UNKNOWN_CATALOG_PATTERN")
    else:
        if any(f.category not in catalog.entries for f in members) or any(
            catalog.entries[f.category].catalog_id != entry.catalog_id for f in members
        ):
            defects.add("PATTERN_NOT_APPLICABLE")
    if not r.rollback:
        defects.add("MISSING_ROLLBACK")
    if not r.acceptance_test:
        defects.add("MISSING_ACCEPTANCE_TEST")
    if not r.validation_steps:
        defects.add("MISSING_VALIDATION_STEPS")
    if r.effort.value is not None:
        defects.add("EFFORT_ESTIMATE_NOT_PERMITTED")  # only an owner may supply one, with a basis
    if not set(r.affected_assets) <= {a for f in members for a in f.affected_assets}:
        defects.add("ASSET_NOT_IN_FINDINGS")
    if r.status is not RecommendationStatus.DRAFT:
        defects.add("UNEXPECTED_STATUS")
    if _tier_of(r.finding_refs, risks) != r.risk_tier:
        defects.add("RECOMMENDATION_TIER_MISMATCH")
    text = [
        r.title or "", r.target_pattern or "", r.current_state or "", r.action, r.rollback or "",
        r.acceptance_test or "", *r.alternatives, *r.dependencies, *r.owner_questions,
        *r.assumptions, *r.validation_steps,
    ]  # fmt: skip
    for t in text:
        defects.update(prohibited_content(t))
    return _result(ctx, f"recommendation:{r.recommendation_id}", defects, review=review)


def assess_narrative(
    n: NarrativeResult,
    subject: NarrativeSubject,
    parent: AssuranceVerdict | None,
    ctx: AssuranceContext,
) -> AssuranceResult | None:
    """None for UNAVAILABLE (nothing to validate: the deterministic text stands on its own)."""
    if n.status == "UNAVAILABLE":
        return None
    ref = f"narrative:{subject.purpose}:{subject.subject_ref}"
    defects: set[str] = set(n.defects) if n.status == "REJECTED" else set()
    review: set[str] = set()
    if n.status == "VALIDATED":
        if n.output is None:
            defects.add("MISSING_OUTPUT")
        else:  # independent re-check of what is stored, not trust in the gateway's earlier verdict
            defects.update(validate_narrative(n.output, subject))
    if parent is not AssuranceVerdict.ACCEPT:
        review.add("PARENT_NOT_ACCEPTED")
    if n.input_flags:
        review.add("INPUT_CONTAINED_INJECTION_PATTERN")
    return _result(ctx, ref, defects, review=review)
