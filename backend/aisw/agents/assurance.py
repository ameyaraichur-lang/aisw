"""Independent assurance gate (Agent 7, M3 subset). Deterministic; no model involved.

Every candidate finding is checked against stored evidence; only ACCEPT results may enter the
authoritative report dataset. Rejected candidates are preserved with their defect codes. If the
evidence store is unavailable the verdict is NEEDS_REVIEW, never an implicit approval.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from aisw.contracts.assurance import AssuranceResult
from aisw.contracts.domain import Finding
from aisw.contracts.enums import AssuranceVerdict
from aisw.contracts.refs import RefError, require_in_scope

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
