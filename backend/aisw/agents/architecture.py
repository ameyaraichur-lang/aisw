"""Agent 6 - Security Architecture & Modernization (deterministic core).

Turns recorded findings into recommendation CANDIDATES using an approved-pattern catalog. Rules:
every recommendation cites findings; effort is UNKNOWN (never estimated here); missing owner or
criticality becomes an explicit owner question; no lifecycle date, cost or compatibility claim is
ever made; nothing here can execute a change (acceptance only records a human decision).
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from importlib import resources

from pydantic import Field

from aisw.contracts.analysis import RiskAssessment
from aisw.contracts.base import NonEmpty, StrictModel
from aisw.contracts.domain import EffortEstimate, Finding, Recommendation
from aisw.policy.rubric import TierOrder


class CatalogEntry(StrictModel):
    catalog_id: NonEmpty
    title: NonEmpty
    target_pattern: NonEmpty
    action: NonEmpty
    alternatives: list[NonEmpty] = Field(default_factory=list)
    prerequisites: list[NonEmpty] = Field(default_factory=list)
    owner_questions: list[NonEmpty] = Field(default_factory=list)
    validation_steps: list[NonEmpty] = Field(min_length=1)
    rollback: NonEmpty
    acceptance_test: NonEmpty
    assumptions: list[NonEmpty] = Field(default_factory=list)


class Catalog(StrictModel):
    version: NonEmpty
    status: NonEmpty
    description: str = ""
    entries: dict[str, CatalogEntry]

    def by_ref(self, ref: str) -> CatalogEntry | None:
        return next(
            (e for e in self.entries.values() if f"{e.catalog_id}@{self.version}" == ref), None
        )


def builtin_catalog(version: str = "1.0.0") -> Catalog:
    text = (
        resources.files("aisw.policy") / "catalogs" / f"architecture-catalog-{version}.json"
    ).read_text(encoding="utf-8")
    return Catalog.model_validate(json.loads(text))


def build_recommendations(
    *, tenant_id: str, findings: Sequence[Finding], risks: Mapping[str, RiskAssessment],
    assets: Mapping[str, tuple[str | None, str | None]],  # asset_id -> (owner, criticality)
    catalog: Catalog,
) -> list[Recommendation]:  # fmt: skip
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.category in catalog.entries:
            groups[f.category].append(f)
    out: list[Recommendation] = []
    for category, fs in sorted(groups.items()):
        entry = catalog.entries[category]
        ids = sorted({f.finding_id for f in fs})
        asset_ids = sorted({a for f in fs for a in f.affected_assets})
        unknown_owner = [a for a in asset_ids if not (assets.get(a) or (None, None))[0]]
        unknown_crit = [a for a in asset_ids if not (assets.get(a) or (None, None))[1]]
        questions = list(entry.owner_questions)
        if unknown_owner:
            questions.append(
                f"Who owns these assets (owner is unknown in the inventory): {', '.join(unknown_owner[:8])}?"
            )
        if unknown_crit:
            questions.append(f"What is the business criticality of: {', '.join(unknown_crit[:8])}?")
        tiers = [risks[i].tier for i in ids if i in risks]
        complete = bool(tiers) and all(t is not None for t in tiers)
        titles = sorted({f.title for f in fs})
        out.append(
            Recommendation(
                recommendation_id="rec-" + hashlib.sha256(f"{entry.catalog_id}|{'|'.join(ids)}".encode()).hexdigest()[:16],
                tenant_id=tenant_id, finding_refs=ids, title=entry.title,
                catalog_ref=f"{entry.catalog_id}@{catalog.version}", target_pattern=entry.target_pattern,
                current_state=f"{len(ids)} finding(s) on {len(asset_ids)} asset(s): " + "; ".join(titles[:3]),
                action=entry.action, alternatives=entry.alternatives, dependencies=entry.prerequisites,
                effort=EffortEstimate(value=None, basis=None),  # UNKNOWN: only an owner can estimate
                owner_questions=questions, rollback=entry.rollback, acceptance_test=entry.acceptance_test,
                assumptions=[*entry.assumptions, f"Pattern source: catalog {catalog.version} ({catalog.status})"],
                affected_assets=asset_ids,
                risk_tier=TierOrder.worst([t for t in tiers if t is not None]) if complete else None,
                validation_steps=entry.validation_steps,
            )
        )  # fmt: skip
    return out
