"""Agent 6 - Modernization roadmap (deterministic): remediation waves over accepted recommendations.

A wave comes only from the rubric tier. A recommendation without a tier is not scheduled, because
placing it would invent a priority; it waits for owner input instead. The only dependency edge is
one the evidence supports: a recommendation on assets whose owner is unknown waits for the
asset-governance recommendation that covers those assets. Effort is never estimated.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

GOVERNANCE_PREFIX = "AC-GOV-"
WAVE_BY_TIER = {"P0": 1, "P1": 1, "P2": 2, "P3": 3}
WAVE_LABEL = {
    1: "Wave 1: highest business risk (P0, P1)",
    2: "Wave 2: elevated business risk (P2)",
    3: "Wave 3: lower business risk (P3)",
    4: "Wave 4: follows a wave-3 prerequisite",
}
RULES = (
    "Only recommendations accepted by independent assurance are placed.",
    "The wave follows the rubric tier; nothing else raises or lowers it.",
    "A recommendation without a tier is not scheduled: its criticality inputs are missing.",
    "A recommendation on assets with an unknown owner follows the asset-governance "
    "recommendation for those assets, one wave later.",
    "Rejected and implemented-pending-validation recommendations are listed, not scheduled.",
    "Effort is unknown until the owner estimates it.",
)


def _is_governance(r: Mapping[str, Any]) -> bool:
    return str(r.get("catalog_ref") or "").startswith(GOVERNANCE_PREFIX)


def _card(r: Mapping[str, Any]) -> dict[str, Any]:
    effort = r.get("effort") or {}
    return {
        "recommendation_id": r["recommendation_id"], "title": r.get("title"),
        "status": r["status"], "risk_tier": r.get("risk_tier"), "catalog_ref": r.get("catalog_ref"),
        "current_state": r.get("current_state"), "target_pattern": r.get("target_pattern"),
        "affected_assets": list(r.get("affected_assets") or []),
        "effort": {"value": effort.get("value"), "is_estimate": bool(effort.get("is_estimate", True))},
        "depends_on": [], "reason": "",
    }  # fmt: skip


def build_roadmap(
    recs: Sequence[Mapping[str, Any]], owners: Mapping[str, str | None]
) -> dict[str, Any]:
    """`recs` are recommendation rows with `status` and `assurance_verdict`; `owners` maps asset id
    to its current owner (None when unknown)."""
    accepted = [r for r in recs if r.get("assurance_verdict") == "ACCEPT"]
    excluded = len(recs) - len(accepted)
    rejected = [_card(r) for r in accepted if r["status"] == "REJECTED"]
    validating = [_card(r) for r in accepted if r["status"] == "IMPLEMENTED_PENDING_VALIDATION"]
    live = sorted(
        (r for r in accepted if r["status"] not in {"REJECTED", "IMPLEMENTED_PENDING_VALIDATION"}),
        key=lambda r: str(r["recommendation_id"]),
    )
    gov = [r for r in live if _is_governance(r)]
    cards = {str(r["recommendation_id"]): _card(r) for r in live}
    edges: list[dict[str, Any]] = []
    for r in live:
        if _is_governance(r):
            continue
        unowned = sorted(a for a in r.get("affected_assets") or [] if not owners.get(a))
        for g in gov:
            shared = [a for a in unowned if a in set(g.get("affected_assets") or [])]
            if shared:
                rid, gid = str(r["recommendation_id"]), str(g["recommendation_id"])
                cards[rid]["depends_on"].append(gid)
                edges.append({"from": gid, "to": rid, "basis": "OWNER_UNKNOWN", "assets": shared})

    waves: dict[int, list[dict[str, Any]]] = {w: [] for w in WAVE_LABEL}
    unrated: list[dict[str, Any]] = []
    placed: dict[str, int] = {}
    for r in sorted(live, key=lambda x: (not _is_governance(x), str(x["recommendation_id"]))):
        c = cards[str(r["recommendation_id"])]
        tier = r.get("risk_tier")
        if tier not in WAVE_BY_TIER:
            c["reason"] = "Not scheduled: criticality is unknown for an affected asset, so no tier."
            unrated.append(c)
            continue
        base = WAVE_BY_TIER[str(tier)]
        after = [placed[d] for d in c["depends_on"] if d in placed]
        wave = max([base, *(w + 1 for w in after)])  # governance has no deps, so at most 4
        waiting = [d for d in c["depends_on"] if d not in placed]
        c["reason"] = (
            f"Risk tier {tier}"
            + (f"; follows {', '.join(c['depends_on'])} (asset owners unknown)" if after else "")
            + (f"; also waits for unscheduled {', '.join(waiting)}" if waiting else "")
        )
        placed[c["recommendation_id"]] = wave
        waves[wave].append(c)
    for c in unrated:
        if c["depends_on"]:
            c["reason"] += f" Also waits for {', '.join(c['depends_on'])} (asset owners unknown)."
    return {
        "waves": [
            {"wave": w, "label": WAVE_LABEL[w], "items": waves[w]}
            for w in WAVE_LABEL
            if w < 4 or waves[w]
        ],
        "unrated": unrated,
        "awaiting_validation": validating,
        "rejected": rejected,
        "edges": edges,
        "not_authoritative": excluded,
        "rules": list(RULES),
    }
