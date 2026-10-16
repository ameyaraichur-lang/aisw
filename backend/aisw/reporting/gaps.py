"""Control-gap matrix and architecture delta for reports and exports.

The gap matrix reads framework controls through the curated mappings (ADR-032) and the run's own
pack-control outcomes. A framework control is a GAP when any mapped pack control failed; it is never
called compliant: the best it gets is "no gap observed", and only when every mapped control was
assessed. A mapping still awaiting policy-owner review is labelled a proposal; a rejected one is
not used.
"""

from __future__ import annotations

from typing import Any

from aisw.policy.engine import PolicyPack
from aisw.policy.mappings import Catalog

GAP_STATES = ("GAP", "EXCEPTION", "UNKNOWN", "NO_GAP_OBSERVED", "NOT_APPLICABLE")
GAP_LABEL = {
    "GAP": "Gap: a mapped check failed",
    "EXCEPTION": "Risk accepted under an exception",
    "UNKNOWN": "Unknown: not every mapped check was assessed",
    "NO_GAP_OBSERVED": "No gap observed (not a statement of compliance)",
    "NOT_APPLICABLE": "Not applicable",
}
GAP_SHORT = {"GAP": "Gap", "EXCEPTION": "Exception", "UNKNOWN": "Unknown",
             "NO_GAP_OBSERVED": "No gap observed", "NOT_APPLICABLE": "Not applicable"}  # fmt: skip
UNASSESSED = {"UNKNOWN", "ERROR", "NOT_ASSESSED"}


def _state(outcomes: list[str]) -> str:
    if "FAIL" in outcomes:
        return "GAP"
    if "EXCEPTION" in outcomes:
        return "EXCEPTION"
    if any(o in UNASSESSED for o in outcomes):
        return "UNKNOWN"
    if all(o == "NOT_APPLICABLE" for o in outcomes):
        return "NOT_APPLICABLE"
    return "NO_GAP_OBSERVED"


def control_gaps(
    pack: PolicyPack, outcomes: dict[str, str], catalog: Catalog, reviews: dict[str, str]
) -> dict[str, Any]:
    """``outcomes``: pack control -> outcome in this run (absent means not assessed).
    ``reviews``: mapping key -> latest review status for this tenant."""
    in_pack = pack.control_ids()
    frameworks = []
    for fw in catalog.frameworks:
        by_control: dict[str, list[tuple[str, str]]] = {}
        for m in catalog.mappings:
            status = reviews.get(m.key, "NEEDS_REVIEW")
            if m.framework != fw.framework or m.pack_control not in in_pack or status == "REJECTED":
                continue
            by_control.setdefault(m.control_id, []).append((m.pack_control, status))
        rows = []
        for control_id in sorted(by_control):
            mapped = sorted(by_control[control_id])
            seen = [outcomes.get(pc, "NOT_ASSESSED") for pc, _ in mapped]
            rows.append({
                "control_id": control_id, "title": catalog.controls[fw.framework][control_id],
                "state": _state(seen),
                "pack_controls": [{"control_id": pc, "outcome": o} for (pc, _), o in zip(mapped, seen, strict=True)],
                "mapping": "APPROVED" if all(s == "APPROVED" for _, s in mapped) else "PROPOSED",
            })  # fmt: skip
        if rows:
            summary = {s: sum(r["state"] == s for r in rows) for s in GAP_STATES}
            frameworks.append({"framework": fw.framework, "version": fw.version, "name": fw.name,
                               "summary": summary, "rows": rows})  # fmt: skip
    return {"catalog_version": catalog.version, "notice": catalog.notice, "frameworks": frameworks}


def architecture_delta(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Current state (accepted findings) beside the approved target pattern, per recommendation."""
    titles = {f["finding_id"]: f["title"] for f in body.get("findings", [])}
    recs = sorted(body.get("recommendations", []),
                  key=lambda r: (r.get("catalog_ref") or "", r["recommendation_id"]))  # fmt: skip
    return [
        {"recommendation_id": r["recommendation_id"], "pattern": r.get("catalog_ref"),
         "title": r.get("title") or r["action"], "target": r.get("target_pattern"),
         "current_state": r.get("current_state"),
         "current": [titles.get(i, i) for i in r["finding_refs"]],
         "assets": list(r.get("affected_assets", [])), "tier": r.get("risk_tier")}
        for r in recs
    ]  # fmt: skip
