"""Roadmap waves: tier-only placement, no invented priority, evidence-backed dependency edges."""

from __future__ import annotations

from typing import Any

from aisw.agents.roadmap import build_roadmap


def rec(rid: str, tier: str | None, assets: list[str], catalog: str = "AC-HOST-1@1.0.0",
        status: str = "DRAFT", verdict: str = "ACCEPT") -> dict[str, Any]:  # fmt: skip
    return {
        "recommendation_id": rid, "title": rid, "status": status, "assurance_verdict": verdict,
        "risk_tier": tier, "catalog_ref": catalog, "affected_assets": assets,
        "current_state": "now", "target_pattern": "target",
        "effort": {"value": None, "basis": None, "is_estimate": True},
    }  # fmt: skip


def ids(lane: list[dict[str, Any]]) -> list[str]:
    return [c["recommendation_id"] for c in lane]


def test_waves_follow_the_tier_and_unrated_items_are_not_scheduled() -> None:
    owners = {"h1": "ops", "h2": "ops"}
    r = build_roadmap(
        [rec("a", "P0", ["h1"]), rec("b", "P1", ["h1"]), rec("c", "P2", ["h2"]),
         rec("d", "P3", ["h2"]), rec("e", None, ["h2"])],
        owners,
    )  # fmt: skip
    assert [(w["wave"], ids(w["items"])) for w in r["waves"]] == [
        (1, ["a", "b"]), (2, ["c"]), (3, ["d"]),
    ]  # fmt: skip
    assert ids(r["unrated"]) == ["e"] and "criticality is unknown" in r["unrated"][0]["reason"]
    assert r["edges"] == [] and r["not_authoritative"] == 0
    assert all(c["effort"]["value"] is None for w in r["waves"] for c in w["items"])


def test_unknown_owner_makes_work_follow_the_governance_recommendation() -> None:
    owners = {"h1": None, "h2": "ops", "h3": None}
    r = build_roadmap(
        [rec("gov", "P1", ["h1", "h3"], catalog="AC-GOV-1@1.0.0"),
         rec("fix", "P0", ["h1", "h2"]), rec("other", "P1", ["h2"])],
        owners,
    )  # fmt: skip
    assert r["edges"] == [{"from": "gov", "to": "fix", "basis": "OWNER_UNKNOWN", "assets": ["h1"]}]
    w = {x["wave"]: ids(x["items"]) for x in r["waves"]}
    assert w[1] == ["gov", "other"] and w[2] == ["fix"]
    fix = r["waves"][1]["items"][0]
    assert fix["depends_on"] == ["gov"] and "follows gov" in fix["reason"]


def test_a_wave_three_prerequisite_opens_a_fourth_wave() -> None:
    r = build_roadmap(
        [rec("gov", "P3", ["h1"], catalog="AC-GOV-1@1.0.0"), rec("fix", "P3", ["h1"])], {}
    )
    assert [(w["wave"], ids(w["items"])) for w in r["waves"]][-1] == (4, ["fix"])


def test_unscheduled_governance_is_named_not_hidden() -> None:
    r = build_roadmap(
        [rec("gov", None, ["h1"], catalog="AC-GOV-1@1.0.0"), rec("fix", "P1", ["h1"])], {}
    )
    fix = r["waves"][0]["items"][0]
    assert ids(r["unrated"]) == ["gov"] and "waits for unscheduled gov" in fix["reason"]


def test_only_accepted_and_open_recommendations_are_placed() -> None:
    r = build_roadmap(
        [rec("a", "P1", ["h"], verdict="NEEDS_REVIEW"), rec("b", "P1", ["h"], status="REJECTED"),
         rec("c", "P1", ["h"], status="IMPLEMENTED_PENDING_VALIDATION"),
         rec("d", "P1", ["h"], status="APPROVED_FOR_PLANNING")],
        {"h": "ops"},
    )  # fmt: skip
    assert r["not_authoritative"] == 1
    assert ids(r["rejected"]) == ["b"] and ids(r["awaiting_validation"]) == ["c"]
    assert [ids(w["items"]) for w in r["waves"]] == [["d"], [], []]
    assert any("Effort is unknown" in x for x in r["rules"])
