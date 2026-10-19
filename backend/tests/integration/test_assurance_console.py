"""Assurance Console read models over a real AI-assisted run with a scripted reviewer."""

from __future__ import annotations

from typing import Any

from tests.integration.test_ai_validation_pipeline import ai_run, reviewer
from tests.integration.test_dissent_resolution import resolve
from tests.slice import Slice


def mixed_run(sl: Slice) -> tuple[str, str]:
    """The reviewer dissents on one finding and raises a concern on the recommendations."""
    held: list[str] = []

    def decide(t: dict[str, Any]) -> str:
        if t["kind"] == "finding" and (not held or held[0] == t["target_ref"]):
            held[:1] = [t["target_ref"]]
            return "DISSENT"
        return "CONCERN" if t["kind"] == "recommendation" else "CONCUR"

    _, run_id = ai_run(sl, reviewer(decide))
    return run_id, held[0]


def test_the_queue_shows_engine_and_ai_side_by_side_until_a_human_decides(sl: Slice) -> None:
    before = sl.call("GET", "/api/v1/assurance/overview", "carol").json()["open_dissent"]
    run_id, ref = mixed_run(sl)
    url = f"/api/v1/assurance/disagreements?run_id={run_id}"
    q = sl.call("GET", url, "carol")
    assert q.status_code == 200, q.text
    (item,) = q.json()["items"]
    assert (item["run_id"], item["target_ref"], item["ai_verdict"]) == (run_id, ref, "DISSENT")
    assert item["effect"] == "HOLD_FOR_REVIEW" and item["resolvable"] and item["ai_generated"]
    assert item["engine_verdict"] == "NEEDS_REVIEW" and item["agent_name"]
    notes = sl.call("GET", f"{url}&state=notes", "carol").json()
    assert notes["total"] == 2 and {i["ai_verdict"] for i in notes["items"]} == {"CONCERN"}
    assert not any(i["resolvable"] for i in notes["items"])  # a concern never holds anything

    ov = sl.call("GET", "/api/v1/assurance/overview", "carol").json()
    assert ov["open_dissent"] == before + 1 and ov["ai_validation"]["DISSENT"] >= 1
    assert ov["assurance"]["finding"]["NEEDS_REVIEW"] >= 1
    assert {t["agent_id"] for t in ov["triggers"]} >= {0, 2, 6}

    assert resolve(sl, run_id, ref, "UPHOLD").status_code == 200
    assert sl.call("GET", url, "carol").json()["total"] == 0
    (done,) = sl.call("GET", f"{url}&state=resolved", "carol").json()["items"]
    assert done["resolution"]["decision"] == "UPHOLD" and done["resolution"]["decided_by"] == "rita"
    assert not done["resolvable"]
    assert sl.call("GET", "/api/v1/assurance/overview", "carol").json()["open_dissent"] == before

    assert sl.call("GET", "/api/v1/assurance/disagreements", "dave").status_code in {200, 403}
    other = sl.call("GET", f"{url}&state=all", "dave")
    assert other.status_code == 403 or other.json()["total"] == 0  # tenant-b sees nothing
    assert sl.call("GET", "/api/v1/assurance/disagreements?state=bogus", "carol").status_code == 422


def test_trigger_policy_is_shown_with_its_signoff_and_per_run_decisions(sl: Slice) -> None:
    run_id, _ = mixed_run(sl)
    p = sl.call("GET", f"/api/v1/assurance/trigger-policy?run_id={run_id}", "carol").json()
    assert p["version"] == "1.0.0" and len(p["sha256"]) == 64 and p["signoff"] == "PENDING"
    assert [a["agent_id"] for a in p["agents"]] == list(range(9))
    assert p["priority"][0]["agent_id"] == 0
    hit = {d["target_ref"]: d for d in p["decisions"]}
    assert any(not d["triggered"] and d["rule"] == "no_rule_matched" for d in hit.values())
    assert all(d["policy_version"] == "1.0.0" for d in hit.values())
    assert sl.call("GET", "/api/v1/assurance/trigger-policy", "paula").status_code == 403


def test_model_call_ledger_is_auditor_only_and_never_returns_prompts(sl: Slice) -> None:
    run_id, _ = mixed_run(sl)
    assert sl.call("GET", "/api/v1/model-calls", "carol").status_code == 403
    r = sl.call("GET", f"/api/v1/model-calls?run_id={run_id}", "erin")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["total"] == d["totals"]["calls"] > 0 and d["items"][0]["project_name"]
    assert all(set(i) >= {"input_hash", "purpose", "status"} for i in d["items"])
    assert not any(k in i for i in d["items"] for k in ("prompt", "reply", "body", "output"))
    v = sl.call("GET", f"/api/v1/model-calls?run_id={run_id}&purpose=validation", "erin").json()
    assert v["total"] > 0 and all(i["purpose"].startswith("validation") for i in v["items"])
    assert sl.call("GET", "/api/v1/model-calls?status=lower", "erin").status_code == 422
    assert sl.call("GET", "/api/v1/model-calls", "dave").status_code == 403
