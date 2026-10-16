"""Agent validation pass (ADR-021) through the real API, Postgres and worker, with a scripted model.

The reviewer can only add caution: a DISSENT holds an accepted item out of the report for human
review; CONCUR, an outage or an invalid reply leave the deterministic report unchanged.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
import sqlalchemy.exc
from sqlalchemy import text

from aisw.core.db import tenant_connection
from aisw.llm.validation import DISSENT_DEFECT, SYSTEM_PROMPT
from tests.evaluation.stub import OUTAGE, ScriptedModel
from tests.integration.test_analysis_pipeline import EXPECTED, grounded, shape
from tests.slice import Slice

Decide = Callable[[dict[str, Any]], str]


def reviewer(decide: Decide) -> Callable[[str, str], str]:
    """Answers narrative prompts with grounded text and validation prompts with ``decide``."""

    def step(system: str, user: str) -> str:
        if not system.startswith(SYSTEM_PROMPT[:40]):
            return grounded(system, user)
        data = json.loads(user.removeprefix("DATA:\n"))
        verdicts = []
        for t in data["targets"]:
            v = decide(t)
            issues = [] if v == "CONCUR" else [{
                "code": "OUTCOME_NOT_SUPPORTED", "explanation": "The observed value is ambiguous.",
                "evidence_refs": t["evidence_refs"][:1],
            }]  # fmt: skip
            verdicts.append({"target_ref": t["target_ref"], "verdict": v, "issues": issues,
                             "validator_confidence": "MEDIUM"})  # fmt: skip
        return json.dumps({"verdicts": verdicts})

    return step


def ai_run(sl: Slice, step: Any) -> tuple[Any, str]:
    model = step if hasattr(step, "complete") else ScriptedModel(step)
    sl.enable_ai(model)
    sl.worker.ai_validation = True
    sl.worker.validation_concurrency = 1
    _, _, run_id = sl.full_run(EXPECTED, ai_assist=True)
    sl.drain()
    assert sl.status(run_id)["state"] in {"REPORT_READY", "REPORT_PARTIAL"}
    return model, run_id


def plain(sl: Slice) -> dict[str, Any]:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    return sl.report(run_id)


def test_validator_reviews_every_agent_and_concur_changes_nothing(sl: Slice) -> None:
    base = shape(plain(sl))
    model, run_id = ai_run(sl, reviewer(lambda _t: "CONCUR"))
    rep = sl.report(run_id)
    assert shape(rep) == base
    rows = sl.sql("SELECT target_ref, agent_id, verdict, effect FROM ai_validations WHERE run_id=:r",
                  r=run_id)  # fmt: skip
    kinds = {ref.split(":")[0] for ref, *_ in rows}
    assert kinds == {"scope", "coverage", "finding", "scenario", "recommendation", "narrative"}
    assert {a for _, a, _, _ in rows} >= {0, 1, 2, 5, 6, 7, 8}
    assert {(v, e) for *_, v, e in rows} == {("CONCUR", "ANNOTATION")}
    calls = sl.sql("SELECT purpose, status FROM llm_calls WHERE run_id=:r AND purpose LIKE "
                   "'validation:%'", r=run_id)  # fmt: skip
    assert calls and {s for _, s in calls} == {"VALIDATED"}
    assert rep["ai"]["validation"]["total"] == len(rows)
    assert rep["ai"]["validation"]["held_for_review"] == 0
    assert all("tools" not in c for c in model.calls)

    api = sl.call("GET", f"/api/v1/assessments/{run_id}/ai-validations", "carol")
    assert api.status_code == 200
    body = api.json()
    assert body["summary"]["total"] == len(rows) and len(body["items"]) == len(rows)
    assert all(i["ai_generated"] and i["agent_name"] for i in body["items"])
    html = sl.call("GET", f"/api/v1/reports/rep-{run_id}?format=html", "carol").text
    assert "AI validation of agent outcomes" in html


def test_dissent_holds_a_finding_for_review(sl: Slice) -> None:
    held: list[str] = []

    def decide(t: dict[str, Any]) -> str:
        if t["kind"] == "finding" and (not held or held[0] == t["target_ref"]):
            held[:1] = [t["target_ref"]]
            return "DISSENT"
        return "CONCUR"

    _, run_id = ai_run(sl, reviewer(decide))
    fid = held[0].removeprefix("finding:")
    rep = sl.report(run_id)
    assert fid not in {f["finding_id"] for f in rep["findings"]}
    assert fid in {f["finding_id"] for f in rep["pending_review"]}
    assert any("AI validator dissented on 1 item" in x for x in rep["limitations"])
    (verdict, defects), = sl.sql(
        "SELECT verdict, defect_codes FROM assurance_results WHERE run_id=:r AND item_ref=:i",
        r=run_id, i=held[0],
    )  # fmt: skip
    assert verdict == "NEEDS_REVIEW" and DISSENT_DEFECT in defects
    (effect,), = sl.sql("SELECT effect FROM ai_validations WHERE run_id=:r AND target_ref=:t",
                        r=run_id, t=held[0])  # fmt: skip
    assert effect == "HOLD_FOR_REVIEW"


def test_dissent_on_a_recommendation_keeps_it_out_of_the_report(sl: Slice) -> None:
    _, run_id = ai_run(
        sl, reviewer(lambda t: "DISSENT" if t["kind"] == "recommendation" else "CONCUR")
    )
    rep = sl.report(run_id)
    assert rep["recommendations"] == []
    rows = sl.sql("SELECT verdict FROM assurance_results WHERE run_id=:r AND item_ref LIKE "
                  "'recommendation:%'", r=run_id)  # fmt: skip
    assert rows and {v for (v,) in rows} == {"NEEDS_REVIEW"}


@pytest.mark.parametrize("decide", ["CONCERN", "INSUFFICIENT_EVIDENCE"])
def test_concern_is_a_review_note_not_a_hold(sl: Slice, decide: str) -> None:
    base = shape(plain(sl))
    _, run_id = ai_run(sl, reviewer(lambda _t: decide))
    assert shape(sl.report(run_id)) == base
    assert {e for (e,) in sl.sql("SELECT effect FROM ai_validations WHERE run_id=:r",
                                  r=run_id)} == {"REVIEW_ITEM"}  # fmt: skip


def test_validator_outage_leaves_the_report_unchanged(sl: Slice) -> None:
    base = shape(plain(sl))

    def narrate_or_fail(system: str, user: str) -> str:
        if system.startswith(SYSTEM_PROMPT[:40]):
            raise OUTAGE
        return grounded(system, user)

    _, run_id = ai_run(sl, narrate_or_fail)
    rep = sl.report(run_id)
    assert shape(rep) == base
    rows = sl.sql("SELECT verdict, effect FROM ai_validations WHERE run_id=:r", r=run_id)
    assert rows and set(rows) == {("UNAVAILABLE", "NONE")}
    assert any(
        "could not be validated" in x or "unavailable" in x.lower() for x in rep["limitations"]
    )


def test_ungrounded_validator_reply_has_no_effect(sl: Slice) -> None:
    base = shape(plain(sl))

    def bad(system: str, user: str) -> str:
        if not system.startswith(SYSTEM_PROMPT[:40]):
            return grounded(system, user)
        data = json.loads(user.removeprefix("DATA:\n"))
        return json.dumps({"verdicts": [{
            "target_ref": t["target_ref"], "verdict": "DISSENT", "validator_confidence": "HIGH",
            "issues": [{"code": "OUTCOME_NOT_SUPPORTED", "explanation": "See CVE-2099-0001."}],
        } for t in data["targets"]]})  # fmt: skip

    _, run_id = ai_run(sl, bad)
    assert shape(sl.report(run_id)) == base
    rows = sl.sql("SELECT verdict, effect FROM ai_validations WHERE run_id=:r", r=run_id)
    assert rows and set(rows) == {("VALIDATOR_INVALID", "NONE")}


def test_validations_are_append_only_and_tenant_scoped(sl: Slice) -> None:
    _, run_id = ai_run(sl, reviewer(lambda _t: "CONCUR"))
    with pytest.raises(sqlalchemy.exc.DBAPIError):
        with tenant_connection(sl.app_engine, "tenant-a") as c:
            c.execute(text("UPDATE ai_validations SET verdict='DISSENT', effect='HOLD_FOR_REVIEW' "
                           "WHERE run_id=:r"), {"r": run_id})  # fmt: skip
    with tenant_connection(sl.app_engine, "tenant-b") as c:
        n = c.execute(text("SELECT count(*) FROM ai_validations WHERE run_id=:r"), {"r": run_id})
        assert n.scalar() == 0


def test_validation_is_off_without_ai_assist(sl: Slice) -> None:
    model = ScriptedModel(reviewer(lambda _t: "DISSENT"))
    sl.enable_ai(model)
    sl.worker.ai_validation = True
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    assert model.calls == []
    assert sl.sql("SELECT count(*) FROM ai_validations WHERE run_id=:r", r=run_id)[0][0] == 0
