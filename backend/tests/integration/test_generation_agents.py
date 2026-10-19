"""Agents 0, 4 and 8 with a model (ADR-024) through the real API, Postgres and worker.

Agent 0's scope is reviewed but a dissent is only a review note; Agent 4 drafts questions for asset
owners about accepted exposure findings; Agent 8 writes an executive summary that is shown only when
every finding it cites was accepted and the reviewer did not dissent.
"""

from __future__ import annotations

import json
from typing import Any

from aisw.llm.validation import SYSTEM_PROMPT
from tests.evaluation.stub import ScriptedModel, good_output
from tests.integration.test_ai_validation_pipeline import ai_run, plain, reviewer
from tests.integration.test_analysis_pipeline import grounded, shape, subject_of
from tests.integration.test_dissent_resolution import reports, resolve
from tests.security.test_import_pipeline import gold, import_run, manifest, project, upload
from tests.slice import Slice


def is_executive(t: dict[str, Any]) -> bool:
    return t["kind"] == "narrative" and str(t["data"]["about"]).startswith("executive ")


def test_scope_review_by_agent_0_is_a_note_that_never_holds_or_reassesses(sl: Slice) -> None:
    base = shape(plain(sl))
    _, run_id = ai_run(sl, reviewer(lambda t: "DISSENT" if t["kind"] == "scope" else "CONCUR"))
    rep = sl.report(run_id)
    assert shape(rep) == base and rep["ai"]["validation"]["held_for_review"] == 0
    rows = sl.sql("SELECT target_ref, agent_id, verdict, effect FROM ai_validations "
                  "WHERE run_id=:r AND target_ref LIKE 'scope:%'", r=run_id)  # fmt: skip
    ((ref, agent, verdict, effect),) = rows
    assert (agent, verdict, effect) == (0, "DISSENT", "REVIEW_ITEM")
    (mid,) = sl.sql("SELECT manifest_id FROM assessment_runs WHERE run_id=:r", r=run_id)[0]
    assert ref == f"scope:{mid}"

    r = resolve(sl, run_id, ref, "OVERRULE")
    assert r.status_code == 200, r.text
    assert r.json()["reassessing"] is False and r.json()["assurance_revision"] == 1
    assert sl.status(run_id)["state"] in {"REPORT_READY", "PARTIAL"}
    sl.drain()
    assert [x["revision"] for x in reports(sl, run_id)] == [1]
    api = sl.call("GET", f"/api/v1/assessments/{run_id}/ai-validations", "carol").json()
    assert api["summary"]["overruled"] == 1 and api["summary"]["held_for_review"] == 0


def test_scope_packet_shows_the_authorisation_against_what_ran(sl: Slice) -> None:
    seen: list[dict[str, Any]] = []

    def decide(t: dict[str, Any]) -> str:
        if t["kind"] == "scope":
            seen.append(t["data"])
        return "CONCUR"

    ai_run(sl, reviewer(decide))
    (d,) = seen
    assert d["approval_separate_from_author"] is True and d["approver_count"] == 1
    assert d["allowed_adapters"] == ["fixture"] and d["expected_assets"] == 3
    assert d["tasks"] and {t["adapter_id"] for t in d["tasks"]} == {"fixture"}


def test_executive_summary_is_written_by_agent_8_and_reviewed(sl: Slice) -> None:
    agents: dict[str, int] = {}
    _, run_id = ai_run(sl, reviewer(lambda _t: "CONCUR"))
    for ref, agent in sl.sql("SELECT target_ref, agent_id FROM ai_validations WHERE run_id=:r",
                             r=run_id):  # fmt: skip
        agents[ref] = agent
    (nid,) = sl.sql("SELECT narrative_id FROM narratives WHERE run_id=:r AND purpose='executive'",
                    r=run_id)[0]  # fmt: skip
    assert agents[f"narrative:{nid}"] == 8
    rep = sl.report(run_id)
    assert rep["executive_summary"]["ai_generated"] and rep["executive_summary"]["summary"]
    html = sl.call("GET", f"/api/v1/reports/rep-{run_id}?format=html", "carol").text
    assert "Executive summary (AI-written)" in html


def test_a_dissent_on_the_executive_summary_holds_it(sl: Slice) -> None:
    _, run_id = ai_run(sl, reviewer(lambda t: "DISSENT" if is_executive(t) else "CONCUR"))
    rep = sl.report(run_id)
    assert "executive_summary" not in rep
    assert rep["ai"]["validation"]["held_for_review"] == 1
    v = sl.sql("SELECT assurance_verdict FROM narratives WHERE run_id=:r AND purpose='executive'",
               r=run_id)  # fmt: skip
    assert v == [("NEEDS_REVIEW",)]


def test_an_executive_summary_citing_a_held_finding_is_not_shown(sl: Slice) -> None:
    cited: list[str] = []

    def step(system: str, user: str) -> str:
        if not system.startswith(SYSTEM_PROMPT[:40]):
            subject = subject_of(user)
            if subject.purpose == "executive":
                cited.append(subject.facts[0].finding_id)
            return good_output(subject)
        return reviewer(lambda t: "DISSENT" if t["target_ref"] == f"finding:{cited[0]}"
                        else "CONCUR")(system, user)  # fmt: skip

    _, run_id = ai_run(sl, step)
    rep = sl.report(run_id)
    assert cited[0] in {f["finding_id"] for f in rep["pending_review"]}
    assert "executive_summary" not in rep
    v = sl.sql("SELECT assurance_verdict FROM narratives WHERE run_id=:r AND purpose='executive'",
               r=run_id)  # fmt: skip
    assert v == [("NEEDS_REVIEW",)]


def test_executive_summary_can_be_turned_off(sl: Slice) -> None:
    sl.worker.ai_executive_summary = False
    _, run_id = ai_run(sl, reviewer(lambda _t: "CONCUR"))
    assert "executive_summary" not in sl.report(run_id)
    assert sl.sql("SELECT count(*) FROM narratives WHERE run_id=:r AND purpose='executive'",
                  r=run_id)[0][0] == 0  # fmt: skip


# ---- Agent 4: questions for asset owners ----------------------------------------------------------
def nmap_ai_run(sl: Slice, step: Any) -> str:
    model = ScriptedModel(step)
    pid = project(sl)
    import_run(sl, pid, ["cmdb_import"])
    sl.enable_ai(model)
    sl.worker.ai_validation = True
    sl.worker.validation_concurrency = 1
    files = {"nmap_import": upload(sl, pid, "nmap_xml", gold("nmap.xml"))}
    m = manifest(sl, pid, ["nmap_import"])
    r = sl.launch(pid, m, ai_assist=True,
                  adapter_params={a: {"import_id": i} for a, i in files.items()})  # fmt: skip
    assert r.status_code == 202, r.text
    run_id = str(r.json()["run_id"])
    sl.drain()
    assert sl.status(run_id)["state"] in {"REPORT_READY", "PARTIAL"}
    return run_id


def test_agent_4_drafts_questions_for_accepted_exposure_findings(sl: Slice) -> None:
    run_id = nmap_ai_run(sl, reviewer(lambda _t: "CONCUR"))
    rep = sl.report(run_id)
    asked = [f for f in rep["findings"] if f.get("verification_questions")]
    assert asked, "the nmap findings should carry owner questions"
    for f in asked:
        vq = f["verification_questions"]
        assert vq["ai_generated"] and vq["questions"]
        assert all(q.endswith("?") for q in vq["questions"])
    subjects = {r for (r,) in sl.sql("SELECT subject_ref FROM narratives WHERE run_id=:r AND "
                                    "purpose='verification'", r=run_id)}  # fmt: skip
    assert {f["finding_id"] for f in asked} <= subjects
    html = sl.call("GET", f"/api/v1/reports/rep-{run_id}?format=html", "carol").text
    assert "Questions for asset owners (AI-written)" in html
    agents = {a for (a,) in sl.sql("SELECT agent_id FROM ai_validations WHERE run_id=:r",
                                    r=run_id)}  # fmt: skip
    assert 4 in agents


def test_an_instruction_is_not_a_verification_question(sl: Slice) -> None:
    def step(system: str, user: str) -> str:
        if system.startswith(SYSTEM_PROMPT[:40]):
            return reviewer(lambda _t: "CONCUR")(system, user)
        subject = subject_of(user)
        if subject.purpose == "verification":
            return good_output(subject, open_questions=["Close the port now."])
        return grounded(system, user)

    run_id = nmap_ai_run(sl, step)
    rep = sl.report(run_id)
    assert not any(f.get("verification_questions") for f in rep["findings"])
    rows = sl.sql("SELECT status, defects FROM llm_calls WHERE run_id=:r AND "
                  "purpose='verification'", r=run_id)  # fmt: skip
    assert rows and all("VERIFICATION_NOT_A_QUESTION" in json.dumps(d) for _, d in rows)
