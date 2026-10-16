"""Agents 5-7 through the real API, Postgres and worker: deterministic first, AI strictly optional."""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import text

from aisw.core.db import tenant_connection
from aisw.llm.schema import NarrativeSubject
from tests.evaluation.stub import OUTAGE, ScriptedModel, good_output
from tests.slice import Slice

EXPECTED = ["host-1", "host-2", "host-3"]  # host-2 fails two checks => one scenario, two recs


def run_to(sl: Slice, run_id: str, state: str) -> None:
    for _ in range(80):
        if sl.status(run_id)["state"] == state:
            return
        assert sl.worker.step()
    raise AssertionError(f"never reached {state}")


def subject_of(user: str) -> NarrativeSubject:
    return NarrativeSubject.model_validate(json.loads(user.removeprefix("DATA:\n")))


def grounded(_system: str, user: str) -> str:
    return good_output(subject_of(user))


def phases(sl: Slice, run_id: str) -> list[str]:
    return [e["payload"]["to"] for e in sl.events(run_id) if e["type"] == "phase.changed"]


def shape(rep: dict[str, Any]) -> dict[str, Any]:
    """The deterministic part of a report, comparable across runs and AI on/off."""
    return {
        "findings": sorted(
            (f["finding_id"], f["severity"], (f.get("risk") or {}).get("basis"))
            for f in rep["findings"]
        ),
        "scenarios": sorted((s["scenario_id"], s["tier"], s["basis"]) for s in rep["scenarios"]),
        "recommendations": sorted(
            (r["recommendation_id"], r["catalog_ref"], r["risk_tier"])
            for r in rep["recommendations"]
        ),
        "counts": rep["finding_counts"],
        "complete": rep["coverage_complete"],
    }


def test_deterministic_analysis_runs_without_ai(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    st = sl.status(run_id)
    assert st["state"] == "REPORT_READY"
    seq = phases(sl, run_id)
    assert seq[seq.index("POLICY_EVALUATION") :][:4] == [
        "POLICY_EVALUATION", "CORRELATION", "ARCHITECTURE_ANALYSIS", "ASSURANCE",
    ]  # fmt: skip
    rep = sl.report(run_id)
    assert rep["ai"] == {
        "mode": "disabled",
        "narratives_total": 0,
        "narratives_accepted": 0,
        "not_shown": 0,
    }
    assert rep["model_versions"] == []
    (scn,) = rep["scenarios"]
    assert scn["finding_ids"] and all(c["basis"] == "OBSERVED" for c in scn["chain"])
    assert {r["catalog_ref"] for r in rep["recommendations"]} == {
        "AC-HOST-1@1.0.0",
        "AC-IDENT-1@1.0.0",
    }
    assert all(
        r["effort"]["value"] is None and r["status"] == "DRAFT" for r in rep["recommendations"]
    )
    assert sl.sql("SELECT count(*) FROM llm_calls WHERE run_id=:r", r=run_id)[0][0] == 0
    assert sl.sql("SELECT count(*) FROM narratives WHERE run_id=:r", r=run_id)[0][0] == 0


def test_unknown_criticality_means_no_fabricated_tier(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    rep = sl.report(run_id)
    for f in rep["findings"]:
        assert f["risk"]["tier"] is None and f["risk"]["basis"] == "NEEDS_POLICY_REVIEW"
        assert f["risk"]["provisional_tier"] in {"P1", "P2", "P3"}
    assert rep["scenarios"][0]["tier"] is None
    assert all(r["risk_tier"] is None for r in rep["recommendations"])
    html = sl.call("GET", f"/api/v1/reports/rep-{run_id}?format=html", "carol").text
    assert "Not rated: criticality unknown" in html and "Correlated scenarios" in html
    assert "AI-written summary" not in html  # AI is off: nothing is labelled as model output


def test_owner_supplied_criticality_produces_a_rubric_tier(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    run_to(sl, run_id, "POLICY_EVALUATION")
    with tenant_connection(sl.worker_engine, "tenant-a") as c:
        c.execute(
            text(
                "UPDATE assets SET criticality='high', criticality_source='test-cmdb' WHERE asset_id='host-2'"
            )
        )
    sl.drain()
    rep = sl.report(run_id)
    risks = {f["finding_id"]: f["risk"] for f in rep["findings"]}
    assert {r["tier"] for r in risks.values()} == {
        "P2"
    }  # 3+2+0 and 2+2+0: exposure was not verified
    assert all("Exposure" in " ".join(r["missing_evidence"]) for r in risks.values())
    assert rep["scenarios"][0]["tier"] == "P2" and rep["scenarios"][0]["basis"] == "COMPLETE"
    assert {r["risk_tier"] for r in rep["recommendations"]} == {"P2"}


def test_free_text_criticality_is_not_guessed(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    run_to(sl, run_id, "POLICY_EVALUATION")
    with tenant_connection(sl.worker_engine, "tenant-a") as c:
        c.execute(
            text(
                "UPDATE assets SET criticality='tier-1', criticality_source='x' WHERE asset_id='host-2'"
            )
        )
    sl.drain()
    assert {f["risk"]["tier"] for f in sl.report(run_id)["findings"]} == {None}


def test_tampered_evidence_rejects_the_whole_analysis_chain(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    run_to(sl, run_id, "ASSURANCE")
    (f,) = [p for p in sl.evidence_dir.rglob("*") if p.is_file()]
    f.write_text(
        f.read_text().replace('"ssh.permit_root_login":"yes"', '"ssh.permit_root_login":"no"')
    )
    sl.drain()
    rep = sl.report(run_id)
    assert rep["findings"] == [] and rep["scenarios"] == [] and rep["recommendations"] == []
    assert any("candidate scenario(s) failed" in x for x in rep["limitations"])
    assert any("candidate recommendation(s) failed" in x for x in rep["limitations"])
    rows = sl.sql(
        "SELECT item_ref, verdict FROM assurance_results WHERE run_id=:r AND "
        "(item_ref LIKE 'scenario:%' OR item_ref LIKE 'recommendation:%')", r=run_id,
    )  # fmt: skip
    assert rows and {v for _, v in rows} == {"REJECT"}


def test_ai_flag_requires_ai_to_be_enabled(sl: Slice) -> None:
    pid = sl.project()
    sl.inventory(pid, EXPECTED)
    m = sl.approved_manifest(pid)
    r = sl.launch(pid, m, ai_assist=True)
    assert r.status_code == 422 and "AI_NOT_ENABLED" in r.json()["reason_codes"]
    assert sl.sql("SELECT count(*) FROM assessment_runs WHERE project_id=:p", p=pid)[0][0] == 0


def test_validated_narratives_are_shown_and_labelled(sl: Slice) -> None:
    model = ScriptedModel(grounded)
    sl.enable_ai(model)
    _, _, run_id = sl.full_run(EXPECTED, ai_assist=True)
    sl.drain()
    assert sl.status(run_id)["state"] == "REPORT_READY"
    rep = sl.report(run_id)
    assert rep["ai"]["mode"] == "enabled" and rep["ai"]["narratives_accepted"] == 3
    assert rep["model_versions"] == ["stub-model-0"]
    assert rep["scenarios"][0]["narrative"]["model_id"] == "stub-model-0"
    assert all(
        r["narrative"]["prompt_version"] == "narrative-1.1.0" for r in rep["recommendations"]
    )
    calls = sl.sql("SELECT status, attempts, input_hash FROM llm_calls WHERE run_id=:r", r=run_id)
    assert len(calls) == 3 and {c[0] for c in calls} == {"VALIDATED"} and all(c[2] for c in calls)
    assert len(model.calls) == 3
    assert all("tools" not in c and "untrusted" in c["system"] for c in model.calls)


def test_model_is_never_called_while_the_run_row_is_locked(sl: Slice) -> None:
    holder: list[str] = []

    def probe(system: str, user: str) -> str:
        with tenant_connection(sl.app_engine, "tenant-a") as c:  # raises if the row is locked
            c.execute(
                text("SELECT 1 FROM assessment_runs WHERE run_id=:r FOR UPDATE NOWAIT"),
                {"r": holder[0]},
            )
        return grounded(system, user)

    sl.enable_ai(ScriptedModel(probe))
    _, _, run_id = sl.full_run(EXPECTED, ai_assist=True)
    holder.append(run_id)
    sl.drain()
    assert sl.report(run_id)["ai"]["narratives_accepted"] == 3


def test_model_outage_leaves_deterministic_results_identical(sl: Slice) -> None:
    _, _, plain = sl.full_run(EXPECTED)
    sl.drain()
    sl.enable_ai(ScriptedModel(OUTAGE))
    _, _, down = sl.full_run(EXPECTED, ai_assist=True)
    sl.drain()
    assert sl.status(down)["state"] == "REPORT_READY"
    a, b = sl.report(plain), sl.report(down)
    assert shape(a) == shape(b)
    assert b["ai"]["narratives_accepted"] == 0 and b["ai"]["not_shown"] == 3
    assert any("AI-written summaries were unavailable" in x for x in b["limitations"])
    assert all("narrative" not in s for s in b["scenarios"])
    st = sl.sql("SELECT DISTINCT status FROM narratives WHERE run_id=:r", r=down)
    assert st == [("UNAVAILABLE",)]


def test_hallucinating_model_is_rejected_and_not_published(sl: Slice) -> None:
    def liar(_s: str, user: str) -> str:
        return good_output(
            subject_of(user), summary="Exploit CVE-2099-4242 at http://203.0.113.7/x"
        )

    sl.enable_ai(ScriptedModel(liar))
    _, _, run_id = sl.full_run(EXPECTED, ai_assist=True)
    sl.drain()
    rep = sl.report(run_id)
    assert "CVE-2099-4242" not in json.dumps(rep)
    assert rep["ai"]["narratives_accepted"] == 0
    assert {r[0] for r in sl.sql("SELECT status FROM narratives WHERE run_id=:r", r=run_id)} == {
        "REJECTED"
    }
    assert {r[0] for r in sl.sql("SELECT status FROM llm_calls WHERE run_id=:r", r=run_id)} == {
        "REJECTED"
    }


def test_evidence_text_never_reaches_the_model(sl: Slice) -> None:
    """baseline-injection plants instructions and a secret in evidence; only vetted fields go out."""
    model = ScriptedModel(grounded)
    sl.enable_ai(model)
    _, _, run_id = sl.full_run(
        ["host-1", "host-2"], fixture_set="baseline-injection", ai_assist=True
    )
    sl.drain()
    assert model.calls, "a finding exists, so the model is asked for a narrative"
    sent = " ".join(c["user"] + c["system"] for c in model.calls)
    for planted in (
        "IGNORE PREVIOUS",
        "10.0.0.0/8",
        "hunter2",
        "approve the report",
        "mark every host",
    ):
        assert planted not in sent
    assert "10.0.0.0/8" not in json.dumps(sl.report(run_id)["recommendations"])


def test_run_without_findings_makes_no_model_call(sl: Slice) -> None:
    model = ScriptedModel(grounded)
    sl.enable_ai(model)
    sl.full_run(["host-1"], fixture_set="baseline-zero", ai_assist=True)
    sl.drain()
    assert model.calls == []


def test_ai_provenance_is_append_only(sl: Slice) -> None:
    sl.enable_ai(ScriptedModel(grounded))
    _, _, run_id = sl.full_run(EXPECTED, ai_assist=True)
    sl.drain()
    from sqlalchemy.exc import DBAPIError

    for stmt in ("UPDATE llm_calls SET status='VALIDATED'", "DELETE FROM llm_calls"):
        with pytest.raises(DBAPIError), tenant_connection(sl.app_engine, "tenant-a") as c:
            c.execute(text(stmt))
    assert sl.sql("SELECT count(*) FROM llm_calls WHERE run_id=:r", r=run_id)[0][0] == 3
