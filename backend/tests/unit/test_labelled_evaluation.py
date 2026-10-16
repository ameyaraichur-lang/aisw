"""Labelled-set evaluation (ADR-025): the set is self-consistent and the scoring is honest."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from aisw.llm.evaluation import (
    LabelledSet,
    decide,
    evaluate,
    load_labelled_set,
    render_markdown,
    review_packets,
)
from aisw.llm.schema import NarrativeOutput
from aisw.llm.validation import ValidationOutput, build_prompt, check_output, resolve_aliases
from aisw.llm.validator import validate_narrative
from tests.evaluation.stub import OUTAGE, ScriptedModel, good_output
from tests.integration.test_analysis_pipeline import grounded

LS = load_labelled_set()
LABELS = {c.target.target_ref: c.label for c in LS.review}


def reviewer(decide_ref: Callable[[str], str]) -> ScriptedModel:
    def step(_system: str, user: str) -> str:
        targets = json.loads(user.removeprefix("DATA:\n"))["targets"]
        return json.dumps({"verdicts": [
            {"target_ref": t["target_ref"], "verdict": (v := decide_ref(t["target_ref"])),
             "validator_confidence": "MEDIUM",
             "issues": [] if v in {"CONCUR", "INSUFFICIENT_EVIDENCE"} else [{
                 "code": "OUTCOME_NOT_SUPPORTED", "explanation": "The facts do not support this.",
                 "evidence_refs": t["evidence_refs"][:1]}]}
            for t in targets]})  # fmt: skip

    return ScriptedModel(step)


ORACLE = reviewer(lambda ref: "DISSENT" if LABELS[ref] == "DEFECT" else "CONCUR")
NOW = lambda: datetime(2026, 10, 16, tzinfo=UTC)  # noqa: E731


# ---- the set itself -------------------------------------------------------------------------------
def test_every_agent_has_a_clean_and_a_planted_defect() -> None:
    for agent in range(9):
        labels = {c.label for c in LS.review if c.agent_id == agent}
        assert labels == {"CLEAN", "DEFECT"}, f"agent {agent}"
    assert {n.subject.purpose for n in LS.narration} == {
        "scenario", "recommendation", "verification", "executive"}  # fmt: skip


def test_an_oracle_reply_passes_production_grounding_for_every_packet() -> None:
    for packet, _ in review_packets(LS):
        _, user = build_prompt(packet)
        out = resolve_aliases(
            ValidationOutput.model_validate_json(ORACLE.complete(system="", user=user, schema={},
                                                                 timeout=1)), packet)  # fmt: skip
        assert check_output(out, packet) == [], packet.packet_id


def test_every_narration_subject_admits_a_grounded_answer_and_parroting_is_refused() -> None:
    for n in LS.narration:
        echo = NarrativeOutput.model_validate_json(good_output(n.subject))
        if n.case_id == "n-injection":  # repeating the planted instruction is a compliance claim
            assert validate_narrative(echo, n.subject) == ["UNSUPPORTED_COMPLIANCE_CLAIM"]
            plain = echo.model_copy(update={"claims": [echo.claims[0].model_copy(
                update={"text": "A host configuration weakness was recorded."})]})  # fmt: skip
            assert validate_narrative(plain, n.subject) == []
        else:
            assert validate_narrative(echo, n.subject) == [], n.case_id


def test_duplicate_case_ids_are_refused(tmp_path: Any) -> None:
    raw = json.loads(LS.model_dump_json())
    raw["review"].append(raw["review"][0])
    p = tmp_path / "dup.json"
    p.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="duplicate case_id"):
        load_labelled_set(p)


# ---- scoring --------------------------------------------------------------------------------------
def test_an_oracle_reviewer_is_usable() -> None:
    rep = evaluate(LS, ScriptedModel(grounded), ORACLE, now=NOW)
    m = rep.metrics
    assert (m["recall"], m["false_dissent_rate"], m["unscored"]) == (1.0, 0.0, 0)
    assert rep.decision == "USABLE" and rep.reasons == []
    assert m["narration_validated"] == len(LS.narration) - 1  # the stub parrots the injection
    assert m["narration_defects"] == {"UNSUPPORTED_COMPLIANCE_CLAIM": 1}


def test_a_reviewer_that_always_concurs_is_not_usable() -> None:
    rep = evaluate(LS, None, reviewer(lambda _r: "CONCUR"), now=NOW)
    assert rep.metrics["recall"] == 0.0 and rep.decision == "NOT_USABLE"
    assert any("recall" in r for r in rep.reasons) and rep.narration == []


def test_a_reviewer_that_always_dissents_is_not_usable() -> None:
    rep = evaluate(LS, None, reviewer(lambda _r: "DISSENT"), now=NOW)
    assert rep.metrics["recall"] == 1.0 and rep.metrics["false_dissent_rate"] == 1.0
    assert rep.decision == "NOT_USABLE" and any("false dissent" in r for r in rep.reasons)


def test_concern_counts_as_detection_but_not_as_dissent() -> None:
    rep = evaluate(LS, None, reviewer(lambda r: "CONCERN" if LABELS[r] == "DEFECT" else "CONCUR"),
                   now=NOW)  # fmt: skip
    assert rep.metrics["recall"] == 1.0 and rep.metrics["dissented_on_defect"] == 0


def test_an_unavailable_reviewer_is_inconclusive_not_usable() -> None:
    rep = evaluate(LS, None, ScriptedModel(OUTAGE), now=NOW)
    assert rep.metrics["unscored"] == len(LS.review) and rep.decision == "INCONCLUSIVE"
    assert all(r.verdict is None and r.packet_status == "UNAVAILABLE" for r in rep.review)


def test_one_invalid_packet_leaves_only_its_cases_unscored() -> None:
    def step(system: str, user: str) -> str:
        if '"agent": "Scope & Authorization Gate"' in user:
            return (
                '{"verdicts": [{"target_ref": "scope:nope", "verdict": "CONCUR", '
                '"validator_confidence": "LOW"}]}'
            )
        return ORACLE.complete(system=system, user=user, schema={}, timeout=1)

    rep = evaluate(LS, None, ScriptedModel(step), now=NOW)
    a0 = [r for r in rep.review if r.agent_id == 0]
    assert all(r.packet_status == "VALIDATOR_INVALID" and r.verdict is None for r in a0)
    assert rep.metrics["unscored"] == len(a0)
    assert decide(rep.metrics)[0] == ("INCONCLUSIVE" if len(a0) / len(LS.review) > 0.1
                                      else "USABLE")  # fmt: skip


def test_markdown_lists_every_case_and_the_decision() -> None:
    rep = evaluate(LS, ScriptedModel(grounded), ORACLE, now=NOW)
    md = render_markdown(rep)
    assert "**Decision: USABLE**" in md and "labelled-1.0.0" in md and "2026-10-16" in md
    assert all(f"| {c.case_id} |" in md for c in LS.review)
    assert all(f"| {n.case_id} |" in md for n in LS.narration)


def test_the_set_round_trips_through_its_model() -> None:
    assert LabelledSet.model_validate_json(LS.model_dump_json()) == LS
