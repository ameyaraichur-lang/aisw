"""Agents 0, 4 and 8 building blocks (ADR-024): subjects, the scope packet, effects and checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from aisw.contracts.domain import CoverageLedger
from aisw.contracts.enums import Severity
from aisw.llm import packets as pk
from aisw.llm.routing import RecordReplayClient
from aisw.llm.schema import NarrativeOutput
from aisw.llm.subject import EXECUTIVE_MAX_FACTS, executive_subject, verification_subject
from aisw.llm.validation import EFFECT, effect_for
from aisw.llm.validator import validate_narrative
from tests.evaluation.stub import ScriptedModel
from tests.unit.analysis_support import finding


def ledger(
    segment: str = "fixture-group-1", expected: int = 3, reconciled: int = 3
) -> CoverageLedger:
    return CoverageLedger(
        tenant_id="ten-1", run_id="run-1", segment=segment, expected_count=expected,
        discovered_count=reconciled, reconciled_count=reconciled, excluded_count=0,
        unsupported_count=0, unknown_count=expected - reconciled, source_ok=True,
    )  # fmt: skip


def output(subject_fid: str, asset: str, questions: list[str]) -> NarrativeOutput:
    return NarrativeOutput.model_validate({
        "summary": f"One recorded weakness relates to {asset}.",
        "claims": [{"text": "The assessment recorded a weakness.", "finding_ids": [subject_fid],
                    "asset_ids": [asset]}],
        "open_questions": questions,
    })  # fmt: skip


# ---- effects --------------------------------------------------------------------------------------
@pytest.mark.parametrize("verdict", ["CONCUR", "CONCERN", "DISSENT", "INSUFFICIENT_EVIDENCE",
                                     "UNAVAILABLE"])  # fmt: skip
def test_only_a_scope_dissent_is_softened_to_a_review_item(verdict: str) -> None:
    assert effect_for("finding", verdict) == EFFECT.get(verdict, "NONE")
    expected = "REVIEW_ITEM" if verdict == "DISSENT" else EFFECT.get(verdict, "NONE")
    assert effect_for("scope", verdict) == expected
    assert effect_for("scope", verdict) != "HOLD_FOR_REVIEW"


# ---- Agent 4 --------------------------------------------------------------------------------------
def test_verification_subject_carries_observed_and_expected_values_clipped() -> None:
    f = finding("f1", asset="host-2", category="network_exposure")
    s = verification_subject(f, ([22, 445], "x" * 500))
    assert (s.purpose, s.subject_ref, s.tier) == ("verification", "f1", None)
    assert s.context[0] == "Observed: [22, 445]"
    assert s.context[1].endswith("...[truncated]") and len(s.context[1]) < 250
    assert s.context[2] == "Observed open ports: port 22, port 445"
    assert verification_subject(f, None).context == []
    assert len(verification_subject(f, ("PermitRootLogin yes", "no")).context) == 2
    assert len(verification_subject(f, ([True, 2], None)).context) == 2  # not a port list


def test_observed_ports_are_groundable_and_others_are_not() -> None:
    f = finding("f1", asset="host-2", category="network_exposure")
    s = verification_subject(f, ([23, 443], [21, 23]))
    assert s.context[3] == "Ports named in the requirement: port 21, port 23"
    ok = output(
        "f1",
        "host-2",
        [
            "Is port 23 on host-2 meant to accept connections, given port 21 "
            "is also named in the requirement?"
        ],
    )
    assert validate_narrative(ok, s) == []
    invented = output("f1", "host-2", ["Is port 3389 on host-2 meant to be reachable?"])
    assert validate_narrative(invented, s) == ["UNGROUNDED_PORT:3389"]


@pytest.mark.parametrize(
    ("questions", "defect"),
    [([], "NO_VERIFICATION_QUESTIONS"), (["Close port 445."], "VERIFICATION_NOT_A_QUESTION"),
     (["Is 445 meant to be open?", "Disable SMBv1."], "VERIFICATION_NOT_A_QUESTION")],
)  # fmt: skip
def test_verification_output_must_ask_questions(questions: list[str], defect: str) -> None:
    f = finding("f1", asset="host-2")
    s = verification_subject(f, None)
    assert defect in validate_narrative(output("f1", "host-2", questions), s)


def test_good_verification_questions_pass_and_other_purposes_need_none() -> None:
    f = finding("f1", asset="host-2")
    ok = output("f1", "host-2", ["Is the exposure recorded for host-2 intended?"])
    assert validate_narrative(ok, verification_subject(f, None)) == []
    invented = output("f1", "host-2", ["Is port 445 on host-2 meant to be reachable?"])
    assert validate_narrative(invented, verification_subject(f, None)) == ["UNGROUNDED_PORT:445"]
    ex = executive_subject([f], [ledger()])
    assert ex is not None
    assert validate_narrative(output("f1", "host-2", []), ex) == []


# ---- Agent 8 --------------------------------------------------------------------------------------
def test_executive_subject_ranks_by_severity_and_states_coverage() -> None:
    fs = [finding("low", severity=Severity.LOW, asset="a"),
          finding("crit", severity=Severity.CRITICAL, asset="b"),
          finding("high", severity=Severity.HIGH, asset="b")]  # fmt: skip
    s = executive_subject(fs, [ledger(expected=3, reconciled=2)])
    assert s is not None and (s.purpose, s.subject_ref) == ("executive", "executive")
    assert [x.finding_id for x in s.facts] == ["crit", "high", "low"]
    assert s.context[0] == "3 failed check(s) on 2 asset(s): 1 critical, 1 high, 1 low."
    assert "2 of 3 expected asset(s) reconciled; incomplete." in s.context[1]


def test_executive_subject_is_bounded_and_absent_without_findings() -> None:
    assert executive_subject([], [ledger()]) is None
    many = [finding(f"f{i}") for i in range(EXECUTIVE_MAX_FACTS + 5)]
    s = executive_subject(many, [])
    assert s is not None and len(s.facts) == EXECUTIVE_MAX_FACTS
    assert s.context[0].startswith(f"{EXECUTIVE_MAX_FACTS + 5} failed check(s)")


# ---- Agent 0 --------------------------------------------------------------------------------------
def test_scope_target_states_the_authorisation_and_what_ran() -> None:
    manifest = {
        "targets": [{"kind": "asset_group", "selector": "g1"}], "exclusions": [],
        "domains": ["host"], "allowed_adapters": ["fixture"],
        "profiles": {"fixture": {"profile_id": "FIXTURE_BASELINE"}}, "expires_at": "2026-10-17",
    }  # fmt: skip
    t = pk.scope_target(
        "m-1", manifest, author="alice", approvers=["bob"],
        permit={"allowed_task_types": ["collect"]},
        tasks=[{"adapter_id": "fixture", "task_type": "collect", "status": "SUCCEEDED"}],
        expected_assets=3,
    )  # fmt: skip
    assert (t.target_ref, t.kind) == ("scope:m-1", "scope")
    assert t.data["approval_separate_from_author"] is True and t.data["approver_count"] == 1
    assert t.data["permit_task_types"] == ["collect"] and t.data["expected_assets"] == 3
    self_approved = pk.scope_target("m-1", manifest, author="alice", approvers=["alice"],
                                    permit=None, tasks=[], expected_assets=0)  # fmt: skip
    assert self_approved.data["approval_separate_from_author"] is False
    assert self_approved.data["permit_task_types"] == []


# ---- replay keeps per-run identifiers aligned -----------------------------------------------------
def test_replayed_reply_refers_to_the_replaying_runs_identifiers(tmp_path: Path) -> None:
    a, b = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
    live = ScriptedModel(lambda _s, u: f'{{"target_ref": "scope:{u.split()[-1]}"}}')
    rec = RecordReplayClient(live, tmp_path, "record")
    assert rec.complete(system="s", user=f"DATA: {a}", schema={}, timeout=1) == (
        f'{{"target_ref": "scope:{a}"}}'
    )
    rep = RecordReplayClient(None, tmp_path, "replay", model_id=live.model_id)
    assert rep.complete(system="s", user=f"DATA: {b}", schema={}, timeout=1) == (
        f'{{"target_ref": "scope:{b}"}}'
    )
    stored = next(tmp_path.iterdir()).read_text()
    assert a not in stored and "<id0>" in stored
