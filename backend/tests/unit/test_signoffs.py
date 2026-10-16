"""Sign-off register (P0-6, P0-7, A-1): pending items keep their labels, an approval needs a
decider, a date, a reference and the hash of the exact artefact, and stale approvals fail."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from aisw.agents.architecture import build_recommendations, builtin_catalog
from aisw.policy import signoffs
from aisw.policy.rubric import assess
from aisw.policy.rubric import builtin as builtin_rubric
from aisw.policy.signoffs import Register, problems, render_markdown, sha256_file
from aisw.reporting.report import build_report
from tests.unit.analysis_support import factors, finding
from tests.unit.test_coverage_report import inputs

REPO = Path(__file__).resolve().parents[3]
RUBRIC = "backend/aisw/policy/rubrics/risk-rubric-1.0.0.json"
EXPECTED = {
    "risk-rubric-1.0.0": "P0-6", "architecture-catalog-1.0.0": "P0-6", "ai-evaluation-bar": "P0-6",
    "config-baseline-1.0.0": "P0-6", "image-baseline-1.0.0": "P0-6", "avp-triggers-1.0.0": "P0-6",
    "licence-review": "P0-7", "astra-data-approval": "A-1",
}  # fmt: skip


def raw() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((REPO / "backend/aisw/policy/signoffs.json").read_text())
    return data


def approve(data: dict[str, Any], signoff_id: str, sha: str) -> dict[str, Any]:
    out = copy.deepcopy(data)
    for s in out["signoffs"]:
        if s["id"] == signoff_id:
            s["status"] = "APPROVED"
            s["decision"] = {
                "by": "Policy Owner",
                "at": "2026-11-01",
                "ref": "DEC-1",
                "sha256": sha,
            }
    return out


def test_every_open_sign_off_is_recorded_pending_with_an_owner_and_next_step() -> None:
    reg = signoffs.builtin()
    assert {s.id: s.plan_ref for s in reg.signoffs} == EXPECTED
    for s in reg.signoffs:
        assert s.status == "PENDING" and s.decision is None, s.id
        assert len(s.owner) > 5 and len(s.next_step) > 20 and s.label_while_pending
    assert problems(reg, REPO) == []


def test_decision_must_match_status() -> None:
    data = raw()
    data["signoffs"][0]["status"] = "APPROVED"
    with pytest.raises(ValidationError, match="decision is recorded exactly"):
        Register.model_validate(data)
    data = raw()
    data["signoffs"][0]["decision"] = {
        "by": "x",
        "at": "2026-11-01",
        "ref": "r",
        "sha256": "0" * 64,
    }
    with pytest.raises(ValidationError, match="decision is recorded exactly"):
        Register.model_validate(data)
    data = approve(raw(), "risk-rubric-1.0.0", "not-a-hash")
    with pytest.raises(ValidationError):
        Register.model_validate(data)
    data = raw()
    data["signoffs"].append(data["signoffs"][0])
    with pytest.raises(ValidationError, match="unique"):
        Register.model_validate(data)


def test_approval_binds_to_the_exact_artefact(tmp_path: Path) -> None:
    good = Register.model_validate(approve(raw(), "risk-rubric-1.0.0", sha256_file(REPO / RUBRIC)))
    assert problems(good, REPO) == [] and good.status_of("risk-rubric-1.0.0") == "APPROVED"
    stale = Register.model_validate(approve(raw(), "risk-rubric-1.0.0", "0" * 64))
    assert problems(stale, REPO) == [
        f"risk-rubric-1.0.0: {RUBRIC} changed after the APPROVED decision DEC-1"
    ]
    assert any("does not exist" in p for p in problems(good, tmp_path))
    assert good.status_of("risk-rubric-9.9.9") == "UNRECORDED"
    assert "APPROVED by Policy Owner on 2026-11-01 (DEC-1)" in render_markdown(good)


def test_rendered_register_is_current() -> None:
    r = subprocess.run([sys.executable, str(REPO / "tools/signoffs.py"), "--check"],  # noqa: S603
                       capture_output=True, text=True, cwd=REPO / "backend")  # fmt: skip
    assert r.returncode == 0, r.stderr
    assert (REPO / "docs/implementation/signoffs.md").read_text() == render_markdown(
        signoffs.builtin()
    )


def risk(version: str = "1.0.0") -> dict[str, Any]:
    a = assess("f-1", factors(), builtin_rubric()).model_dump(mode="json")
    return {**a, "rubric_version": version}


def recommendation() -> dict[str, Any]:
    f = finding("f-1")
    [rec] = build_recommendations(
        tenant_id="t", findings=[f], risks={}, assets={"asset-a": ("ops", "high")},
        catalog=builtin_catalog(),
    )  # fmt: skip
    return rec.model_dump(mode="json")


def test_report_carries_the_pending_label_of_what_it_relies_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, body, _ = build_report(inputs())
    assert not any("sample" in x for x in body["limitations"])  # nothing used, nothing claimed
    _, body, _ = build_report(inputs(risks={"f-1": risk()}, recommendations=[recommendation()]))
    text = " ".join(body["limitations"])
    assert (
        "sample rubric awaiting policy-owner approval" in text
        and "(risk-rubric-1.0.0: PENDING)" in text
    )
    assert "sample catalog" in text and "(architecture-catalog-1.0.0: PENDING)" in text
    _, body, _ = build_report(inputs(policy_version="config-baseline:1.0.0"))
    assert any("(config-baseline-1.0.0: PENDING)" in x for x in body["limitations"])
    _, body, _ = build_report(inputs(risks={"f-1": risk("9.9.9")}))
    assert any("risk-rubric-9.9.9 has no sign-off record" in x for x in body["limitations"])
    approved = Register.model_validate(
        approve(raw(), "risk-rubric-1.0.0", sha256_file(REPO / RUBRIC))
    )
    monkeypatch.setattr(signoffs, "builtin", lambda: approved)
    _, body, _ = build_report(inputs(risks={"f-1": risk()}))
    assert not any("risk-rubric" in x for x in body["limitations"])
