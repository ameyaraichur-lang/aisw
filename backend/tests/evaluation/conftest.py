from __future__ import annotations

import pytest

from aisw.agents.correlation import build_scenarios
from aisw.contracts.analysis import CorrelationScenario
from aisw.llm.schema import Fact, NarrativeSubject
from aisw.llm.subject import scenario_subject
from aisw.policy.rubric import assess, builtin
from tests.unit.analysis_support import factors, finding

pytestmark = pytest.mark.evaluation


def make_subject(
    title: str = "SSH root login permitted", tier: str | None = "P1"
) -> NarrativeSubject:
    return NarrativeSubject(
        purpose="scenario", subject_ref="sc-1", title="Two weaknesses on asset-a", tier=tier,
        facts=[
            Fact(finding_id="f1", title=title, severity="HIGH", category="host_configuration",
                 asset_ids=["asset-a"], evidence_refs=["ev-f1"], control_ids=["CIS 5.2.1"]),
            Fact(finding_id="f2", title="Telnet service reachable on port 23", severity="HIGH",
                 category="network_exposure", asset_ids=["asset-a"], evidence_refs=["ev-f2"],
                 control_ids=[]),
        ],
        context=["Exploitability of the listed weaknesses was not tested"],
    )  # fmt: skip


@pytest.fixture
def subject() -> NarrativeSubject:
    return make_subject()


def real_scenario() -> tuple[CorrelationScenario, NarrativeSubject]:
    fs = [finding("f1"), finding("f2")]
    rs = {f.finding_id: assess(f.finding_id, factors(), builtin()) for f in fs}
    s = build_scenarios(fs, rs)[0]
    return s, scenario_subject(s, {f.finding_id: f for f in fs})
