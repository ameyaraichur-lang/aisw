"""The worker produces the same observations, controls and findings with either engine, and a pack
that needs Rego is refused at launch when OPA is not the engine (ADR-031)."""

from __future__ import annotations

from typing import Any

import pytest

from aisw.policy.opa import OpaClient, OpaEvaluator
from tests.slice import Slice


def outcomes(sl: Slice, run_id: str) -> dict[str, Any]:
    obs = sl.sql("SELECT asset_id, rule_id, outcome FROM observations WHERE run_id=:r "
                 "ORDER BY 1, 2", r=run_id)  # fmt: skip
    ctl = sl.sql("SELECT control_id, outcome FROM control_assessments WHERE run_id=:r ORDER BY 1",
                 r=run_id)  # fmt: skip
    fnd = sl.sql("SELECT stable_dedupe_key, assurance_verdict FROM findings WHERE run_id=:r "
                 "ORDER BY 1", r=run_id)  # fmt: skip
    return {"observations": [tuple(x) for x in obs], "controls": [tuple(x) for x in ctl],
            "findings": [tuple(x) for x in fnd], "state": sl.status(run_id)["state"]}  # fmt: skip


@pytest.mark.parametrize("fixture_set", ["baseline-ok", "baseline-partial"])
def test_python_and_opa_engines_produce_the_same_run(
    sl: Slice, opa_url: str, fixture_set: str
) -> None:
    hosts = ["host-1", "host-2", "host-3"]
    _, _, py_run = sl.full_run(hosts, fixture_set=fixture_set)
    sl.drain()
    opa = OpaEvaluator(OpaClient(opa_url))
    sl.container.evaluator = opa
    sl.worker.evaluator = opa
    _, _, opa_run = sl.full_run(hosts, fixture_set=fixture_set)
    sl.drain()
    a, b = outcomes(sl, py_run), outcomes(sl, opa_run)
    assert a["observations"] and a == b


def test_rego_pack_is_refused_at_launch_without_opa(sl: Slice) -> None:
    pid = sl.project()
    sl.inventory(pid, ["host-1"])
    m = sl.approved_manifest(pid, policy_version="config-baseline:1.0.0")
    r = sl.launch(pid, m)
    assert r.status_code != 202 and "POLICY_ENGINE_OPA_REQUIRED" in r.text
