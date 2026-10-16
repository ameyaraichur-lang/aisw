"""Roadmap and scenario-chain read models over a real run."""

from __future__ import annotations

from sqlalchemy import text

from aisw.core.db import tenant_connection
from tests.integration.test_analysis_pipeline import run_to
from tests.slice import Slice

EXPECTED = ["host-1", "host-2", "host-3"]


def test_roadmap_without_criticality_schedules_nothing(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    r = sl.call("GET", f"/api/v1/assessments/{run_id}/roadmap", "carol")
    assert r.status_code == 200, r.text
    d = r.json()
    assert all(w["items"] == [] for w in d["waves"]) and len(d["unrated"]) == 2
    assert d["catalog_signoff"] != "APPROVED" and d["edges"] == []
    assert sl.call("GET", f"/api/v1/assessments/{run_id}/roadmap", "paula").status_code == 403
    assert sl.call("GET", f"/api/v1/assessments/{run_id}/roadmap", "dave").status_code in {403, 404}


def test_roadmap_places_rated_work_and_the_chain_names_each_finding(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    run_to(sl, run_id, "POLICY_EVALUATION")
    with tenant_connection(sl.worker_engine, "tenant-a") as c:
        c.execute(
            text("UPDATE assets SET criticality='high', criticality_source='test-cmdb' "
                 "WHERE asset_id='host-2'")
        )  # fmt: skip
    sl.drain()
    d = sl.call("GET", f"/api/v1/assessments/{run_id}/roadmap", "carol").json()
    wave2 = next(w for w in d["waves"] if w["wave"] == 2)
    assert len(wave2["items"]) == 2 and d["unrated"] == []
    assert all(
        c["reason"] == "Risk tier P2" and c["effort"]["value"] is None for c in wave2["items"]
    )

    sc = sl.call("GET", f"/api/v1/assessments/{run_id}/scenarios", "carol").json()
    chain = sc[0]["chain"]
    assert {c["title"] for c in chain} == {
        "Direct root login over SSH is disabled",
        "Minimum password length is at least 12",
    }
    assert all(c["basis"] == "OBSERVED" and c["severity"] in {"HIGH", "MEDIUM"} for c in chain)
