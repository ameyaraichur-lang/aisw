"""Asset Explorer API: reconciled assets with sourced owner/criticality, latest posture per rule,
accepted findings, filters, permissions and tenant isolation."""

from __future__ import annotations

from tests.slice import Slice


def test_assets_list_filters_and_facets(sl: Slice) -> None:
    pid, _, run_id = sl.full_run(["host-1", "host-2", "host-3"])
    sl.drain()
    r = sl.call("GET", f"/api/v1/assets?project_id={pid}", "alice")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["total"] == 3 and [a["asset_id"] for a in d["items"]] == ["host-1", "host-2", "host-3"]
    a = d["items"][0]
    assert (
        a["last_run_id"] == run_id and a["match_confidence"] == "HIGH" and a["asset_type"] == "host"
    )
    assert a["owner"] is None and a["owner_source"] is None  # never inferred
    assert d["types"] == [
        {"asset_type": "host", "count": 3, "owner_unknown": 3, "low_confidence": 0}
    ]
    one = sl.call("GET", f"/api/v1/assets?project_id={pid}&q=host-2", "alice").json()
    assert [x["asset_id"] for x in one["items"]] == ["host-2"]
    assert (
        sl.call("GET", f"/api/v1/assets?project_id={pid}&owner=known", "alice").json()["total"] == 0
    )
    assert sl.call("GET", f"/api/v1/assets?project_id={pid}&q=%25", "alice").json()["total"] == 3
    assert sl.call("GET", "/api/v1/assets?confidence=BOGUS", "alice").status_code == 422


def test_asset_detail_shows_latest_posture_and_accepted_findings(sl: Slice) -> None:
    pid, _, run_id = sl.full_run(["host-1", "host-2", "host-3"])
    sl.drain()
    r = sl.call("GET", f"/api/v1/assets/{pid}/host-2", "alice")
    assert r.status_code == 200, r.text
    d = r.json()
    outcomes = {p["rule_id"]: p["outcome"] for p in d["posture"]}
    assert "FAIL" in outcomes.values() and all(p["run_id"] == run_id for p in d["posture"])
    assert d["runs"][0]["run_id"] == run_id and d["runs"][0]["status"] == "SCANNED"
    assert {f["title"] for f in d["findings"]} == {
        "Direct root login over SSH is disabled",
        "Minimum password length is at least 12",
    }
    assert d["findings_visible"] is True and d["relationships"] is None

    # a later run supersedes the posture; history keeps both runs
    sl.clock.advance(minutes=1)
    m = sl.approved_manifest(pid)
    second = sl.launch(pid, m)
    assert second.status_code == 202
    sl.drain()
    d2 = sl.call("GET", f"/api/v1/assets/{pid}/host-2", "alice").json()
    later = str(second.json()["run_id"])
    assert {p["run_id"] for p in d2["posture"]} == {later}
    assert [x["run_id"] for x in d2["runs"]][:2] == [later, run_id]
    assert len(d2["findings"]) == 2  # one per stable key, the latest run's


def test_asset_views_are_permissioned_and_tenant_isolated(sl: Slice) -> None:
    pid, _, _ = sl.full_run(["host-1", "host-2", "host-3"])
    sl.drain()
    assert sl.call("GET", f"/api/v1/assets/{pid}/nope", "alice").status_code == 404
    assert sl.call("GET", f"/api/v1/assets?project_id={pid}", "dave").json()["total"] == 0
    assert sl.call("GET", f"/api/v1/assets/{pid}/host-2", "dave").status_code == 404
    paula = sl.call("GET", f"/api/v1/assets/{pid}/host-2", "paula")  # project:read only
    assert paula.status_code == 200
    assert paula.json()["findings_visible"] is False and paula.json()["findings"] == []
    assert paula.json()["posture"]
