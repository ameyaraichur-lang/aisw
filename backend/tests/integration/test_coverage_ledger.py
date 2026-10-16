"""Tenant-wide Coverage Ledger: absence of a result is shown as absence, never as clean."""

from __future__ import annotations

from typing import Any

from tests.slice import Slice


def ledger(sl: Slice, user: str = "carol", **params: Any) -> dict[str, Any]:
    r = sl.call("GET", "/api/v1/coverage", user, params=params)
    assert r.status_code == 200, r.text
    return dict(r.json())


def project(body: dict[str, Any], pid: str) -> dict[str, Any] | None:
    return next((p for p in body["projects"] if p["project_id"] == pid), None)


def test_gaps_untargeted_inventory_and_never_assessed_projects(sl: Slice) -> None:
    idle = sl.project()
    sl.inventory(idle, ["host-1"])
    pid, _, _ = sl.full_run(
        ["host-1", "host-2", "host-3", "host-4"], fixture_set="baseline-partial"
    )
    sl.drain()
    r = sl.call("POST", "/api/v1/inventory", "alice",
                json={"project_id": pid, "kind": "asset_group", "selector": "later-group",
                      "expected_assets": ["host-7"]})  # fmt: skip
    assert r.status_code == 201, r.text

    body = ledger(sl)
    assert body["basis"] == "latest finished run per project"
    assert {"project_id": idle, "inventory_entries": 1}.items() <= next(
        p for p in body["never_assessed"] if p["project_id"] == idle).items()  # fmt: skip
    p = project(body, pid)
    assert p is not None and p["complete"] is False and p["run"]["partial"] is True
    [seg] = p["segments"]
    assert seg["complete"] is False and seg["age_days"] == 0
    gaps = {g["kind"]: [i["asset_id"] for i in g["items"]] for g in seg["gaps"]}
    assert gaps["EXPECTED_ASSET_ABSENT"] == ["host-4"]
    assert gaps["ASSET_UNREACHABLE"] == ["host-2"]
    assert gaps["ASSET_UNSUPPORTED"] == ["host-3"]
    assert gaps["UNEXPECTED_ASSET"] == ["host-9"]
    unreachable = next(g for g in seg["gaps"] if g["kind"] == "ASSET_UNREACHABLE")
    assert unreachable["label"] == "Unreachable"
    assert unreachable["items"][0]["detail"] == "connection timed out"
    assert p["untargeted_inventory"] == [{"kind": "asset_group", "selector": "later-group"}]
    assert p["totals"]["expected"] == 4

    only = ledger(sl, project_id=pid, incomplete_only="true")
    assert [x["project_id"] for x in only["projects"]] == [pid]


def test_a_complete_project_and_filters(sl: Slice) -> None:
    pid, _, _ = sl.full_run(["host-1", "host-2", "host-3"])
    sl.drain()
    p = project(ledger(sl, project_id=pid), pid)
    assert p is not None and p["complete"] is True and p["untargeted_inventory"] == []
    assert all(s["gaps"] == [] for s in p["segments"])
    assert project(ledger(sl, project_id=pid, incomplete_only="true"), pid) is None
    assert ledger(sl, project_id=pid, incomplete_only="true")["summary"]["complete"] == 1


def test_coverage_is_tenant_scoped(sl: Slice) -> None:
    pid, _, _ = sl.full_run(["host-1"])
    sl.drain()
    other = ledger(sl, user="dave")
    assert project(other, pid) is None
    assert all(p["project_id"] != pid for p in other["never_assessed"])
