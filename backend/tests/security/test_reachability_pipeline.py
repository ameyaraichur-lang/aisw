"""Reachability through the real API, orchestrator and assurance gate (ADR-041). Loopback only:
the scan and firewall files are fixtures; nothing is sent to any host."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from aisw.agents.assurance import AssuranceContext, assess_risk, assess_scenario
from aisw.contracts.analysis import CorrelationScenario, RiskAssessment
from aisw.contracts.enums import AssuranceVerdict
from aisw.core.db import tenant_connection
from aisw.orchestrator.analysis import load_edges, load_findings, load_risks, load_scenarios
from aisw.policy.rubric import builtin
from tests.security.test_import_pipeline import ADAPTERS, GROUP, POLICY, gold, project, upload
from tests.slice import Slice

pytestmark = pytest.mark.security

DB = "10.20.0.12"
NMAP_WEB_ONLY = re.sub(r'\s*<host><status state="up" reason="syn-ack"/><address addr="10\.(20\.0\.1[23]|99\.0\.5)".*?</host>',
                       "", gold("nmap.xml"), flags=re.S)  # fmt: skip
DB_IPTABLES = "\n".join(
    ln for ln in gold("iptables.rules").splitlines()
    if not ln.startswith("-A INPUT -p tcp")  # keep only SSH from 10.20.0.0/16, ICMP and the final DROP
)  # fmt: skip
PROFILES = {**{a: v[0] for a, v in ADAPTERS.items()}, "firewall_import": "FIREWALL_CONFIG_IMPORT"}


def reach_run(sl: Slice, vantage: str | None) -> str:
    pid = project(sl)
    r = sl.call("POST", "/api/v1/inventory", "alice",
                json={"project_id": pid, "kind": "host", "selector": DB, "expected_assets": ["host-2"]})  # fmt: skip
    assert r.status_code == 201, r.text
    adapters = ["cmdb_import", "greenbone_import", "nmap_import", "firewall_import"]
    body = sl.manifest_payload(
        pid, targets=[{"kind": "asset_group", "selector": GROUP}, {"kind": "host", "selector": DB}],
        domains=["host", "inventory", "network"], allowed_adapters=adapters, policy_version=POLICY,
        profiles={a: {"profile_id": PROFILES[a], "profile_class": "READ_ONLY"} for a in adapters},
    )  # fmt: skip
    r = sl.call("POST", "/api/v1/scope-manifests", "alice", json=body)
    assert r.status_code == 201, r.text
    mid = r.json()["manifest"]["manifest_id"]
    assert sl.call("POST", f"/api/v1/scope-manifests/{mid}/preflight", "alice").status_code == 200
    ap = sl.call("POST", f"/api/v1/scope-manifests/{mid}/approve", "bob",
                 json={"acknowledge_active_adapters": []})  # fmt: skip
    assert ap.status_code == 200, ap.text
    m = ap.json()
    files = {
        "cmdb_import": upload(sl, pid, "cmdb_csv", gold("cmdb.csv")),
        "greenbone_import": upload(sl, pid, "greenbone_xml", gold("greenbone.xml")),
        "nmap_import": upload(sl, pid, "nmap_xml", NMAP_WEB_ONLY),
        "firewall_import": upload(sl, pid, "iptables_save", DB_IPTABLES),
    }
    params: dict[str, dict[str, Any]] = {a: {"import_id": i} for a, i in files.items()}
    if vantage:
        params["nmap_import"]["vantage"] = vantage
    launched = sl.launch(pid, m, adapter_params=params)
    assert launched.status_code == 202, launched.text
    sl.drain()
    return str(launched.json()["run_id"])


def risks(sl: Slice, run_id: str) -> dict[str, dict[str, Any]]:
    return {f: fac for f, fac in sl.sql(
        "SELECT finding_id, factors FROM risk_assessments WHERE run_id=:r", r=run_id)}  # fmt: skip


def test_declared_untrusted_scan_and_host_firewall_build_a_two_hop_path(sl: Slice) -> None:
    run_id = reach_run(sl, "untrusted")
    assert sl.status(run_id)["state"] in {"REPORT_READY", "PARTIAL"}
    body = sl.call("GET", f"/api/v1/assessments/{run_id}/reachability", "carol").json()
    edges = {(e["src"], e["dst"]): e for e in body["edges"]}
    assert edges["internet", "host-1"]["basis"] == "OBSERVED"
    assert edges["internet", "host-1"]["ports"] == [[22, 22], [443, 443]]
    assert edges["host-1", "host-2"]["basis"] == "CONFIGURED"
    assert edges["host-1", "host-2"]["ports"] == [[22, 22]]
    assert edges["host-3", "host-2"]["note"] == "from 10.20.0.0/16"
    assert ("internet", "host-2") not in edges  # the final DROP closes everything else
    assert body["exposure"]["host-1"]["level"] == "VERIFIED" and "host-2" not in body["exposure"]

    host1 = [fac for fac in risks(sl, run_id).values() if fac["exposure_basis"]]
    assert host1 and all(f["exposure"] == "VERIFIED" for f in host1)
    assert {e for f in host1 for e in f["exposure_basis"]} == {
        edges["internet", "host-1"]["edge_id"]
    }

    scenarios = sl.call("GET", f"/api/v1/assessments/{run_id}/scenarios", "alice").json()
    path = [s for s in scenarios if s["asset_id"] == "host-2" and s["path"]]
    assert len(path) == 1
    s = path[0]
    assert [(h["src"], h["dst"]) for h in s["path"]] == [
        ("internet", "host-1"),
        ("host-1", "host-2"),
    ]
    assert s["title"].startswith("host-2 is reachable from the internet in 2 hops")
    assert s["confidence"] == "LOW" and any("upstream" in a for a in s["assumptions"])
    assert s["assurance_verdict"] == "ACCEPT"
    html = sl.sql("SELECT html FROM reports WHERE run_id=:r", r=run_id)[0][0]
    assert "Route: internet → host-1 (observed, 22, 443) → host-2 (configured, 22)" in html

    rows = sl.sql("SELECT verdict, defect_codes FROM assurance_results WHERE run_id=:r "
                  "AND item_ref LIKE 'risk:%'", r=run_id)  # fmt: skip
    assert rows and all(v == "ACCEPT" for v, _ in rows)


def test_a_scan_without_a_declared_vantage_adds_no_exposure(sl: Slice) -> None:
    run_id = reach_run(sl, None)
    body = sl.call("GET", f"/api/v1/assessments/{run_id}/reachability", "alice").json()
    assert not [e for e in body["edges"] if e["src"] == "internet"]
    assert "SCAN_VANTAGE_NOT_STATED:1" in body["caveats"]
    assert not [f for f in risks(sl, run_id).values() if f["exposure_basis"]]
    assert any(e["src"] == "host-1" and e["dst"] == "host-2" for e in body["edges"])


def test_a_tampered_exposure_claim_or_path_hop_is_rejected_by_assurance(sl: Slice) -> None:
    run_id = reach_run(sl, "untrusted")
    with tenant_connection(sl.app_engine, "tenant-a") as conn:
        edges = load_edges(conn, run_id)
        findings = load_findings(conn, run_id)
        stored = load_risks(conn, run_id)
        scenarios = load_scenarios(conn, run_id)
    ctx = AssuranceContext(
        tenant_id="tenant-a", project_id="p", run_id=run_id, policy_version="import-baseline:1.0.0",
        pack_control_ids=frozenset(), pack_framework="x", now=datetime.now(UTC),
        freshness=timedelta(days=1), artifact=lambda _ref: None, evidence_ok=lambda _m: True,
        asset_exists=lambda _a: True,
    )  # fmt: skip
    victim = next(r for r in stored.values() if r.factors.exposure == "UNKNOWN")
    internal = sorted(e for e, v in edges.items() if v.src != "internet")[:1]
    for claim, basis in (
        ("VERIFIED", internal),
        ("VERIFIED", []),
        ("CONFIGURED", ["re-0000000000000000"]),
    ):
        forged = RiskAssessment.model_validate({**victim.model_dump(mode="json"),
            "factors": {**victim.factors.model_dump(mode="json"), "exposure": claim, "exposure_basis": basis}})  # fmt: skip
        res = assess_risk(forged, findings[victim.finding_id], builtin(), ctx, edges)
        assert "EXPOSURE_NOT_SUPPORTED" in res.defect_codes, (claim, basis)

    ok = dict.fromkeys(findings, AssuranceVerdict.ACCEPT)
    s = next(x for x in scenarios.values() if x.path)
    assert assess_scenario(s, findings, ok, stored, ctx, edges).defect_codes == []
    hops = [h.model_dump(mode="json") for h in s.path]
    bent = CorrelationScenario.model_validate(
        {**s.model_dump(mode="json"), "path": [{**hops[0], "ports": None}, *hops[1:]]}
    )
    assert (
        "PATH_EDGE_NOT_RECORDED"
        in assess_scenario(bent, findings, ok, stored, ctx, edges).defect_codes
    )
    with pytest.raises(ValueError, match="hop by hop"):
        CorrelationScenario.model_validate({**s.model_dump(mode="json"), "path": hops[:1]})
