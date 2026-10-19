"""Imports through the real API, orchestrator and gateway. Nothing runs a scanner or contacts a
host: ``loopback_only`` fails any connect(), and imports are files the operator uploaded."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.http_server import loopback_only
from tests.slice import Slice

pytestmark = pytest.mark.security
GOLD = Path(__file__).resolve().parents[1] / "fixtures" / "golden"
POLICY = "import-baseline:1.0.0"
GROUP = "fixture-group-1"
HOSTS = ["host-1", "host-2", "host-3"]

ADAPTERS: dict[str, tuple[str, str, str, str]] = {  # adapter -> (profile, domain, kind, fixture)
    "cmdb_import": ("CMDB_IMPORT", "inventory", "cmdb_csv", "cmdb.csv"),
    "greenbone_import": ("GREENBONE_REPORT_IMPORT", "host", "greenbone_xml", "greenbone.xml"),
    "nmap_import": ("NMAP_BOUNDED_IMPORT", "network", "nmap_xml", "nmap.xml"),
    "openscap_import": ("OPENSCAP_RESULTS_IMPORT", "host", "openscap_xccdf", "openscap.xml"),
    "wazuh_import": ("WAZUH_EXPORT_IMPORT", "host", "wazuh_json", "wazuh.json"),
    "prowler_import": ("PROWLER_IMPORT", "cloud", "prowler_json", "prowler.json"),
    "zap_import": ("ZAP_BASELINE_IMPORT", "web", "zap_json", "zap.json"),
}


@pytest.fixture()
def sl(app_engine: Any, worker_engine: Any, tmp_path: Path) -> Iterator[Slice]:
    with loopback_only() as attempts:
        s = Slice(app_engine, worker_engine, tmp_path / "evidence")
        attempts.clear()
        yield s
        assert attempts == [], "an import path touched the network"


def artifact_text(sl: Slice, run_id: str) -> str:
    """What the run stored as EVIDENCE (not the operator's raw uploads, which keep the original file)."""
    store = sl.container.evidence
    assert store is not None
    return "".join(
        store.get("tenant-a", h).decode()
        for (h,) in sl.sql("SELECT content_hash FROM evidence_artifacts WHERE run_id=:r", r=run_id)
    )


def gold(name: str) -> str:
    return (GOLD / name).read_text()


def upload(
    sl: Slice, pid: str, kind: str, content: str, name: str = "report.dat", user: str = "alice"
) -> str:
    r = sl.call(
        "POST",
        "/api/v1/imports",
        user,
        json={"project_id": pid, "kind": kind, "filename": name, "content": content},
    )
    assert r.status_code == 201, r.text
    return str(r.json()["import_id"])


def project(
    sl: Slice, kind: str = "asset_group", selector: str = GROUP, expected: list[str] | None = None
) -> str:
    pid = sl.project()
    r = sl.call(
        "POST",
        "/api/v1/inventory",
        "alice",
        json={
            "project_id": pid,
            "kind": kind,
            "selector": selector,
            "expected_assets": HOSTS if expected is None else expected,
        },
    )
    assert r.status_code == 201, r.text
    return pid


def manifest(sl: Slice, pid: str, adapters: list[str], *, kind: str = "asset_group", selector: str = GROUP, profiles: dict[str, str] | None = None,
             ack: list[str] | None = None, **over: Any) -> dict[str, Any]:  # fmt: skip
    prof = {a: {"profile_id": (profiles or {}).get(a, ADAPTERS[a][0]),
                "profile_class": "ACTIVE" if (profiles or {}).get(a) == "ZAP_ACTIVE_IMPORT" else "READ_ONLY"} for a in adapters}  # fmt: skip
    body = sl.manifest_payload(pid, targets=[{"kind": kind, "selector": selector}], domains=sorted({ADAPTERS[a][1] for a in adapters}),
                               allowed_adapters=adapters, profiles=prof, policy_version=POLICY, **({"allowed_ports": [443]} if kind == "url" else {}), **over)  # fmt: skip
    r = sl.call("POST", "/api/v1/scope-manifests", "alice", json=body)
    assert r.status_code == 201, r.text
    mid = r.json()["manifest"]["manifest_id"]
    assert sl.call("POST", f"/api/v1/scope-manifests/{mid}/preflight", "alice").status_code == 200
    ap = sl.call(
        "POST",
        f"/api/v1/scope-manifests/{mid}/approve",
        "bob",
        json={"acknowledge_active_adapters": ack or []},
    )
    assert ap.status_code == 200, ap.text
    return dict(ap.json())


def go(sl: Slice, pid: str, m: dict[str, Any], files: dict[str, str]) -> str:
    """files: adapter -> import_id"""
    r = sl.launch(pid, m, adapter_params={a: {"import_id": i} for a, i in files.items()})
    assert r.status_code == 202, r.text
    return str(r.json()["run_id"])


def import_run(
    sl: Slice, pid: str, adapters: list[str], overrides: dict[str, str] | None = None, **mkw: Any
) -> str:
    files = {
        a: upload(sl, pid, ADAPTERS[a][2], (overrides or {}).get(a) or gold(ADAPTERS[a][3]))
        for a in adapters
    }
    run_id = go(sl, pid, manifest(sl, pid, adapters, **mkw), files)
    sl.drain()
    return run_id


def findings(sl: Slice, run_id: str) -> dict[str, str]:
    return {
        i["title"]: i["severity"]
        for i in sl.call("GET", f"/api/v1/assessments/{run_id}/findings", "alice").json()["items"]
    }


def reasons(sl: Slice, run_id: str) -> str:
    return " | ".join(
        r
        for s in sl.call("GET", f"/api/v1/assessments/{run_id}/coverage", "alice").json()[
            "segments"
        ]
        for r in s["reasons"]
    )


def codes(sl: Slice, run_id: str) -> list[str]:
    out: list[str] = []
    for e in sl.events(run_id):
        if e["type"] in {"task.failed", "task.partial"}:
            out += e["payload"].get("error_codes", []) + e["payload"].get("warning_codes", [])
    return out


# ---- upload controls ------------------------------------------------------------------------------
def test_upload_is_authorised_validated_redacted_and_audited(sl: Slice) -> None:
    pid = project(sl)
    secret = "password=" + "hunter2hunter2"
    meta = sl.call(
        "POST",
        "/api/v1/imports",
        "alice",
        json={
            "project_id": pid,
            "kind": "cmdb_csv",
            "filename": "../../etc/passwd",
            "content": gold("cmdb.csv") + f"\n# {secret}\n",
        },
    )
    assert meta.status_code == 201
    m = meta.json()
    assert (
        m["filename"] == "passwd"
        and m["redacted"] is True
        and m["content_hash"].startswith("sha256:")
    )
    assert "hunter2hunter2" not in "".join(
        p.read_text(errors="ignore") for p in sl.evidence_dir.rglob("*") if p.is_file()
    )
    listing = sl.call("GET", f"/api/v1/imports?project_id={pid}", "carol").json()
    assert [i["import_id"] for i in listing] == [m["import_id"]]
    assert (
        sl.sql(
            "SELECT count(*) FROM audit_events WHERE action='import.upload' AND resource=:r",
            r=f"import:{m['import_id']}",
        )[0][0]
        == 1
    )
    body = {"project_id": pid, "kind": "cmdb_csv", "filename": "x.csv", "content": "a,b\n1,2\n"}
    assert (
        sl.call("POST", "/api/v1/imports", "carol", json=body).status_code == 403
    )  # report reader
    assert sl.call("POST", "/api/v1/imports", "bob", json=body).status_code == 403  # approver
    assert sl.client.post("/api/v1/imports", json=body).status_code == 401


@pytest.mark.parametrize(
    ("over", "status"),
    [
        ({"kind": "shell_script"}, 422),
        ({"content": ""}, 422),
        ({"content": "a\x00b"}, 422),
        ({"content": "x" * 5_000_001}, 422),
        ({"extra": 1}, 422),
        ({"project_id": "00000000-0000-0000-0000-000000000000"}, 404),
        ({"filename": ""}, 422),
    ],
)
def test_bad_uploads_are_rejected(sl: Slice, over: dict[str, Any], status: int) -> None:
    pid = project(sl)
    body = {
        "project_id": pid,
        "kind": "cmdb_csv",
        "filename": "x.csv",
        "content": "asset_id\nh\n",
        **over,
    }
    assert sl.call("POST", "/api/v1/imports", "alice", json=body).status_code == status


def test_other_tenants_cannot_upload_to_or_list_a_project(sl: Slice) -> None:
    pid = project(sl)
    body = {"project_id": pid, "kind": "cmdb_csv", "filename": "x.csv", "content": "asset_id\nh\n"}
    assert sl.call("POST", "/api/v1/imports", "dave", json=body).status_code in (403, 404)
    assert sl.call("GET", f"/api/v1/imports?project_id={pid}", "dave").json() == []


# ---- a multi-source estate ----------------------------------------------------------------------
def test_cmdb_import_supplies_owner_and_names_every_data_quality_gap(sl: Slice) -> None:
    pid = project(sl)
    run_id = import_run(sl, pid, ["cmdb_import"])
    st = sl.status(run_id)
    assert st["state"] == "REPORT_READY" and st["tasks"] == {"SUCCEEDED": 1}
    assert findings(sl, run_id) == {
        "Asset has a named owner in the authoritative inventory": "MEDIUM",
        "Asset has an owner-supplied criticality": "LOW",
        "Inventory record was seen recently": "MEDIUM",
    }
    r = reasons(sl, run_id)
    assert "OWNER_UNKNOWN:host-2" in r and "STALE_RECORD:host-3:2025-06-01" in r
    own = {
        a: (o, s)
        for a, o, s in sl.sql(
            "SELECT asset_id, owner, owner_source FROM assets WHERE project_id=:p", p=pid
        )
    }
    assert own["host-1"] == ("team-web", "cmdb:cmdb-main") and own["host-2"] == (
        None,
        None,
    )  # UNKNOWN stays unknown
    cov = sl.call("GET", f"/api/v1/assessments/{run_id}/coverage", "alice").json()
    assert cov["complete"] is True and cov["segments"][0]["segment"] == f"{GROUP} [cmdb_import]"
    ctrls = {
        c["control_id"]: c["outcome"]
        for c in sl.call("GET", f"/api/v1/assessments/{run_id}/controls", "carol").json()
    }
    assert (
        ctrls["IB-1"] == "FAIL"
        and ctrls["IB-4"] == "NOT_ASSESSED"
        and ctrls["IB-8"] == "NOT_ASSESSED"
    )  # no scan evidence: not "pass"


def test_scanner_imports_resolve_onto_cmdb_assets_and_the_stray_host_stays_separate(
    sl: Slice,
) -> None:
    pid = project(sl)
    import_run(sl, pid, ["cmdb_import"])  # an inventory baseline from an earlier run
    run_id = import_run(
        sl, pid, ["greenbone_import", "nmap_import", "openscap_import", "wazuh_import"]
    )
    st = sl.status(run_id)
    assert st["state"] == "PARTIAL" and st["tasks"] == {
        "SUCCEEDED": 2,
        "PARTIAL": 2,
    }  # openscap: unchecked rule; wazuh: agent down
    f = findings(sl, run_id)
    assert f["Highest CVSS score reported for the host is below 7.0"] == "HIGH"
    assert f["No critical or high vulnerability findings are reported"] == "HIGH"
    assert f["No cleartext or legacy remote-access ports are open"] == "MEDIUM"
    assert (
        f["No SCAP benchmark rules fail"] == "MEDIUM"
        and f["No endpoint configuration-assessment checks fail"] == "MEDIUM"
    )
    obs = {
        (a, r): v
        for a, r, v in sl.sql(
            "SELECT asset_id, rule_id, observed_value FROM observations WHERE run_id=:r", r=run_id
        )
    }
    assert (
        obs["host-1", "vuln.max_cvss"] == 9.8 and obs["host-2", "vuln.max_cvss"] == 0.0
    )  # attached to the CMDB asset ids
    assert obs["host-2", "net.open_ports"] == [22, 445] and obs["host-3", "net.open_ports"] == [
        3389
    ]
    assert (
        obs["host-1", "sca.failed_checks"] == ["cis_ubuntu22-04:28500"]
        and ("host-3", "sca.failed_checks") not in obs
    )
    stray = [
        a
        for (a,) in sl.sql(
            "SELECT asset_id FROM assets WHERE project_id=:p AND asset_id LIKE 'ip-%'", p=pid
        )
    ]
    assert len(stray) == 1  # 10.99.0.5 was NOT merged into any known asset
    assert sl.sql(
        "SELECT match_confidence FROM assets WHERE asset_id=:a AND project_id=:p", a=stray[0], p=pid
    ) == [("LOW",)]
    r = reasons(sl, run_id)
    assert (
        "AGENT_DISCONNECTED:win-01.corp.test" in r
        and "RULES_NOT_CHECKED:1" in r
        and f"UNEXPECTED_ASSET:{stray[0]}" in r
    )
    h1 = sl.sql(
        "SELECT native_ids, owner, match_confidence FROM assets WHERE asset_id='host-1' AND project_id=:p",
        p=pid,
    )[0]
    assert (
        h1[0]["ip"] == "10.20.0.11"
        and h1[0]["cmdb_id"] == "host-1"
        and h1[1] == "team-web"
        and h1[2] == "HIGH"
    )  # merged, owner kept
    assert (
        sl.sql(
            "SELECT count(*) FROM run_asset_status WHERE run_id=:r AND status='UNREACHABLE'",
            r=run_id,
        )[0][0]
        >= 1
    )  # win-01 agent
    segs = {
        s["segment"]
        for s in sl.call("GET", f"/api/v1/assessments/{run_id}/coverage", "alice").json()[
            "segments"
        ]
    }
    assert len(segs) == 4  # one ledger per adapter on the same target: none silently overwritten


def test_one_run_imports_the_inventory_before_the_scanners_that_resolve_against_it(
    sl: Slice,
) -> None:
    pid = project(sl)
    run_id = import_run(sl, pid, ["nmap_import", "greenbone_import", "cmdb_import"])
    tasks = {a: (t, d) for t, a, d in sl.sql(
        "SELECT task_id::text, adapter_id, depends_on FROM run_tasks WHERE run_id=:r", r=run_id)}  # fmt: skip
    cmdb = tasks["cmdb_import"][0]
    assert tasks["cmdb_import"][1] == []
    assert tasks["nmap_import"][1] == [cmdb] and tasks["greenbone_import"][1] == [cmdb]
    events = sl.call(
        "GET", f"/api/v1/assessments/{run_id}/events", "alice", params={"limit": 500}
    ).json()["events"]
    queued = {e["payload"]["agent_id"]: e["payload"]["dependencies"]
              for e in events if e["type"] == "task.queued"}  # fmt: skip
    assert queued == {"cmdb_import": [], "nmap_import": [cmdb], "greenbone_import": [cmdb]}
    started = [e["payload"]["agent_id"] for e in events if e["type"] == "task.started"]
    assert started[0] == "cmdb_import"
    obs = {(a, r): v for a, r, v in sl.sql(
        "SELECT asset_id, rule_id, observed_value FROM observations WHERE run_id=:r", r=run_id)}  # fmt: skip
    assert obs["host-1", "vuln.max_cvss"] == 9.8 and obs["host-3", "net.open_ports"] == [3389]
    assert sl.sql(
        "SELECT match_confidence FROM assets WHERE asset_id='host-1' AND project_id=:p", p=pid
    ) == [("HIGH",)]
    warnings = [w for (ws,) in sl.sql("SELECT warnings FROM run_tasks WHERE run_id=:r", r=run_id)
                for w in ws]  # fmt: skip
    assert not [w for w in warnings if w.startswith("INVENTORY_DEPENDENCY_")]


def test_a_failed_inventory_import_is_named_on_the_tasks_that_needed_it(sl: Slice) -> None:
    pid = project(sl)
    run_id = import_run(
        sl, pid, ["cmdb_import", "nmap_import"], overrides={"cmdb_import": "not,a\ncmdb"}
    )
    rows = {a: (t, st, w) for t, a, st, w in sl.sql(
        "SELECT task_id::text, adapter_id, status, warnings FROM run_tasks WHERE run_id=:r",
        r=run_id)}  # fmt: skip
    cmdb_id, cmdb_status, _ = rows["cmdb_import"]
    assert cmdb_status == "FAILED"
    _, nmap_status, nmap_warnings = rows["nmap_import"]
    assert nmap_status in ("SUCCEEDED", "PARTIAL")  # the scan evidence is still collected
    assert f"INVENTORY_DEPENDENCY_FAILED:{cmdb_id}" in nmap_warnings
    assert sl.sql(
        "SELECT count(*) FROM assets WHERE project_id=:p AND match_confidence<>'LOW'", p=pid
    ) == [(0,)]  # with no inventory, no scanned host is promoted to a known asset


def test_ambiguous_identity_is_named_and_never_guessed(sl: Slice) -> None:
    pid = project(sl)
    import_run(sl, pid, ["cmdb_import"])
    confused = gold("greenbone.xml").replace(
        "<ip>10.20.0.12</ip><detail><name>hostname</name><value>db-01.corp.test</value>",
        "<ip>10.20.0.12</ip><detail><name>hostname</name><value>web-01.corp.test</value>",
    )
    confused = confused.replace(
        "<host>10.20.0.11<hostname>web-01.corp.test</hostname></host>",
        "<host>10.20.0.12<hostname>web-01.corp.test</hostname></host>",
    )
    run_id = import_run(sl, pid, ["greenbone_import"], {"greenbone_import": confused})
    assert any(
        w.startswith("AMBIGUOUS_IDENTITY:10.20.0.12")
        for w in sl.sql("SELECT warnings FROM run_tasks WHERE run_id=:r", r=run_id)[0][0]
    )
    assert "AMBIGUOUS_IDENTITY:10.20.0.12" in reasons(sl, run_id)
    obs_assets = {
        a
        for (a,) in sl.sql(
            "SELECT DISTINCT asset_id FROM observations WHERE run_id=:r AND rule_id LIKE 'vuln.%'",
            r=run_id,
        )
    }
    assert "host-2" not in obs_assets  # the contested record was NOT attached to either candidate
    assert (
        sl.sql(
            "SELECT count(*) FROM assets WHERE project_id=:p AND native_ids->>'ip'='10.20.0.12' AND asset_id LIKE 'ip-%'",
            p=pid,
        )[0][0]
        == 1
    )
    assert sl.sql(
        "SELECT observed_value FROM observations WHERE run_id=:r AND asset_id='host-1' AND rule_id='vuln.max_cvss'",
        r=run_id,
    ) == [(0.0,)]  # none of the contested results leaked into host-1
    contested = sl.sql(
        "SELECT o.observed_value FROM observations o JOIN assets a ON a.asset_id=o.asset_id AND a.project_id=:p "
        "WHERE o.run_id=:r AND o.rule_id='vuln.max_cvss' AND a.native_ids->>'ip'='10.20.0.12' AND a.asset_id LIKE 'ip-%'",
        p=pid,
        r=run_id,
    )
    assert contested == [(9.8,)]  # they live on their own separate, low-confidence asset


# ---- scope enforcement on file contents ------------------------------------------------------------
def test_ip_scoped_imports_drop_records_outside_the_signed_scope(sl: Slice) -> None:
    pid = project(sl, kind="cidr", selector="10.20.0.0/24", expected=[])
    run_id = import_run(
        sl, pid, ["greenbone_import", "nmap_import"], kind="cidr", selector="10.20.0.0/24"
    )
    assert sl.status(run_id)["state"] in {"REPORT_READY", "PARTIAL"}
    assert "OUT_OF_SCOPE_RECORDS_DROPPED" in reasons(
        sl, run_id
    ) and "NO_EXPECTED_ASSET_LIST" in reasons(sl, run_id)
    blob = artifact_text(sl, run_id)
    assert (
        "10.99.0.5" not in blob and "stray-01" not in blob
    )  # not in anything the run stored as evidence
    assert (
        sl.sql(
            "SELECT count(*) FROM assets WHERE project_id=:p AND native_ids->>'ip'='10.99.0.5'",
            p=pid,
        )[0][0]
        == 0
    )
    assert sl.sql("SELECT count(*) FROM observations WHERE run_id=:r", r=run_id)[0][0] > 0


def test_prowler_import_is_account_scoped_and_denied_services_remain_gaps(sl: Slice) -> None:
    pid = project(sl, kind="cloud_account", selector="123456789012", expected=[])
    run_id = import_run(sl, pid, ["prowler_import"], kind="cloud_account", selector="123456789012")
    st = sl.status(run_id)
    assert st["state"] == "PARTIAL" and st["tasks"] == {"PARTIAL": 1}
    assert findings(sl, run_id) == {
        "No high or critical cloud posture checks fail": "HIGH",
        "No medium or low cloud posture checks fail": "LOW",
    }
    r = reasons(sl, run_id)
    assert (
        "PERMISSION_DENIED:123456789012/eu-west-1/kms" in r
        and "OUT_OF_SCOPE_RECORDS_DROPPED:1" in r
    )
    assert "someone-elses-bucket" not in artifact_text(sl, run_id)
    assert (
        sl.sql(
            "SELECT count(*) FROM assets WHERE project_id=:p AND native_ids->>'resource_id'='key-0'",
            p=pid,
        )[0][0]
        == 0
    )  # denied: nothing claimed
    assert sl.report(run_id)["banner"].startswith("PARTIAL ASSESSMENT")


def test_zero_asset_reports_are_a_coverage_anomaly_for_every_adapter(sl: Slice) -> None:
    pid = project(sl)
    empty = '<nmaprun args="nmap -sT x" version="7.95"><runstats><finished exit="success"/></runstats></nmaprun>'
    run_id = import_run(sl, pid, ["nmap_import"], {"nmap_import": empty})
    assert sl.status(run_id)["tasks"] == {"PARTIAL": 1}
    seg = sl.call("GET", f"/api/v1/assessments/{run_id}/coverage", "alice").json()["segments"][0]
    assert (
        seg["source_ok"] is False
        and "ZERO_ASSETS_RETURNED" in seg["reasons"]
        and seg["unknown_count"] == 3
    )


# ---- ZAP profiles ---------------------------------------------------------------------------------
def test_zap_baseline_import_becomes_findings_on_the_url_asset(sl: Slice) -> None:
    pid = project(sl, kind="url", selector="https://app.corp.test", expected=[])
    run_id = import_run(sl, pid, ["zap_import"], kind="url", selector="https://app.corp.test")
    assert sl.status(run_id)["state"] in {"REPORT_READY", "PARTIAL"}
    assert findings(sl, run_id) == {"No medium-risk web alerts are reported": "MEDIUM"}
    assert "OUT_OF_SCOPE_RECORDS_DROPPED:1" in reasons(sl, run_id)
    assert "not-ours" not in artifact_text(sl, run_id)


def test_active_scan_output_is_refused_under_the_baseline_profile_and_needs_acknowledgement_under_the_active_one(
    sl: Slice,
) -> None:
    pid = project(sl, kind="url", selector="https://app.corp.test", expected=[])
    active = gold("zap.json").replace('"pluginid": "10096"', '"pluginid": "40012"')
    run_id = import_run(
        sl,
        pid,
        ["zap_import"],
        {"zap_import": active},
        kind="url",
        selector="https://app.corp.test",
    )
    assert sl.status(run_id)[
        "state"
    ] == "FAILED" and "SCAN_PROFILE_VIOLATION:ACTIVE_SCAN_RULES_IN_BASELINE_IMPORT" in codes(
        sl, run_id
    )
    # the ACTIVE profile is an approval-gated class: approval without the acknowledgement is refused
    body = sl.manifest_payload(pid, targets=[{"kind": "url", "selector": "https://app.corp.test"}], domains=["web"], allowed_adapters=["zap_import"],
                               profiles={"zap_import": {"profile_id": "ZAP_ACTIVE_IMPORT", "profile_class": "ACTIVE"}}, policy_version=POLICY, allowed_ports=[443])  # fmt: skip
    mid = sl.call("POST", "/api/v1/scope-manifests", "alice", json=body).json()["manifest"][
        "manifest_id"
    ]
    sl.call("POST", f"/api/v1/scope-manifests/{mid}/preflight", "alice")
    refused = sl.call("POST", f"/api/v1/scope-manifests/{mid}/approve", "bob", json={})
    assert (
        refused.status_code == 422
        and "ACTIVE_PROFILE_REQUIRES_APPROVAL" in refused.json()["reason_codes"]
    )
    ok = sl.call(
        "POST",
        f"/api/v1/scope-manifests/{mid}/approve",
        "bob",
        json={"acknowledge_active_adapters": ["zap_import"]},
    )
    assert ok.status_code == 200
    run2 = go(sl, pid, ok.json(), {"zap_import": upload(sl, pid, "zap_json", active)})
    sl.drain()
    assert sl.status(run2)["state"] in {"REPORT_READY", "PARTIAL"}


# ---- hostile and misused imports -----------------------------------------------------------------------
def test_xxe_and_entity_bombs_fail_the_task_without_expanding_anything(sl: Slice) -> None:
    pid = project(sl)
    xxe = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><report>&e;</report>'
    run_id = import_run(sl, pid, ["greenbone_import"], {"greenbone_import": xxe})
    assert sl.status(run_id)["state"] == "FAILED" and codes(sl, run_id) == [
        "XML_FORBIDDEN_CONSTRUCT"
    ]
    assert "root:" not in artifact_text(sl, run_id)
    assert sl.sql("SELECT count(*) FROM assets WHERE project_id=:p", p=pid)[0][0] == 0


def test_an_import_cannot_be_used_across_projects_kinds_or_after_tampering(
    sl: Slice,
) -> None:
    pid, other = project(sl), project(sl)
    m = manifest(sl, pid, ["cmdb_import"])
    wrong_project = upload(sl, other, "cmdb_csv", gold("cmdb.csv"))
    wrong_kind = upload(sl, pid, "greenbone_xml", gold("greenbone.xml"))
    for imp, code in (
        (wrong_project, "IMPORT_OTHER_PROJECT"),
        (wrong_kind, "IMPORT_KIND_MISMATCH"),
        ("imp-" + "0" * 20, "IMPORT_NOT_FOUND"),
    ):
        run_id = go(sl, pid, m, {"cmdb_import": imp})
        sl.drain()
        assert sl.status(run_id)["state"] == "FAILED" and codes(sl, run_id) == [code], code
    good = upload(sl, pid, "cmdb_csv", gold("cmdb.csv"))
    f = next(
        p
        for p in sl.evidence_dir.rglob("*")
        if p.is_file() and gold("cmdb.csv").split("\n")[1][:20] in p.read_text(errors="ignore")
    )
    f.write_text(
        f.read_text() + "host-666,evil,10.6.6.6,linux,x,x,x,2026-10-10,evil\n"
    )  # tampered at rest
    tampered = go(sl, pid, m, {"cmdb_import": good})
    sl.drain()
    assert (
        codes(sl, tampered) == ["IMPORT_INTEGRITY_FAILURE"]
        and sl.sql("SELECT count(*) FROM assets WHERE asset_id='host-666'")[0][0] == 0
    )


def test_an_import_is_invisible_to_other_tenants_at_the_store_level(sl: Slice) -> None:
    from aisw.evidence.imports import ImportRejected

    pid = project(sl)
    imp = upload(sl, pid, "cmdb_csv", gold("cmdb.csv"))
    store = sl.container.imports
    assert store is not None
    kinds = frozenset({"cmdb_csv"})
    assert store.read(tenant_id="tenant-a", project_id=pid, import_id=imp, kinds=kinds).startswith(
        b"asset_id"
    )
    for tenant in ("tenant-b", "tenant-zzz"):
        with pytest.raises(ImportRejected) as e:
            store.read(tenant_id=tenant, project_id=pid, import_id=imp, kinds=kinds)
        assert e.value.code == "IMPORT_NOT_FOUND"  # row-level security: it does not exist for them


def test_import_parameters_are_validated_by_the_gateway(sl: Slice) -> None:
    pid = project(sl)
    m = manifest(sl, pid, ["cmdb_import"])
    for params in (
        {},
        {"import_id": "../../etc/passwd"},
        {"import_id": "imp-" + "a" * 20, "path": "/etc/passwd"},
        {"import_id": "imp-" + "a" * 20, "stale_days": 0},
    ):
        r = sl.launch(pid, m, adapter_params={"cmdb_import": params})
        run_id = r.json()["run_id"]
        sl.drain()
        assert sl.status(run_id)["state"] == "FAILED" and codes(sl, run_id) == ["INVALID_PARAMS"], (
            params
        )


def test_a_nmap_report_from_an_unapproved_scan_profile_is_refused_end_to_end(sl: Slice) -> None:
    pid = project(sl)
    bad = gold("nmap.xml").replace("--top-ports 20", "--script vuln --top-ports 20")
    run_id = import_run(sl, pid, ["nmap_import"], {"nmap_import": bad})
    assert sl.status(run_id)["state"] == "FAILED" and codes(sl, run_id) == [
        "SCAN_PROFILE_VIOLATION:--script"
    ]
    assert sl.sql("SELECT count(*) FROM observations WHERE run_id=:r", r=run_id)[0][0] == 0


def test_connector_matrix_lists_import_adapters_with_kinds_formats_and_health(sl: Slice) -> None:
    rows = {c["adapter_id"]: c for c in sl.call("GET", "/api/v1/connectors", "carol").json()}
    assert {
        "cmdb_import",
        "prowler_import",
        "greenbone_import",
        "nmap_import",
        "openscap_import",
        "wazuh_import",
        "zap_import",
        "url_smoke",
        "fixture",
    } <= set(rows)
    n = rows["nmap_import"]
    assert (
        n["kind"] == "import"
        and n["import_kinds"] == ["nmap_xml"]
        and n["health"] == "HEALTHY"
        and n["formats"]
        and n["read_only"]
    )
    assert rows["url_smoke"]["kind"] == "live" and rows["fixture"]["import_kinds"] == []
    assert [p for p in rows["zap_import"]["profiles"] if p["profile_class"] == "ACTIVE"] == [
        {"profile_id": "ZAP_ACTIVE_IMPORT", "profile_class": "ACTIVE"}
    ]
    assert json.dumps(rows)  # serialisable, no secrets
