"""Inventory and vulnerability imports through the real API, orchestrator and gateway: NetBox seeds
the authoritative inventory, a later Nessus run attaches to those hosts by address, and Trivy images
are judged under image-baseline. Nothing outside loopback is contacted."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.security.test_import_pipeline import GROUP, HOSTS, findings, project, reasons, sl, upload
from tests.slice import Slice

pytestmark = pytest.mark.security
__all__ = ["sl"]
GOLD = Path(__file__).resolve().parents[1] / "fixtures" / "golden"
ADAPTERS = {  # adapter -> (profile, domain, kind, fixture)
    "netbox_import": ("NETBOX_EXPORT_IMPORT", "inventory", "netbox_json", "netbox.json"),
    "servicenow_import": (
        "SERVICENOW_CMDB_IMPORT",
        "inventory",
        "servicenow_json",
        "servicenow.json",
    ),
    "nessus_import": ("NESSUS_REPORT_IMPORT", "host", "nessus_xml", "nessus.xml"),
    "tenable_import": ("TENABLE_EXPORT_IMPORT", "host", "tenable_json", "tenable.json"),
    "qualys_import": ("QUALYS_DETECTION_IMPORT", "host", "qualys_xml", "qualys.xml"),
    "trivy_import": ("TRIVY_IMAGE_REPORT_IMPORT", "container", "trivy_json", "trivy.json"),
}


def go(sl: Slice, pid: str, adapters: list[str], policy: str = "import-baseline:1.0.0") -> str:
    m = sl.approved_manifest(
        pid, targets=[{"kind": "asset_group", "selector": GROUP}], policy_version=policy,
        domains=sorted({ADAPTERS[a][1] for a in adapters}), allowed_adapters=adapters,
        profiles={a: {"profile_id": ADAPTERS[a][0], "profile_class": "READ_ONLY"} for a in adapters},
    )  # fmt: skip
    files = {
        a: upload(sl, pid, ADAPTERS[a][2], (GOLD / ADAPTERS[a][3]).read_text()) for a in adapters
    }
    r = sl.launch(pid, m, adapter_params={a: {"import_id": i} for a, i in files.items()})
    assert r.status_code == 202, r.text
    sl.drain()
    return str(r.json()["run_id"])


def test_netbox_inventory_then_nessus_results_attach_to_the_same_hosts(sl: Slice) -> None:
    pid = project(sl)
    inv = go(sl, pid, ["netbox_import"])
    assert sl.status(inv)["state"] == "REPORT_READY"
    assert findings(sl, inv) == {
        "Asset has a named owner in the authoritative inventory": "MEDIUM",
        "Asset has an owner-supplied criticality": "LOW",
        "Inventory record was seen recently": "MEDIUM",
    }
    assert "NOT_ACTIVE_SKIPPED:2" in reasons(sl, inv)

    scan = go(sl, pid, ["nessus_import"])
    rows = sl.sql("SELECT a.asset_id, o.rule_id, o.outcome FROM observations o JOIN assets a "
                  "ON a.asset_id=o.asset_id AND a.project_id=:p WHERE o.run_id=:r ORDER BY 1, 2", p=pid, r=scan)  # fmt: skip
    matched = [tuple(r) for r in rows if r[0] in HOSTS]
    assert matched == [
        ("host-1", "vuln.critical_high_findings", "FAIL"), ("host-1", "vuln.max_cvss", "FAIL"),
        ("host-2", "vuln.critical_high_findings", "PASS"), ("host-2", "vuln.max_cvss", "PASS"),
    ]  # fmt: skip
    # a group scope keeps a host it cannot match as a separate low-confidence asset, never merged
    stray = sl.sql("SELECT match_confidence, native_ids->>'ip' FROM assets WHERE project_id=:p "
                   "AND asset_id NOT IN ('host-1','host-2','host-3')", p=pid)  # fmt: skip
    assert [tuple(s) for s in stray] == [("LOW", "10.99.0.5")]
    r = reasons(sl, scan)
    assert "UNCREDENTIALED_SCAN:db-01" in r and "SCAN_INCOMPLETE:10.20.0.13" in r


@pytest.mark.parametrize("adapter", ["servicenow_import", "tenable_import", "qualys_import"])
def test_each_import_completes_through_the_pipeline(sl: Slice, adapter: str) -> None:
    pid = project(sl, expected=HOSTS)
    run_id = go(sl, pid, [adapter])
    assert sl.status(run_id)["state"] in {"REPORT_READY", "PARTIAL"}
    assert sl.sql("SELECT count(*) FROM observations WHERE run_id=:r", r=run_id)[0][0] > 0


def test_trivy_images_are_judged_under_image_baseline(sl: Slice) -> None:
    pid = project(sl, expected=[])
    run_id = go(sl, pid, ["trivy_import"], policy="image-baseline:1.0.0")
    assert sl.status(run_id)["state"] == "REPORT_READY"
    assert findings(sl, run_id) == {
        "Container images carry no critical or high vulnerabilities": "HIGH",
        "Container image base OS is within its support period": "HIGH",
    }
    types = {
        t for (t,) in sl.sql("SELECT DISTINCT asset_type FROM assets WHERE project_id=:p", p=pid)
    }
    assert types == {"container_image"}
