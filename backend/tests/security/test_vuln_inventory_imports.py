"""Inventory (NetBox, ServiceNow) and vulnerability (Nessus, Tenable, Qualys, Trivy) importers:
golden synthetic fixtures, scope drops, completeness, and fail-closed parsing. No network."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from aisw.adapters.imports_base import ImportAdapter
from aisw.adapters.inventory_imports import NetboxImportAdapter, ServiceNowImportAdapter
from aisw.adapters.vuln_imports import (
    NessusImportAdapter,
    QualysImportAdapter,
    TenableImportAdapter,
    TrivyImportAdapter,
)
from aisw.gateway.registry import AdapterJob, AdapterOutput
from aisw.policy.engine import PackRegistry, PythonRuleEvaluator
from tests.http_server import loopback_only

pytestmark = pytest.mark.security
GOLD = Path(__file__).resolve().parents[1] / "fixtures" / "golden"
NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
NETBOX, SNOW = NetboxImportAdapter(clock=lambda: NOW), ServiceNowImportAdapter(clock=lambda: NOW)
NESSUS, TENABLE = NessusImportAdapter(clock=lambda: NOW), TenableImportAdapter(clock=lambda: NOW)
QUALYS, TRIVY = QualysImportAdapter(clock=lambda: NOW), TrivyImportAdapter(clock=lambda: NOW)
NET = ipaddress.ip_network("10.20.0.0/24")


@pytest.fixture(autouse=True)
def no_network() -> Iterator[None]:
    with loopback_only() as attempts:
        yield
        assert attempts == [], "an import adapter touched the network"


def in_net(kind: str, sel: str) -> bool:
    return kind == "host" and ipaddress.ip_address(sel) in NET


def run(
    a: ImportAdapter,
    text: str,
    kind: str = "cidr",
    scope: Callable[[str, str], bool] | None = in_net,
) -> AdapterOutput:
    data = text.encode()
    return a.execute(AdapterJob(
        tenant_id="t", project_id="p", run_id="r", task_id="k", profile=next(iter(a.profiles)),
        target_kind=kind, target_selector="10.20.0.0/24" if kind == "cidr" else "grp",
        params={"import_id": "imp-" + "a" * 20}, read_import=lambda i, k: data, in_scope=scope,
    ))  # fmt: skip


def judged(
    a: ImportAdapter, out: AdapterOutput, pack: str = "import-baseline:1.0.0"
) -> dict[tuple[str, str], str]:
    p = PackRegistry.builtin().get(pack)
    assert p is not None
    b = a.normalize(out, run_id="r", task_id="k")
    assets = {x.asset_id: x for x in b.assets}
    res = {}
    for o in b.observations:
        outcome = PythonRuleEvaluator().evaluate_observation(
            p, rule_id=o.rule_id, value=o.value, attrs=assets[o.asset_id].attrs
        )
        assert outcome is not None, o.rule_id
        res[(assets[o.asset_id].hostname, o.rule_id)] = outcome.value
    return res


def gold(name: str) -> str:
    return (GOLD / name).read_text()


# ---- inventory --------------------------------------------------------------------------------------
def test_netbox_maps_custom_fields_only_and_skips_inactive_records() -> None:
    out = run(NETBOX, gold("netbox.json"), "asset_group", None)
    assert out.status == "SUCCEEDED"
    assert out.warnings == [
        "NOT_ACTIVE_SKIPPED:2",
        "OWNER_UNKNOWN:host-2",
        "STALE_RECORD:host-3:2026-01-02",
    ]
    recs = {r["asset_id"]: r for r in out.raw["records"]}
    assert set(recs) == {"host-1", "host-2", "host-3"}
    assert recs["host-1"] | {"flags": None} == recs["host-1"] | {
        "ip": "10.20.0.11", "os_family": "linux", "owner": "payments-ops", "criticality": "high",
        "environment": "prod", "source": "netbox-device", "flags": None}  # fmt: skip
    assert recs["host-2"]["owner"] is None  # the tenant "Payments" is not an owner
    assert recs["host-3"]["source"] == "netbox-vm" and recs["host-3"]["owner"] == "platform-team"
    assert judged(NETBOX, out)[("host-2", "cmdb.owner_known")] == "FAIL"


def test_a_paginated_netbox_page_is_partial() -> None:
    text = gold("netbox.json").replace(
        '"next": null', '"next": "https://netbox.corp.test/api/dcim/devices/?offset=5"'
    )
    out = run(NETBOX, text.replace('"count": 5', '"count": 900'), "asset_group", None)
    assert out.status == "PARTIAL" and out.warnings[0] == "EXPORT_TRUNCATED:5 of 900"


def test_servicenow_reads_raw_and_display_values_and_skips_retired() -> None:
    out = run(SNOW, gold("servicenow.json"), "asset_group", None)
    recs = {r["asset_id"]: r for r in out.raw["records"]}
    assert "retired-01" not in recs and out.warnings[0] == "NOT_ACTIVE_SKIPPED:1"
    assert (
        recs["host-1"]["owner"] == "Payments Ops"
        and recs["host-1"]["criticality"] == "1 - most critical"
    )
    assert (
        recs["host-1"]["hostname"] == "host-1.corp.example.com"
        and recs["host-1"]["environment"] == "Production"
    )
    assert (
        recs["host-2"]["owner"] is None and recs["host-2"]["fresh"] is True
    )  # falls back to sys_updated_on
    legacy = next(r for r in recs.values() if r["hostname"] == "host 3 (legacy)")
    assert legacy["asset_id"].startswith("sn-") and legacy["fresh"] is False


@pytest.mark.parametrize("adapter", [NETBOX, SNOW], ids=lambda a: a.adapter_id)
@pytest.mark.parametrize("text", ['{"items": []}', "[1, 2]", "not json"])
def test_inventory_imports_fail_closed(adapter: ImportAdapter, text: str) -> None:
    out = run(adapter, text, "asset_group", None)
    assert out.status == "FAILED" and out.errors[0] in {"UNSUPPORTED_FORMAT", "MALFORMED_JSON"}


# ---- host vulnerability scanners -------------------------------------------------------------------
def test_nessus_judges_finished_hosts_only_and_names_uncredentialed_scans() -> None:
    out = run(NESSUS, gold("nessus.xml"))
    assert out.status == "PARTIAL"
    assert out.warnings == [
        "OUT_OF_SCOPE_RECORDS_DROPPED:1",
        "UNCREDENTIALED_SCAN:db-01",
        "SCAN_INCOMPLETE:10.20.0.13",
    ]
    assert "stray" not in str(out.raw).lower()
    b = NESSUS.normalize(out, run_id="r", task_id="k")
    assert {a.hostname: a.status for a in b.assets}["10.20.0.13"] == "UNSUPPORTED"
    assert judged(NESSUS, out) == {
        ("web-01.corp.test", "vuln.max_cvss"): "FAIL", ("web-01.corp.test", "vuln.critical_high_findings"): "FAIL",
        ("db-01", "vuln.max_cvss"): "PASS", ("db-01", "vuln.critical_high_findings"): "PASS",
    }  # fmt: skip


def test_tenable_ignores_fixed_and_informational_results() -> None:
    out = run(TENABLE, gold("tenable.json"))
    assert out.status == "SUCCEEDED" and out.warnings == ["OUT_OF_SCOPE_RECORDS_DROPPED:1"]
    hosts = {h["hostname"]: h for h in out.raw["hosts"]}
    assert hosts["web-01.corp.test"]["crit_high"] == [
        "Synthetic Web Server Remote Code Execution (cvss 9.8) CVE-2099-0001"
    ]
    assert hosts["db-01"]["max_cvss"] == 5.3 and hosts["db-01"]["results"] == 1


def test_qualys_has_no_scores_so_only_the_critical_high_list_is_judged() -> None:
    out = run(QUALYS, gold("qualys.xml"))
    r = judged(QUALYS, out)
    assert r == {("web-01.corp.test", "vuln.critical_high_findings"): "FAIL",
                 ("db-01.corp.test", "vuln.critical_high_findings"): "PASS"}  # fmt: skip
    assert out.raw["hosts"][0]["crit_high"] == [
        "QID 900001 (severity 5)",
        "QID 900005 (severity 4) potential",
    ]


def test_a_qualys_page_with_a_next_url_is_partial() -> None:
    text = gold("qualys.xml").replace(
        "</RESPONSE>",
        "<WARNING><CODE>1980</CODE><URL><![CDATA[https://qualysapi.example/next]]></URL></WARNING></RESPONSE>",
    )
    out = run(QUALYS, text)
    assert out.status == "PARTIAL" and "EXPORT_TRUNCATED:a next page is listed" in out.warnings


@pytest.mark.parametrize(
    ("adapter", "text", "code"),
    [
        (NESSUS, "<NessusClientData><Report/></NessusClientData>", "UNSUPPORTED_FORMAT"),
        (NESSUS, '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><NessusClientData_v2>&e;</NessusClientData_v2>', "XML_FORBIDDEN_CONSTRUCT"),
        (QUALYS, "<SCAN/>", "UNSUPPORTED_FORMAT"),
        (QUALYS, "<HOST_LIST_VM_DETECTION_OUTPUT>", "MALFORMED_XML"),
        (TENABLE, '[{"plugin": {}}]', "UNSUPPORTED_FORMAT"),
        (TRIVY, '{"SchemaVersion": 1, "Results": []}', "UNSUPPORTED_FORMAT"),
    ],
)  # fmt: skip
def test_vulnerability_imports_fail_closed(adapter: ImportAdapter, text: str, code: str) -> None:
    out = run(adapter, text, "asset_group" if adapter is TRIVY else "cidr")
    assert out.status == "FAILED" and out.errors == [code]


# ---- Trivy -------------------------------------------------------------------------------------------
def test_trivy_images_judge_vulnerabilities_and_base_os_support() -> None:
    out = run(TRIVY, gold("trivy.json"), "asset_group", None)
    assert out.status == "SUCCEEDED"
    assert judged(TRIVY, out, "image-baseline:1.0.0") == {
        ("registry.corp.test/payments/api:1.4.2", "image.critical_high_vulns"): "FAIL",
        ("registry.corp.test/payments/api:1.4.2", "image.os_supported"): "PASS",
        ("registry.corp.test/legacy/batch:2019", "image.critical_high_vulns"): "PASS",
        ("registry.corp.test/legacy/batch:2019", "image.os_supported"): "FAIL",  # CentOS 7: EOSL
        ("registry.corp.test/tools/static:latest", "image.critical_high_vulns"): "PASS",
    }  # an image whose OS Trivy did not recognise has no support judgement at all
    api = out.raw["images"][0]["crit_high"]
    assert api == [
        "CVE-2099-1001 libsynth@1.0.0 (CRITICAL, fixed in 1.0.1)",
        "CVE-2099-1002 libsynth-utils@1.0.0 (HIGH, no fix)",
    ]


def test_trivy_non_image_artifacts_and_missing_results_are_named() -> None:
    import json

    reports: list[dict[str, Any]] = json.loads(gold("trivy.json"))
    reports[0]["ArtifactType"] = "filesystem"
    del reports[2]["Results"]
    out = run(TRIVY, json.dumps(reports), "asset_group", None)
    assert out.status == "PARTIAL"
    assert out.warnings == ["UNSUPPORTED_ARTIFACT:registry.corp.test/payments/api:1.4.2",
                            "NO_SCAN_RESULTS:registry.corp.test/tools/static:latest"]  # fmt: skip
    b = TRIVY.normalize(out, run_id="r", task_id="k")
    assert {a.hostname: a.status for a in b.assets}[
        "registry.corp.test/tools/static:latest"
    ] == "UNSUPPORTED"
