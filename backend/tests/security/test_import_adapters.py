"""Import adapters against golden sanitized fixtures. No scanner is run and nothing is contacted:
``loopback_only`` fails any connect(), and every adapter receives its file only via read_import."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from aisw.adapters.cloud_import import ProwlerImportAdapter
from aisw.adapters.cmdb_import import CmdbImportAdapter
from aisw.adapters.imports_base import ImportAdapter
from aisw.adapters.scanner_imports import (
    GreenboneImportAdapter,
    NmapImportAdapter,
    OpenScapImportAdapter,
    WazuhImportAdapter,
    nmap_args_violation,
)
from aisw.adapters.web_import import ZapImportAdapter
from aisw.gateway.registry import AdapterJob, AdapterOutput, ImportReadError
from tests.http_server import loopback_only

pytestmark = pytest.mark.security
GOLD = Path(__file__).resolve().parents[1] / "fixtures" / "golden"
NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
IMPORT_ID = "imp-" + "a" * 20


@pytest.fixture(autouse=True)
def no_network() -> Iterator[list[tuple[str, int]]]:
    with loopback_only() as attempts:
        yield attempts
        assert attempts == [], "an import adapter touched the network"


def gold(name: str) -> str:
    return (GOLD / name).read_text()


def job(
    adapter: ImportAdapter, text: str | bytes | None, *, kind: str = "asset_group", selector: str = "grp",
    profile: str | None = None, scope: Callable[[str, str], bool] | None = None, params: dict[str, Any] | None = None,
    reader: Any = "default",
) -> AdapterJob:  # fmt: skip
    data = text.encode() if isinstance(text, str) else (text or b"")
    rd = (lambda i, k: data) if reader == "default" else reader
    return AdapterJob(
        tenant_id="t", project_id="p", run_id="r", task_id="k",
        profile=profile or next(iter(adapter.profiles)), target_kind=kind, target_selector=selector,
        params={"import_id": IMPORT_ID, **(params or {})}, read_import=rd, in_scope=scope,
    )  # fmt: skip


def run(adapter: ImportAdapter, text: str | bytes | None, **kw: Any) -> AdapterOutput:
    return adapter.execute(job(adapter, text, **kw))


def norm(adapter: ImportAdapter, out: AdapterOutput) -> tuple[Any, dict[tuple[str, str], Any]]:
    b = adapter.normalize(out, run_id="r", task_id="t")
    return b, {(o.asset_id, o.rule_id): o.value for o in b.observations}


def cidr_scope(*cidrs: str) -> Callable[[str, str], bool]:
    import ipaddress

    nets = [ipaddress.ip_network(c) for c in cidrs]
    return lambda kind, sel: kind == "host" and any(ipaddress.ip_address(sel) in n for n in nets)


CMDB, PROWLER, GREEN = (
    CmdbImportAdapter(clock=lambda: NOW),
    ProwlerImportAdapter(clock=lambda: NOW),
    GreenboneImportAdapter(clock=lambda: NOW),
)
NMAP, SCAP, WAZUH, ZAP = (NmapImportAdapter(clock=lambda: NOW), OpenScapImportAdapter(clock=lambda: NOW), WazuhImportAdapter(clock=lambda: NOW), ZapImportAdapter(clock=lambda: NOW))  # fmt: skip
ALL_XML = [(GREEN, "greenbone.xml"), (NMAP, "nmap.xml"), (SCAP, "openscap.xml")]


# ---- hostile input, for every adapter -------------------------------------------------------------
XXE = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun args="nmap -sT">&e;</nmaprun>'
BOMB = '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "AAAA"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;">]><report>&c;</report>'
EXT_DTD = '<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://169.254.169.254/evil.dtd"><report/>'


@pytest.mark.parametrize("adapter", [GREEN, NMAP, SCAP], ids=lambda a: a.adapter_id)
@pytest.mark.parametrize(
    "payload", [XXE, BOMB, EXT_DTD], ids=["xxe-file", "entity-bomb", "external-dtd"]
)
def test_xml_adapters_refuse_dtds_entities_and_external_references(
    adapter: ImportAdapter, payload: str
) -> None:
    out = run(adapter, payload)
    assert (
        out.status == "FAILED"
        and out.errors == ["XML_FORBIDDEN_CONSTRUCT"]
        and out.raw["records"] == []
    )
    assert "root:" not in str(out.raw) and "AAAA" not in str(out.raw)  # nothing was expanded


@pytest.mark.parametrize(
    "adapter", [CMDB, PROWLER, GREEN, NMAP, SCAP, WAZUH, ZAP], ids=lambda a: a.adapter_id
)
@pytest.mark.parametrize(
    ("payload", "codes"),
    [
        ("", {"UNSUPPORTED_FORMAT", "MALFORMED_XML", "MALFORMED_JSON", "SCAN_ARGS_UNVERIFIABLE"}),
        ("not a report at all", {"UNSUPPORTED_FORMAT", "MALFORMED_XML", "MALFORMED_JSON"}),
        ("{" * 5000, {"MALFORMED_JSON", "MALFORMED_XML", "UNSUPPORTED_FORMAT"}),
        ("<a><b></a>", {"MALFORMED_XML", "MALFORMED_JSON", "UNSUPPORTED_FORMAT"}),
        (
            "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[" * 200,
            {"MALFORMED_JSON", "UNSUPPORTED_FORMAT", "MALFORMED_XML"},
        ),
        ('{"agents": 5}', {"UNSUPPORTED_FORMAT", "MALFORMED_XML"}),
    ],
)
def test_garbage_fails_closed_with_a_stable_code(
    adapter: ImportAdapter, payload: str, codes: set[str]
) -> None:
    out = run(adapter, payload)
    assert out.status == "FAILED" and out.errors[0] in codes and out.raw["records"] == []
    assert (
        adapter.normalize(out, run_id="r", task_id="t").assets == []
    )  # a failed import yields no assets


@pytest.mark.parametrize(
    "adapter", [CMDB, PROWLER, GREEN, NMAP, SCAP, WAZUH, ZAP], ids=lambda a: a.adapter_id
)
def test_file_access_only_through_the_gateway_reader(adapter: ImportAdapter) -> None:
    none = adapter.execute(job(adapter, None, reader=None))
    assert none.status == "FAILED" and none.errors == ["IMPORTS_UNAVAILABLE"]

    def missing(i: str, k: frozenset[str]) -> bytes:
        raise ImportReadError("IMPORT_NOT_FOUND")

    assert adapter.execute(job(adapter, None, reader=missing)).errors == ["IMPORT_NOT_FOUND"]
    assert run(adapter, b"\xff\xfe\x00bad").errors == ["NOT_UTF8"]
    seen: list[frozenset[str]] = []

    def spy(i: str, k: frozenset[str]) -> bytes:
        seen.append(k)
        return b"[]"

    adapter.execute(job(adapter, "[]", reader=spy))
    assert seen == [adapter.import_kinds]  # it may only ask for ITS kinds, never "any file"


@pytest.mark.parametrize(
    "adapter", [CMDB, PROWLER, GREEN, NMAP, SCAP, WAZUH, ZAP], ids=lambda a: a.adapter_id
)
@pytest.mark.parametrize(
    "bad",
    [
        {"import_id": "../../etc/passwd"},
        {"import_id": "imp-short"},
        {"import_id": IMPORT_ID, "path": "/etc/passwd"},
        {"import_id": IMPORT_ID, "url": "http://x"},
        {},
    ],
)
def test_parameters_cannot_name_files_paths_or_urls(
    adapter: ImportAdapter, bad: dict[str, Any]
) -> None:
    j = job(adapter, "[]")
    with pytest.raises(ValidationError):
        adapter.execute(AdapterJob(**{**j.__dict__, "params": bad}))


# ---- CMDB + Agent 1 -------------------------------------------------------------------------------
def test_cmdb_csv_reconciliation_and_provenance() -> None:
    out = run(CMDB, gold("cmdb.csv"))
    assert out.status == "SUCCEEDED" and out.tool_version == "cmdb-csv-export"
    assert set(out.warnings) == {"OWNER_UNKNOWN:host-2", "STALE_RECORD:host-3:2025-06-01"}
    b, o = norm(CMDB, out)
    assert [a.asset_id for a in b.assets] == ["host-1", "host-2", "host-3"]
    h2 = next(a for a in b.assets if a.asset_id == "host-2")
    assert h2.owner is None and h2.owner_source is None  # "TBD" is UNKNOWN, never inferred
    assert h2.criticality == "critical" and h2.criticality_source == "cmdb:cmdb-main"
    h3 = next(a for a in b.assets if a.asset_id == "host-3")
    assert (
        h3.criticality is None
        and h3.owner == "team-win"
        and h3.native_ids
        == {"cmdb_id": "host-3", "hostname": "win-01.corp.test", "ip": "10.20.0.13"}
    )
    assert (o["host-1", "cmdb.owner_known"], o["host-2", "cmdb.owner_known"]) == (True, False)
    assert (o["host-3", "cmdb.criticality_known"], o["host-1", "cmdb.criticality_known"]) == (
        False,
        True,
    )
    assert (o["host-1", "cmdb.record_fresh"], o["host-3", "cmdb.record_fresh"]) == (True, False)


def test_cmdb_json_and_csv_normalize_identically() -> None:
    a, b = norm(CMDB, run(CMDB, gold("cmdb.csv"))), norm(CMDB, run(CMDB, gold("cmdb.json")))
    assert b[1] == a[1] and [x.asset_id for x in a[0].assets] == [x.asset_id for x in b[0].assets]
    assert [(x.owner, x.criticality) for x in a[0].assets] == [
        (x.owner, x.criticality) for x in b[0].assets
    ]


def test_cmdb_duplicates_and_conflicts_are_flagged_never_merged() -> None:
    dup = (
        gold("cmdb.csv")
        + "host-9,WEB-01.corp.test.,10.20.0.99,linux,team-x,low,production,2026-10-10T09:00:00Z,cmdb-main\n"
    )
    out = run(CMDB, dup)
    assert out.status == "PARTIAL" and any(
        w.startswith("DUPLICATE_CANDIDATE:host-1,host-9") for w in out.warnings
    )
    assert [a.asset_id for a in norm(CMDB, out)[0].assets] == [
        "host-1",
        "host-2",
        "host-3",
        "host-9",
    ]  # both kept
    conflict = (
        gold("cmdb.csv")
        + "host-1,other.corp.test,10.20.0.77,linux,x,low,production,2026-10-10T09:00:00Z,cmdb-main\n"
    )
    out2 = run(CMDB, conflict)
    assert "CONFLICTING_RECORDS:host-1" in out2.warnings and out2.status == "PARTIAL"
    assert "host-1" not in [
        a.asset_id for a in norm(CMDB, out2)[0].assets
    ]  # an ambiguous record is not trusted


@pytest.mark.parametrize(
    "row",
    [
        "bad id!,h,10.0.0.1,linux,o,low,prod,2026-10-10",
        "host-8,h,not-an-ip,linux,o,low,prod,2026-10-10",
    ],
)
def test_cmdb_invalid_records_are_named_and_skipped(row: str) -> None:
    out = run(CMDB, gold("cmdb.csv") + row + ",cmdb\n")
    assert out.status == "PARTIAL" and any(w.startswith("INVALID_RECORD") for w in out.warnings)
    assert len(out.raw["records"]) == 3


def test_cmdb_format_and_size_limits() -> None:
    assert run(CMDB, "hostname,ip\nx,10.0.0.1\n").errors == [
        "UNSUPPORTED_FORMAT"
    ]  # no asset_id column
    assert run(CMDB, "[1, 2, 3]").errors == ["UNSUPPORTED_FORMAT"]
    big = "asset_id,hostname\n" + "".join(f"h-{i},n{i}\n" for i in range(20_001))
    assert run(CMDB, big).errors == ["TOO_MANY_RECORDS"]
    with pytest.raises(ValidationError):
        CMDB.execute(job(CMDB, "x", params={"stale_days": 0}))
    old = run(
        CMDB, gold("cmdb.csv"), params={"stale_days": 3650}
    )  # a longer window: nothing is stale
    assert not any(w.startswith("STALE_RECORD") for w in old.warnings)


# ---- Prowler --------------------------------------------------------------------------------------
def test_prowler_import_scopes_to_the_account_and_names_every_gap() -> None:
    out = run(PROWLER, gold("prowler.json"), kind="cloud_account", selector="123456789012")
    assert out.status == "PARTIAL" and out.tool_version == "prowler-4.5.0"
    assert set(out.warnings) == {
        "OUT_OF_SCOPE_RECORDS_DROPPED:1",
        "PERMISSION_DENIED:123456789012/eu-west-1/kms",
        "UNSUPPORTED_SERVICE:cloudtrail/cloudtrail_review",
    }  # noqa: E501
    blob = str(out.raw)
    assert (
        "someone-elses-bucket" not in blob and "999999999999" not in blob
    )  # out-of-scope data is not retained
    b, o = norm(PROWLER, out)
    assert len(b.assets) == 2 and all(a.attrs["asset_class"] == "cloud_resource" for a in b.assets)
    by = {a.native_ids["resource_id"]: a.asset_id for a in b.assets if a.native_ids}
    assert o[by["corp-logs"], "cloud.high_critical_failures"] == ["s3_bucket_public_access"]
    assert o[by["corp-logs"], "cloud.other_failures"] == ["s3_bucket_versioning"]
    assert (
        o[by["sg-0abc"], "cloud.high_critical_failures"] == [] and "key-0" not in by
    )  # a denied check is never a PASS
    assert {"region": "eu-west-1", "service": "kms", "results": {"ERROR": 1}} in out.raw["coverage"]


def test_prowler_for_the_wrong_account_yields_nothing_rather_than_someone_elses_data() -> None:
    out = run(PROWLER, gold("prowler.json"), kind="cloud_account", selector="555555555555")
    assert out.raw["resources"] == [] and out.warnings[0] == "OUT_OF_SCOPE_RECORDS_DROPPED:7"
    assert PROWLER.normalize(out, run_id="r", task_id="t").assets == []


def test_prowler_unknown_shapes_fail_closed() -> None:
    assert run(PROWLER, '{"findings": []}', kind="cloud_account").errors == ["UNSUPPORTED_FORMAT"]
    assert run(PROWLER, '[{"CheckID": "x"}]', kind="cloud_account").errors == ["UNSUPPORTED_FORMAT"]


# ---- Greenbone ------------------------------------------------------------------------------------
def test_greenbone_report_to_observations() -> None:
    out = run(GREEN, gold("greenbone.xml"))
    assert (
        out.status == "SUCCEEDED"
        and out.tool_version == "greenbone-feed-20261012"
        and out.warnings == []
    )
    b, o = norm(GREEN, out)
    hosts = {a.identity["ip"]: a.asset_id for a in b.assets if a.identity}
    assert set(hosts) == {
        "10.20.0.11",
        "10.20.0.12",
        "10.99.0.5",
    }  # group scope: unexpected hosts are surfaced
    w = hosts["10.20.0.11"]
    assert o[w, "vuln.max_cvss"] == 9.8 and o[w, "scan.feed_age_days"] == 3
    assert (
        len(o[w, "vuln.critical_high_findings"]) == 1
        and "CVE-2099-0001" in o[w, "vuln.critical_high_findings"][0]
    )
    assert (
        o[hosts["10.20.0.12"], "vuln.max_cvss"] == 0.0
        and o[hosts["10.20.0.12"], "vuln.critical_high_findings"] == []
    )
    assert all(a.identity and a.identity.get("hostname") for a in b.assets)


def test_greenbone_ip_scope_drops_hosts_outside_the_signed_scope() -> None:
    out = run(
        GREEN,
        gold("greenbone.xml"),
        kind="cidr",
        selector="10.20.0.0/24",
        scope=cidr_scope("10.20.0.0/24"),
    )
    assert out.warnings == [
        "OUT_OF_SCOPE_RECORDS_DROPPED:2"
    ]  # the stray host's summary and its result
    assert "10.99.0.5" not in str(out.raw) and "stray-01" not in str(out.raw)


def test_greenbone_incomplete_scan_never_reports_clean_hosts() -> None:
    out = run(
        GREEN,
        gold("greenbone.xml").replace("<scan_run_status>Done", "<scan_run_status>Interrupted"),
    )
    assert out.status == "PARTIAL" and "SCAN_INCOMPLETE:Interrupted" in out.warnings
    _, o = norm(GREEN, out)
    assert not any(rule.startswith("vuln.") for _, rule in o)  # not assessed, not "no findings"


def test_greenbone_stale_or_missing_feed_is_named() -> None:
    old = run(GREEN, gold("greenbone.xml").replace("20261012", "20260801"))
    assert (
        "FEED_STALE:75d" in old.warnings
        and norm(GREEN, old)[1][
            next(a for a in norm(GREEN, old)[0].assets).asset_id, "scan.feed_age_days"
        ]
        == 75
    )
    none = run(GREEN, gold("greenbone.xml").replace("<feed_version>20261012</feed_version>", ""))
    assert "FEED_STALE:unknown" in none.warnings and not any(
        r == "scan.feed_age_days" for _, r in norm(GREEN, none)[1]
    )


# ---- Nmap -----------------------------------------------------------------------------------------
def test_nmap_import_open_ports_as_observations() -> None:
    out = run(
        NMAP,
        gold("nmap.xml"),
        kind="cidr",
        selector="10.20.0.0/24",
        scope=cidr_scope("10.20.0.0/24"),
    )
    assert (
        out.status == "SUCCEEDED"
        and out.tool_version == "nmap-7.95"
        and out.warnings == ["OUT_OF_SCOPE_RECORDS_DROPPED:1"]
    )
    assert "10.99.0.5" not in str(out.raw) and "telnet" not in str(out.raw)
    b, o = norm(NMAP, out)
    ports = {a.identity["ip"]: o[a.asset_id, "net.open_ports"] for a in b.assets if a.identity}
    assert ports == {
        "10.20.0.11": [22, 443],
        "10.20.0.12": [22, 445],
        "10.20.0.13": [3389],
    }  # closed ports are not listed


@pytest.mark.parametrize(
    "args",
    [
        "nmap -sT --script vuln 10.20.0.0/24",
        "nmap -A 10.20.0.11",
        "nmap -sV 10.20.0.11",
        "nmap -sT -T4 10.20.0.11",
        "nmap -sT --top-ports 1000 x",
        "nmap -sT -p 1-65535 x",
        "nmap -sT -iL targets.txt",
        "nmap -sU x",
        "nmap -O x",
        "nmap -sT --min-rate 1000 x",
        "nmap -sT -sC x",
        "nmap -sT --max-retries 9 x",
        "nmap -sT --host-timeout forever x",
        "nmap -sT --max-rate 5000 x",
        "nmap 'unterminated",
    ],
)
def test_nmap_output_from_outside_the_approved_profile_is_refused(args: str) -> None:
    out = run(
        NMAP,
        gold("nmap.xml").replace(
            gold("nmap.xml").split('args="')[1].split('"')[0], args.replace("'", "&apos;")
        ),
    )
    assert (
        out.status == "FAILED"
        and out.errors[0].startswith("SCAN_PROFILE_VIOLATION")
        or out.errors[0] == "SCAN_PROFILE_VIOLATION:UNPARSEABLE_ARGS"
    )
    assert out.raw["records"] == [] and norm(NMAP, out)[0].assets == []


def test_nmap_args_check_accepts_exactly_the_documented_bounded_profile() -> None:
    assert (
        nmap_args_violation(
            "nmap -sT -T2 --top-ports 20 --max-retries 1 --host-timeout 60s scanme.example"
        )
        is None
    )
    assert nmap_args_violation("nmap -sT -Pn -n -p 22,80,443 --open --reason 10.0.0.0/30") is None
    for bad in ("nmap --script=banner x", "nmap -T5 x", "nmap -sT --top-ports 101 x", "nmap -oN"):
        assert nmap_args_violation(bad) is not None, bad


def test_nmap_missing_args_incomplete_runs_and_down_hosts() -> None:
    assert run(
        NMAP,
        gold("nmap.xml").replace(
            ' args="nmap -sT -T2 --top-ports 20 --max-retries 1 --host-timeout 60s -oX scan.xml 10.20.0.0/24"',
            "",
        ),
    ).errors == ["SCAN_ARGS_UNVERIFIABLE"]
    assert run(NMAP, "<other/>").errors == ["UNSUPPORTED_FORMAT"]
    inc = run(NMAP, gold("nmap.xml").replace('exit="success"', 'exit="error"'))
    assert inc.status == "PARTIAL" and any(w.startswith("SCAN_INCOMPLETE") for w in inc.warnings)
    down = run(
        NMAP,
        gold("nmap.xml").replace(
            '<status state="up" reason="syn-ack"/><address addr="10.20.0.13"',
            '<status state="down" reason="no-response"/><address addr="10.20.0.13"',
        ),
    )
    b, o = norm(NMAP, down)
    d = next(a for a in b.assets if a.identity and a.identity["ip"] == "10.20.0.13")
    assert (
        d.status == "UNREACHABLE" and (d.asset_id, "net.open_ports") not in o
    )  # down is not "no open ports"


# ---- OpenSCAP and Wazuh ---------------------------------------------------------------------------
def test_openscap_failed_rules_and_unchecked_rules() -> None:
    out = run(SCAP, gold("openscap.xml"))
    assert (
        out.status == "PARTIAL"
        and out.warnings == ["RULES_NOT_CHECKED:1"]
        and out.tool_version == "openscap-1.3.9"
    )
    b, o = norm(SCAP, out)
    assert o[b.assets[0].asset_id, "scap.failed_rules"] == ["sshd_disable_root_login (high)"]
    assert b.assets[0].identity == {"ip": "10.20.0.11", "hostname": "web-01.corp.test"}
    dropped = run(
        SCAP,
        gold("openscap.xml"),
        kind="host",
        selector="10.20.0.99",
        scope=cidr_scope("10.20.0.99/32"),
    )
    assert dropped.raw["hosts"] == [] and "OUT_OF_SCOPE_RECORDS_DROPPED:1" in dropped.warnings


def test_openscap_result_with_no_evaluated_rules_is_not_assessed_rather_than_clean() -> None:
    empty = "<Benchmark xmlns='http://checklists.nist.gov/xccdf/1.2'><TestResult id='x'><target>t</target><target-address>10.20.0.11</target-address></TestResult></Benchmark>"
    b, o = norm(SCAP, run(SCAP, empty))
    assert [a.status for a in b.assets] == [
        "UNSUPPORTED"
    ] and o == {}  # zero evidence must not become zero failures


def test_wazuh_active_disconnected_and_missing_sca() -> None:
    out = run(WAZUH, gold("wazuh.json"))
    assert (
        out.status == "PARTIAL"
        and out.warnings == ["AGENT_DISCONNECTED:win-01.corp.test"]
        and out.tool_version == "wazuh-4.9.0"
    )
    b, o = norm(WAZUH, out)
    st = {a.identity["hostname"]: a.status for a in b.assets if a.identity}
    assert st == {
        "web-01.corp.test": "SCANNED",
        "db-01.corp.test": "SCANNED",
        "win-01.corp.test": "UNREACHABLE",
    }
    web = next(a for a in b.assets if a.identity["hostname"] == "web-01.corp.test")
    db = next(a for a in b.assets if a.identity["hostname"] == "db-01.corp.test")
    assert (
        o[web.asset_id, "sca.failed_checks"] == ["cis_ubuntu22-04:28500"]
        and o[db.asset_id, "sca.failed_checks"] == []
    )
    assert not any(
        a.identity["hostname"] == "win-01.corp.test" and k == a.asset_id
        for a in b.assets
        for (k, _) in o
    )
    nosca = run(WAZUH, gold("wazuh.json").replace('"002": {"data"', '"zzz": {"data"'))
    _, o2 = norm(WAZUH, nosca)
    assert (
        not any(r == "sca.failed_checks" and "db" in str(a) for (a, r) in o2)
        and len([k for k in o2 if k[1] == "sca.failed_checks"]) == 1
    )  # no data: not assessed


# ---- ZAP ------------------------------------------------------------------------------------------
def zap_scope(kind: str, sel: str) -> bool:
    return kind == "url" and sel.startswith("https://app.corp.test")


def test_zap_baseline_import_keeps_names_and_risk_only() -> None:
    out = run(
        ZAP,
        gold("zap.json"),
        kind="url",
        selector="https://app.corp.test",
        profile="ZAP_BASELINE_IMPORT",
        scope=zap_scope,
    )
    assert (
        out.status == "SUCCEEDED"
        and out.warnings == ["OUT_OF_SCOPE_RECORDS_DROPPED:1"]
        and out.tool_version == "zap-2.15.0"
    )
    blob = str(out.raw)
    assert (
        "not-ours" not in blob
        and "ignored body text" not in blob
        and "https://app.corp.test/" not in blob
    )  # no URIs/desc kept
    b, o = norm(ZAP, out)
    assert len(b.assets) == 1 and b.assets[0].attrs["asset_class"] == "web"
    aid = b.assets[0].asset_id
    assert o[aid, "web.high_alerts"] == [] and o[aid, "web.medium_alerts"] == [
        "Content Security Policy (CSP) Header Not Set [10038]",
        "Missing Anti-clickjacking Header [10020]",
    ]


def test_zap_active_scan_output_cannot_be_imported_as_a_passive_baseline() -> None:
    active = gold("zap.json").replace('"pluginid": "10096"', '"pluginid": "40012"')
    base = run(
        ZAP,
        active,
        kind="url",
        selector="https://app.corp.test",
        profile="ZAP_BASELINE_IMPORT",
        scope=zap_scope,
    )
    assert base.status == "FAILED" and base.errors == [
        "SCAN_PROFILE_VIOLATION:ACTIVE_SCAN_RULES_IN_BASELINE_IMPORT"
    ]
    ok = run(
        ZAP,
        active,
        kind="url",
        selector="https://app.corp.test",
        profile="ZAP_ACTIVE_IMPORT",
        scope=zap_scope,
    )
    assert (
        ok.status == "SUCCEEDED" and ZAP.capability.profiles["ZAP_ACTIVE_IMPORT"].value == "ACTIVE"
    )
    assert ZAP.capability.profiles["ZAP_BASELINE_IMPORT"].value == "READ_ONLY"


def test_zap_malformed_alerts_fail_closed() -> None:
    bad = gold("zap.json").replace(
        '"riskcode": "2", "confidence": "3"', '"riskcode": "banana", "confidence": "3"'
    )
    assert run(ZAP, bad, kind="url", scope=zap_scope).errors == ["UNSUPPORTED_FORMAT"]
    assert run(ZAP, '{"site": "x"}', kind="url").errors == ["UNSUPPORTED_FORMAT"]


# ---- determinism and "scanner says success but saw nothing" ----------------------------------------
@pytest.mark.parametrize(
    ("adapter", "fixture", "kw"),
    [
        (CMDB, "cmdb.csv", {}),
        (PROWLER, "prowler.json", {"kind": "cloud_account", "selector": "123456789012"}),
        (GREEN, "greenbone.xml", {}),
        (NMAP, "nmap.xml", {}),
        (SCAP, "openscap.xml", {}),
        (WAZUH, "wazuh.json", {}),
        (ZAP, "zap.json", {"kind": "url", "selector": "https://app.corp.test", "scope": zap_scope}),
    ],
    ids=lambda x: getattr(x, "adapter_id", None) or (x if isinstance(x, str) else "kw"),
)
def test_same_input_gives_identical_output_and_ids(
    adapter: ImportAdapter, fixture: str, kw: dict[str, Any]
) -> None:
    a, b = run(adapter, gold(fixture), **kw), run(adapter, gold(fixture), **kw)
    assert a.raw == b.raw and a.warnings == b.warnings
    na, nb = (
        adapter.normalize(a, run_id="r", task_id="t"),
        adapter.normalize(b, run_id="r", task_id="t"),
    )
    assert [o.observation_id for o in na.observations] == [
        o.observation_id for o in nb.observations
    ]
    assert len({o.observation_id for o in na.observations}) == len(na.observations)
    other = adapter.normalize(a, run_id="r2", task_id="t")  # ids are scoped to the run
    assert {o.observation_id for o in other.observations}.isdisjoint(
        {o.observation_id for o in na.observations}
    )


@pytest.mark.parametrize(
    ("adapter", "empty", "kw"),
    [
        (CMDB, "asset_id,hostname\n", {}),
        (PROWLER, "[]", {"kind": "cloud_account"}),
        (
            GREEN,
            "<get_reports_response><report><report><scan_run_status>Done</scan_run_status></report></report></get_reports_response>",
            {},
        ),
        (
            NMAP,
            '<nmaprun args="nmap -sT x" version="7.95"><runstats><finished exit="success"/></runstats></nmaprun>',
            {},
        ),
        (
            SCAP,
            "<Benchmark xmlns='http://checklists.nist.gov/xccdf/1.2'><version>1</version></Benchmark>",
            {},
        ),
        (WAZUH, '{"agents": {"data": {"affected_items": []}}}', {}),
        (ZAP, '{"site": []}', {"kind": "url"}),
    ],
    ids=lambda x: getattr(x, "adapter_id", "") if hasattr(x, "adapter_id") else "",
)
def test_a_successful_looking_but_empty_report_yields_no_assets(
    adapter: ImportAdapter, empty: str, kw: dict[str, Any]
) -> None:
    out = run(adapter, empty, **kw)
    assert (
        adapter.normalize(out, run_id="r", task_id="t").assets == []
    )  # the worker turns this into ZERO_ASSETS_RETURNED
