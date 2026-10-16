"""Scanner report imports for hosts: Greenbone/OpenVAS, Nmap XML, OpenSCAP (XCCDF), Wazuh.

These adapters READ files that were produced elsewhere. They never run a scanner. A report is
only as trustworthy as the profile it claims to have been produced under, so the Nmap importer
checks the recorded command line against the approved bounded profile and refuses anything else.
Formats here follow the documented structures but were written against synthetic, sanitized
fixtures; compatibility with each real tool version is UNVERIFIED (see docs/implementation/status.md).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import shlex
from datetime import date
from typing import Any

from aisw.adapters.imports_base import (
    ImportAdapter,
    ImportParams,
    ImportParseError,
    Parsed,
    cap,
    clean,
    local,
    parse_json,
    parse_xml,
)
from aisw.adapters.normalized import NormalizedAsset, NormalizedBatch, NormalizedObservation
from aisw.contracts.enums import ProfileClass
from aisw.gateway.registry import AdapterJob, AdapterOutput

MAX_LIST = 50


def _ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _provisional(ip: str | None, hostname: str | None) -> str:
    key = ip or (hostname or "unknown")
    return "ip-" + hashlib.sha256(key.encode()).hexdigest()[:12]


def _obs(
    batch: NormalizedBatch, run_id: str, task_id: str, aid: str, rule: str, value: Any
) -> None:
    oid = hashlib.sha256(f"{run_id}|{task_id}|{aid}|{rule}".encode()).hexdigest()[:24]
    batch.observations.append(NormalizedObservation(f"o-{oid}", aid, rule, value))


def _scope_host_ok(adapter: ImportAdapter, job: AdapterJob, ip: str | None) -> bool:
    """For IP-based scopes every host must be inside the signed scope; group scopes use identity."""
    if job.target_kind in {"cidr", "host"}:
        return ip is not None and not adapter.scope_drop(job, "host", ip)
    return True


def _host_asset(
    rec: dict[str, Any], aid: str, status: str = "SCANNED", reason: str | None = None
) -> NormalizedAsset:
    ident = {k: v for k, v in {"ip": rec.get("ip"), "hostname": rec.get("hostname")}.items() if v}
    return NormalizedAsset(
        aid, rec.get("hostname") or rec.get("ip") or aid, {"asset_class": "host"},
        status, reason, asset_type="host", identity=ident or None,  # type: ignore[arg-type]
    )  # fmt: skip


# ================================================================ Greenbone / OpenVAS
class GreenboneImportAdapter(ImportAdapter):
    adapter_id = "greenbone_import"
    tool = "aisw-greenbone-import"
    domains = frozenset({"host"})
    profiles = {"GREENBONE_REPORT_IMPORT": ProfileClass.READ_ONLY}
    target_kinds = frozenset({"asset_group", "cidr", "host"})
    import_kinds = frozenset({"greenbone_xml"})
    formats = (
        "GMP report XML: report/scan_run_status, feed_version (YYYYMMDD), host/ip, results/result (host, nvt, cvss_base, severity)",
    )  # noqa: E501
    param_model = ImportParams

    def parse(self, text: str, job: AdapterJob, params: ImportParams) -> Parsed:
        root = parse_xml(text)
        if "report" not in {local(e.tag) for e in root.iter()} | {local(root.tag)}:
            raise ImportParseError("UNSUPPORTED_FORMAT")

        def first(tag: str) -> str:
            return next(
                (clean(e.text, 60) for e in root.iter() if local(e.tag) == tag and e.text), ""
            )

        status_txt, feed = first("scan_run_status") or "Unknown", first("feed_version")
        hosts: dict[str, dict[str, Any]] = {}
        dropped = 0

        def host_rec(ip: str, hostname: str | None) -> dict[str, Any] | None:
            nonlocal dropped
            if not _scope_host_ok(self, job, ip):
                dropped += 1
                return None
            rec = hosts.setdefault(
                ip, {"ip": ip, "hostname": hostname, "results": 0, "max_cvss": 0.0, "crit_high": []}
            )
            rec["hostname"] = rec["hostname"] or hostname
            return rec

        for el in root.iter():
            if local(el.tag) == "host" and any(local(c.tag) == "ip" for c in el):
                ip = _ip(next((c.text or "" for c in el if local(c.tag) == "ip"), ""))
                name = next(
                    (
                        clean(d.findtext("{*}value") or d.findtext("value"), 253)
                        for d in el
                        if local(d.tag) == "detail"
                        and clean(d.findtext("{*}name") or d.findtext("name")) == "hostname"
                    ),
                    None,
                )  # noqa: E501
                if ip:
                    host_rec(ip, name or None)
        results = cap([e for e in root.iter() if local(e.tag) == "result"])
        for res in results:
            hel = next((c for c in res if local(c.tag) == "host"), None)
            ip = _ip((hel.text or "") if hel is not None else "")
            if ip is None:
                continue
            hn = next(
                (
                    clean(c.text, 253)
                    for c in (hel if hel is not None else [])
                    if local(c.tag) == "hostname"
                ),
                None,
            )
            rec = host_rec(ip, hn)
            if rec is None:
                continue
            nvt = next((c for c in res if local(c.tag) == "nvt"), None)
            name = clean(
                next(
                    (c.text for c in (nvt if nvt is not None else []) if local(c.tag) == "name"),
                    None,
                )
                or res.findtext("name"),
                120,
            )
            try:
                sev = float(clean(res.findtext("severity") or "0", 10))
            except ValueError:
                continue
            rec["results"] += 1
            rec["max_cvss"] = max(rec["max_cvss"], sev)
            if sev >= 7.0 and len(rec["crit_high"]) < MAX_LIST:
                cves = [
                    clean(r.get("id"), 20)
                    for r in (nvt if nvt is not None else [])
                    for r in r
                    if local(r.tag) == "ref" and r.get("type") == "cve"
                ]
                rec["crit_high"].append(
                    f"{name} (cvss {sev})" + (f" {','.join(cves[:3])}" if cves else "")
                )
        warnings: list[str] = []
        if dropped:
            warnings.append(f"OUT_OF_SCOPE_RECORDS_DROPPED:{dropped}")
        complete = status_txt.lower() == "done"
        if not complete:
            warnings.append(f"SCAN_INCOMPLETE:{status_txt}")
        feed_age: int | None = None
        if re.fullmatch(r"\d{8}", feed):
            feed_age = (
                self._clock().date() - date(int(feed[:4]), int(feed[4:6]), int(feed[6:]))
            ).days
            if feed_age > 7:
                warnings.append(f"FEED_STALE:{feed_age}d")
        else:
            warnings.append("FEED_STALE:unknown")
        raw = {"scan_run_status": status_txt, "feed_version": feed or None, "feed_age_days": feed_age,
               "complete": complete, "dropped_out_of_scope": dropped,
               "hosts": sorted(hosts.values(), key=lambda h: h["ip"])}  # fmt: skip
        return Parsed(raw, tool_version=f"greenbone-feed-{feed or 'unknown'}",
                      status="SUCCEEDED" if complete else "PARTIAL", warnings=warnings)  # fmt: skip

    def normalize(self, output: AdapterOutput, *, run_id: str, task_id: str) -> NormalizedBatch:
        b = NormalizedBatch()
        for h in output.raw.get("hosts", []):
            aid = _provisional(h["ip"], h["hostname"])
            b.assets.append(_host_asset(h, aid))
            if output.raw["complete"]:  # a clean host is only "clean" if the scan actually finished
                _obs(b, run_id, task_id, aid, "vuln.max_cvss", h["max_cvss"])
                _obs(b, run_id, task_id, aid, "vuln.critical_high_findings", h["crit_high"])
            if output.raw["feed_age_days"] is not None:
                _obs(b, run_id, task_id, aid, "scan.feed_age_days", output.raw["feed_age_days"])
        return b


# ================================================================ Nmap XML
ALLOWED_FLAGS = {
    "-sT",
    "-sS",
    "-sn",
    "-Pn",
    "-n",
    "-v",
    "-vv",
    "--open",
    "--reason",
    "-T0",
    "-T1",
    "-T2",
    "-T3",
}
FLAGS_WITH_VALUE = {
    "--top-ports",
    "-p",
    "--max-retries",
    "--host-timeout",
    "--max-rate",
    "-oX",
    "-oN",
    "-oG",
}


def nmap_args_violation(args: str) -> str | None:
    """Return the first part of the recorded command line that is outside the approved profile."""
    try:
        tokens = shlex.split(args)
    except ValueError:
        return "UNPARSEABLE_ARGS"
    it = iter(tokens[1:])  # tokens[0] is the program name
    for t in it:
        if t in ALLOWED_FLAGS:
            continue
        if t in FLAGS_WITH_VALUE:
            v = next(it, "")
            if not v:  # a flag that needs a value but has none is a malformed command line
                return f"{t} (missing value)"[:60]
            ok = {
                "--top-ports": v.isdigit() and 1 <= int(v) <= 100,
                "--max-retries": v.isdigit() and int(v) <= 2,
                "--max-rate": v.isdigit() and 1 <= int(v) <= 100,
                "--host-timeout": bool(re.fullmatch(r"\d{1,5}[smh]?", v)),
                "-p": bool(re.fullmatch(r"[0-9,]{1,300}", v))
                and len(v.split(",")) <= 100
                and all(x.isdigit() and 0 < int(x) < 65536 for x in v.split(",") if x),
            }.get(t, True)
            if not ok:
                return f"{t} {v}"[:60]
            continue
        if t.startswith("-"):
            return t[:60]  # --script, -sC, -A, -O, -sV, -T4, -sU, --min-rate ... all refused
    return None


class NmapImportAdapter(ImportAdapter):
    adapter_id = "nmap_import"
    tool = "aisw-nmap-import"
    domains = frozenset({"network"})
    profiles = {"NMAP_BOUNDED_IMPORT": ProfileClass.READ_ONLY}
    target_kinds = frozenset({"cidr", "host", "asset_group"})
    import_kinds = frozenset({"nmap_xml"})
    formats = (
        "nmaprun XML (xmloutputversion 1.0x) from the approved bounded profile: -sT/-sS, -T0-3, <=100 ports, <=2 retries, no scripts/version/OS detection",
    )  # noqa: E501
    param_model = ImportParams

    def parse(self, text: str, job: AdapterJob, params: ImportParams) -> Parsed:
        root = parse_xml(text)
        if local(root.tag) != "nmaprun":
            raise ImportParseError("UNSUPPORTED_FORMAT")
        args = root.get("args", "")
        if not args:
            raise ImportParseError("SCAN_ARGS_UNVERIFIABLE")
        if (bad := nmap_args_violation(args)) is not None:
            raise ImportParseError(f"SCAN_PROFILE_VIOLATION:{bad}")
        scaninfo = next((c for c in root if local(c.tag) == "scaninfo"), None)
        if scaninfo is not None and scaninfo.get("type") not in {"connect", "syn", None}:
            raise ImportParseError("SCAN_PROFILE_VIOLATION:scan type")
        hosts: list[dict[str, Any]] = []
        dropped = 0
        for h in cap([e for e in root if local(e.tag) == "host"]):
            addr = next(
                (
                    _ip(a.get("addr", ""))
                    for a in h
                    if local(a.tag) == "address" and a.get("addrtype") in {"ipv4", "ipv6"}
                ),
                None,
            )
            if addr is None or not _scope_host_ok(self, job, addr):
                dropped += 1 if addr is not None else 0
                continue
            state = next((s.get("state") for s in h if local(s.tag) == "status"), "unknown")
            name = next(
                (
                    clean(n.get("name"), 253)
                    for hn in h
                    if local(hn.tag) == "hostnames"
                    for n in hn
                    if local(n.tag) == "hostname"
                ),
                None,
            )
            ports = [
                {"port": int(p.get("portid", 0)), "proto": clean(p.get("protocol"), 8),
                 "service": clean(next((s.get("name") for s in p if local(s.tag) == "service"), ""), 40)}
                for pe in h if local(pe.tag) == "ports" for p in pe if local(p.tag) == "port"
                if next((s.get("state") for s in p if local(s.tag) == "state"), "") == "open" and (p.get("portid") or "").isdigit()
            ]  # fmt: skip
            hosts.append({"ip": addr, "hostname": name, "state": state, "open_ports": sorted({p["port"] for p in ports}),
                          "services": sorted(ports, key=lambda x: (x["proto"], x["port"]))[:200]})  # fmt: skip
        finished = next(
            (
                e
                for r in root
                if local(r.tag) == "runstats"
                for e in r
                if local(e.tag) == "finished"
            ),
            None,
        )
        exit_ok = finished is not None and finished.get("exit") == "success"
        warnings = [f"OUT_OF_SCOPE_RECORDS_DROPPED:{dropped}"] if dropped else []
        if not exit_ok:
            warnings.append("SCAN_INCOMPLETE:nmap did not report a successful exit")
        raw = {"args": clean(args, 400), "scan_type": scaninfo.get("type") if scaninfo is not None else None,
               "nmap_version": clean(root.get("version"), 20), "exit_success": exit_ok,
               "dropped_out_of_scope": dropped, "hosts": sorted(hosts, key=lambda x: x["ip"])}  # fmt: skip
        return Parsed(raw, tool_version=f"nmap-{raw['nmap_version'] or 'unknown'}",
                      status="SUCCEEDED" if exit_ok else "PARTIAL", warnings=warnings)  # fmt: skip

    def normalize(self, output: AdapterOutput, *, run_id: str, task_id: str) -> NormalizedBatch:
        b = NormalizedBatch()
        for h in output.raw.get("hosts", []):
            aid = _provisional(h["ip"], h["hostname"])
            if h["state"] != "up":  # down/unknown is NOT "no open ports"
                b.assets.append(_host_asset(h, aid, "UNREACHABLE", f"host state {h['state']}"))
                continue
            b.assets.append(_host_asset(h, aid))
            _obs(b, run_id, task_id, aid, "net.open_ports", h["open_ports"])
        return b


# ================================================================ OpenSCAP (XCCDF)
class OpenScapImportAdapter(ImportAdapter):
    adapter_id = "openscap_import"
    tool = "aisw-openscap-import"
    domains = frozenset({"host"})
    profiles = {"OPENSCAP_RESULTS_IMPORT": ProfileClass.READ_ONLY}
    target_kinds = frozenset({"asset_group", "host"})
    import_kinds = frozenset({"openscap_xccdf"})
    formats = (
        "XCCDF 1.2 results: TestResult with target, target-address, rule-result idref/severity and result",
    )
    param_model = ImportParams

    def parse(self, text: str, job: AdapterJob, params: ImportParams) -> Parsed:
        root = parse_xml(text)
        results = [e for e in root.iter() if local(e.tag) == "TestResult"]
        if not results:
            raise ImportParseError("UNSUPPORTED_FORMAT")
        hosts: list[dict[str, Any]] = []
        warnings: list[str] = []
        dropped = unchecked = 0
        for tr in cap(results):
            ip = _ip(next((t.text or "" for t in tr if local(t.tag) == "target-address"), ""))
            name = next((clean(t.text, 253) for t in tr if local(t.tag) == "target"), None)
            if not _scope_host_ok(self, job, ip):
                dropped += 1
                continue
            failed: list[str] = []
            evaluated = 0
            for rr in (e for e in tr if local(e.tag) == "rule-result"):
                res = clean(next((c.text for c in rr if local(c.tag) == "result"), ""), 20).lower()
                if res in {"pass", "fail", "fixed", "notapplicable", "informational"}:
                    evaluated += 1
                if res == "fail" and len(failed) < MAX_LIST * 2:
                    failed.append(
                        f"{clean(rr.get('idref'), 160).replace('xccdf_org.ssgproject.content_rule_', '')} ({clean(rr.get('severity'), 10)})"
                    )
                elif res in {"error", "unknown", "notchecked"}:
                    unchecked += 1
            hosts.append({"ip": ip, "hostname": name, "failed_rules": sorted(failed), "evaluated": evaluated,
                          "version": clean(tr.get("version"), 20)})  # fmt: skip
        if dropped:
            warnings.append(f"OUT_OF_SCOPE_RECORDS_DROPPED:{dropped}")
        if unchecked:
            warnings.append(f"RULES_NOT_CHECKED:{unchecked}")
        version = next((h["version"] for h in hosts if h["version"]), "") or "unknown"
        return Parsed({"hosts": hosts, "rules_not_checked": unchecked, "dropped_out_of_scope": dropped},
                      tool_version=f"openscap-{version}", status="PARTIAL" if unchecked else "SUCCEEDED", warnings=warnings)  # fmt: skip

    def normalize(self, output: AdapterOutput, *, run_id: str, task_id: str) -> NormalizedBatch:
        b = NormalizedBatch()
        for h in output.raw.get("hosts", []):
            aid = _provisional(h["ip"], h["hostname"])
            if (
                h["evaluated"] == 0
            ):  # a result with no evaluated rules proves nothing: NOT "no failures"
                b.assets.append(_host_asset(h, aid, "UNSUPPORTED", "NO_RULE_RESULTS"))
                continue
            b.assets.append(_host_asset(h, aid))
            _obs(b, run_id, task_id, aid, "scap.failed_rules", h["failed_rules"])
        return b


# ================================================================ Wazuh
class WazuhImportAdapter(ImportAdapter):
    adapter_id = "wazuh_import"
    tool = "aisw-wazuh-import"
    domains = frozenset({"host"})
    profiles = {"WAZUH_EXPORT_IMPORT": ProfileClass.READ_ONLY}
    target_kinds = frozenset({"asset_group"})
    import_kinds = frozenset({"wazuh_json"})
    formats = (
        "JSON {manager_version, agents: {data.affected_items[]}, sca: {<agent id>: {data.affected_items[].checks[]}}}",
    )
    param_model = ImportParams

    def parse(self, text: str, job: AdapterJob, params: ImportParams) -> Parsed:
        data = parse_json(text)
        if not isinstance(data, dict) or "agents" not in data:
            raise ImportParseError("UNSUPPORTED_FORMAT")
        try:
            agents = cap(list(data["agents"]["data"]["affected_items"]))
        except (KeyError, TypeError) as exc:
            raise ImportParseError("UNSUPPORTED_FORMAT") from exc
        sca = data.get("sca") or {}
        out: list[dict[str, Any]] = []
        warnings: list[str] = []
        for a in agents:
            if not isinstance(a, dict):
                continue
            aid = clean(a.get("id"), 20)
            ip, name = _ip(clean(a.get("ip"), 45)), clean(a.get("name"), 253) or None
            active = clean(a.get("status"), 20).lower() == "active"
            failed: list[str] = []
            have_sca = False
            for pol in (sca.get(aid) or {}).get("data", {}).get("affected_items", []):
                have_sca = True
                failed += [
                    f"{clean(c.get('policy_id') or pol.get('policy_id'), 60)}:{clean(c.get('id'), 20)}"
                    for c in pol.get("checks", [])
                    if clean(c.get("result"), 20).lower() == "failed"
                ]
            if not active:
                warnings.append(f"AGENT_DISCONNECTED:{name or aid}")
            out.append({"agent_id": aid, "ip": ip, "hostname": name, "active": active, "have_sca": have_sca,
                        "failed_checks": sorted(failed)[:200], "last_keepalive": clean(a.get("lastKeepAlive"), 40),
                        "os": clean((a.get("os") or {}).get("name"), 60)})  # fmt: skip
        return Parsed({"agents": out}, tool_version=f"wazuh-{clean(data.get('manager_version'), 20) or 'unknown'}",
                      status="PARTIAL" if warnings else "SUCCEEDED", warnings=warnings)  # fmt: skip

    def normalize(self, output: AdapterOutput, *, run_id: str, task_id: str) -> NormalizedBatch:
        b = NormalizedBatch()
        for a in output.raw.get("agents", []):
            aid = _provisional(a["ip"], a["hostname"])
            if not a["active"]:
                b.assets.append(
                    _host_asset(
                        a,
                        aid,
                        "UNREACHABLE",
                        f"agent disconnected (last keepalive {a['last_keepalive'] or 'unknown'})",
                    )
                )
                continue
            b.assets.append(_host_asset(a, aid))
            if a["have_sca"]:  # no SCA data means NOT assessed, never "no failures"
                _obs(b, run_id, task_id, aid, "sca.failed_checks", a["failed_checks"])
        return b
