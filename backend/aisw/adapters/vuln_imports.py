"""Vulnerability scanner exports: Nessus (.nessus v2), Tenable VM export, Qualys VMDR detections,
Trivy image reports. These READ files produced elsewhere; they never run a scanner.

Host results feed the same ``vuln.*`` rules as Greenbone, and a host is only "clean" when the
export proves the scan of that host finished. Qualys detections carry no CVSS score, so only the
critical/high list is judged for them. Trivy images feed ``image-baseline``. Formats follow the
documented structures but were written against synthetic fixtures; real-tool compatibility per
version is UNVERIFIED (see docs/implementation/status.md).
"""

from __future__ import annotations

import hashlib
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
from aisw.adapters.normalized import NormalizedAsset, NormalizedBatch
from aisw.adapters.scanner_imports import _host_asset, _ip, _obs, _provisional, _scope_host_ok
from aisw.contracts.enums import ProfileClass
from aisw.gateway.registry import AdapterJob, AdapterOutput

MAX_LIST = 50
HOST_TARGETS = frozenset({"asset_group", "cidr", "host"})


def _score(*values: Any) -> float | None:
    for v in values:
        try:
            return float(clean(v, 10))
        except ValueError:
            continue
    return None


def _label(name: str, score: float | None, cves: list[str]) -> str:
    s = f"{name}" + (f" (cvss {score})" if score is not None else "")
    return s + (f" {','.join(cves[:3])}" if cves else "")


class _HostVulnAdapter(ImportAdapter):
    """Collects per-host results; subclasses fill ``hosts`` from their format."""

    domains = frozenset({"host"})
    target_kinds = HOST_TARGETS
    param_model = ImportParams
    scores = True  # False when the format has no CVSS score per result

    def _host(
        self, hosts: dict[str, dict[str, Any]], ip: str | None, name: str | None
    ) -> dict[str, Any]:
        key = ip or name or "unknown"
        rec = hosts.setdefault(key, {"ip": ip, "hostname": name, "results": 0, "max_cvss": 0.0,
                                     "crit_high": [], "complete": True})  # fmt: skip
        rec["hostname"] = rec["hostname"] or name
        return rec

    def _hit(self, rec: dict[str, Any], label: str, score: float | None, crit_high: bool) -> None:
        rec["results"] += 1
        if score is not None:
            rec["max_cvss"] = max(rec["max_cvss"], score)
        if crit_high and len(rec["crit_high"]) < MAX_LIST:
            rec["crit_high"].append(label)

    def _parsed(self, hosts: dict[str, dict[str, Any]], dropped: int, version: str,
                warnings: list[str] | None = None, partial: bool = False) -> Parsed:  # fmt: skip
        warnings = list(warnings or [])
        if dropped:
            warnings.insert(0, f"OUT_OF_SCOPE_RECORDS_DROPPED:{dropped}")
        incomplete = [h["hostname"] or h["ip"] for h in hosts.values() if not h["complete"]]
        warnings += [f"SCAN_INCOMPLETE:{h}" for h in incomplete[:20]]
        for h in hosts.values():
            h["crit_high"] = sorted(h["crit_high"])
        raw = {"dropped_out_of_scope": dropped, "scores": self.scores,
               "hosts": sorted(hosts.values(), key=lambda h: (h["ip"] or "", h["hostname"] or ""))}  # fmt: skip
        return Parsed(raw, tool_version=version, warnings=warnings,
                      status="PARTIAL" if partial or incomplete else "SUCCEEDED")  # fmt: skip

    def normalize(self, output: AdapterOutput, *, run_id: str, task_id: str) -> NormalizedBatch:
        b = NormalizedBatch()
        for h in output.raw.get("hosts", []):
            aid = _provisional(h["ip"], h["hostname"])
            if not h["complete"]:  # an unfinished host is not a clean host
                b.assets.append(_host_asset(h, aid, "UNSUPPORTED", "SCAN_INCOMPLETE"))
                continue
            b.assets.append(_host_asset(h, aid))
            if output.raw.get("scores"):
                _obs(b, run_id, task_id, aid, "vuln.max_cvss", h["max_cvss"])
            _obs(b, run_id, task_id, aid, "vuln.critical_high_findings", h["crit_high"])
        return b


# ================================================================ Nessus (.nessus v2)
class NessusImportAdapter(_HostVulnAdapter):
    adapter_id = "nessus_import"
    tool = "aisw-nessus-import"
    profiles = {"NESSUS_REPORT_IMPORT": ProfileClass.READ_ONLY}
    import_kinds = frozenset({"nessus_xml"})
    formats = (
        "NessusClientData_v2 XML (.nessus) from Nessus or Tenable.sc: ReportHost, HostProperties (host-ip, HOST_END, Credentialed_Scan), ReportItem severity 0-4",
    )  # noqa: E501

    def parse(self, text: str, job: AdapterJob, params: ImportParams) -> Parsed:
        root = parse_xml(text)
        if local(root.tag) != "NessusClientData_v2":
            raise ImportParseError("UNSUPPORTED_FORMAT")
        hosts: dict[str, dict[str, Any]] = {}
        dropped = 0
        warnings: list[str] = []
        for rh in cap([e for e in root.iter() if local(e.tag) == "ReportHost"]):
            props = {clean(t.get("name"), 40): clean(t.text, 253)
                     for p in rh if local(p.tag) == "HostProperties" for t in p}  # fmt: skip
            ip = _ip(props.get("host-ip") or clean(rh.get("name"), 253))
            if not _scope_host_ok(self, job, ip):
                dropped += 1
                continue
            name = props.get("host-fqdn") or props.get("hostname") or None
            rec = self._host(hosts, ip, name)
            rec["complete"] = bool(props.get("HOST_END"))
            if props.get("Credentialed_Scan", "").lower() == "false":
                warnings.append(f"UNCREDENTIALED_SCAN:{name or ip}")
            for item in (i for i in rh if local(i.tag) == "ReportItem"):
                sev = clean(item.get("severity"), 2)
                if sev in {"", "0"}:
                    continue  # informational
                score = _score(item.findtext("cvss3_base_score"), item.findtext("cvss_base_score"))
                cves = [clean(c.text, 20) for c in item if local(c.tag) == "cve"]
                label = _label(clean(item.get("pluginName"), 120), score, cves)
                self._hit(rec, label, score, sev in {"3", "4"})
        return self._parsed(hosts, dropped, "nessus-v2", warnings[:20])


# ================================================================ Tenable VM export
TENABLE_OPEN = {"open", "reopened"}


class TenableImportAdapter(_HostVulnAdapter):
    adapter_id = "tenable_import"
    tool = "aisw-tenable-import"
    profiles = {"TENABLE_EXPORT_IMPORT": ProfileClass.READ_ONLY}
    import_kinds = frozenset({"tenable_json"})
    formats = (
        "Tenable Vulnerability Management vulns export chunk: JSON list of {asset: {ipv4, hostname, fqdn}, plugin: {name, cvss3_base_score, cve}, severity, state}",
    )  # noqa: E501

    def parse(self, text: str, job: AdapterJob, params: ImportParams) -> Parsed:
        data = parse_json(text)
        items = data.get("vulnerabilities") if isinstance(data, dict) else data
        if not isinstance(items, list) or not all(
            isinstance(i, dict) and "asset" in i and "plugin" in i for i in items
        ):
            raise ImportParseError("UNSUPPORTED_FORMAT")
        hosts: dict[str, dict[str, Any]] = {}
        dropped = 0
        for v in cap(items):
            asset, plugin = v.get("asset") or {}, v.get("plugin") or {}
            ipv4 = asset.get("ipv4")
            ip = _ip(clean(ipv4[0] if isinstance(ipv4, list) and ipv4 else ipv4, 45))
            if not _scope_host_ok(self, job, ip):
                dropped += 1
                continue
            rec = self._host(
                hosts, ip, clean(asset.get("fqdn") or asset.get("hostname"), 253) or None
            )
            sev = clean(v.get("severity"), 10).lower()
            if clean(v.get("state"), 10).lower() not in TENABLE_OPEN or sev in {"info", ""}:
                continue
            score = _score(plugin.get("cvss3_base_score"), plugin.get("cvss_base_score"))
            cves = [clean(c, 20) for c in plugin.get("cve") or []]
            self._hit(
                rec,
                _label(clean(plugin.get("name"), 120), score, cves),
                score,
                sev in {"critical", "high"},
            )
        return self._parsed(hosts, dropped, "tenable-vm-export")


# ================================================================ Qualys VMDR host detections
class QualysImportAdapter(_HostVulnAdapter):
    adapter_id = "qualys_import"
    tool = "aisw-qualys-import"
    profiles = {"QUALYS_DETECTION_IMPORT": ProfileClass.READ_ONLY}
    import_kinds = frozenset({"qualys_xml"})
    formats = (
        "HOST_LIST_VM_DETECTION_OUTPUT XML (/api/2.0/fo/asset/host/vm/detection/): HOST IP, DNS, DETECTION QID, TYPE, SEVERITY 1-5, STATUS",
    )  # noqa: E501
    scores = False

    def parse(self, text: str, job: AdapterJob, params: ImportParams) -> Parsed:
        root = parse_xml(text)
        if local(root.tag) != "HOST_LIST_VM_DETECTION_OUTPUT":
            raise ImportParseError("UNSUPPORTED_FORMAT")
        hosts: dict[str, dict[str, Any]] = {}
        dropped = 0
        for h in cap([e for e in root.iter() if local(e.tag) == "HOST"]):
            ip = _ip(clean(h.findtext("IP"), 45))
            if not _scope_host_ok(self, job, ip):
                dropped += 1
                continue
            rec = self._host(hosts, ip, clean(h.findtext("DNS"), 253) or None)
            for d in h.iter("DETECTION"):
                kind, status = (
                    clean(d.findtext("TYPE"), 20).lower(),
                    clean(d.findtext("STATUS"), 20).lower(),
                )
                if kind == "info" or status == "fixed":
                    continue
                sev = clean(d.findtext("SEVERITY"), 2)
                label = f"QID {clean(d.findtext('QID'), 12)} (severity {sev})" + (
                    " potential" if kind == "potential" else ""
                )
                self._hit(rec, label, None, sev in {"4", "5"})
        truncated = any(
            local(e.tag) == "WARNING" and "URL" in {local(c.tag) for c in e} for e in root.iter()
        )
        warnings = ["EXPORT_TRUNCATED:a next page is listed"] if truncated else []
        return self._parsed(hosts, dropped, "qualys-vmdr-detection", warnings, partial=truncated)


# ================================================================ Trivy (container images)
class TrivyImportAdapter(ImportAdapter):
    adapter_id = "trivy_import"
    tool = "aisw-trivy-import"
    domains = frozenset({"container"})
    profiles = {"TRIVY_IMAGE_REPORT_IMPORT": ProfileClass.READ_ONLY}
    target_kinds = frozenset({"asset_group"})
    import_kinds = frozenset({"trivy_json"})
    formats = (
        "trivy image --format json (SchemaVersion 2): ArtifactName, ArtifactType container_image, Metadata.OS {Family, Name, EOSL}, Results[].Vulnerabilities[]; one report or a list",
    )  # noqa: E501
    param_model = ImportParams

    def parse(self, text: str, job: AdapterJob, params: ImportParams) -> Parsed:
        data = parse_json(text)
        reports = data if isinstance(data, list) else [data]
        if not reports or not all(
            isinstance(r, dict) and r.get("SchemaVersion") == 2 for r in reports
        ):
            raise ImportParseError("UNSUPPORTED_FORMAT")
        images: list[dict[str, Any]] = []
        warnings: list[str] = []
        for r in cap(reports):
            name = clean(r.get("ArtifactName"), 253)
            if clean(r.get("ArtifactType"), 40) != "container_image":
                warnings.append(f"UNSUPPORTED_ARTIFACT:{name}")
                continue
            meta = r.get("Metadata") or {}
            os_ = meta.get("OS") or {}
            digest = clean((meta.get("RepoDigests") or [""])[0], 200) or clean(
                meta.get("ImageID"), 100
            )
            results = r.get("Results")
            vulns = [v for res in results or [] if isinstance(res, dict)
                     for v in res.get("Vulnerabilities") or [] if isinstance(v, dict)]  # fmt: skip
            crit_high = sorted({
                f"{clean(v.get('VulnerabilityID'), 30)} {clean(v.get('PkgName'), 60)}@{clean(v.get('InstalledVersion'), 40)} "
                f"({clean(v.get('Severity'), 10)}" + (f", fixed in {clean(v.get('FixedVersion'), 40)})" if v.get("FixedVersion") else ", no fix)")
                for v in vulns if clean(v.get("Severity"), 10).upper() in {"CRITICAL", "HIGH"}
            })[:MAX_LIST]  # fmt: skip
            if not isinstance(results, list):
                warnings.append(f"NO_SCAN_RESULTS:{name}")
            images.append({"id": "img-" + hashlib.sha256(f"{name}|{digest}".encode()).hexdigest()[:14],
                           "name": name, "digest": digest or None, "scanned": isinstance(results, list),
                           "os": f"{clean(os_.get('Family'), 30)} {clean(os_.get('Name'), 30)}".strip() or None,
                           "eosl": bool(os_.get("EOSL")) if os_.get("Family") else None,
                           "crit_high": crit_high, "vuln_count": len(vulns)})  # fmt: skip
        raw = {"images": images}
        return Parsed(raw, tool_version="trivy-schema-2", warnings=warnings,
                      status="PARTIAL" if warnings else "SUCCEEDED")  # fmt: skip

    def normalize(self, output: AdapterOutput, *, run_id: str, task_id: str) -> NormalizedBatch:
        b = NormalizedBatch()
        for i in output.raw.get("images", []):
            b.assets.append(NormalizedAsset(
                i["id"], i["name"], {"asset_class": "container_image", **({"os": i["os"]} if i["os"] else {})},
                "SCANNED" if i["scanned"] else "UNSUPPORTED", None if i["scanned"] else "NO_SCAN_RESULTS",
                asset_type="container_image",
                native_ids={k: v for k, v in {"image": i["name"], "digest": i["digest"]}.items() if v},
            ))  # fmt: skip
            if i["scanned"]:
                _obs(b, run_id, task_id, i["id"], "image.critical_high_vulns", i["crit_high"])
            if i["eosl"] is not None:  # Trivy did not recognise the OS: support status unknown
                _obs(b, run_id, task_id, i["id"], "image.os_supported", not i["eosl"])
        return b
