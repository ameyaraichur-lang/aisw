"""Prowler JSON import (cloud posture). Imports results; never calls a cloud API or assumes a role.

Fixtures and parsers follow the documented per-finding field names (Provider, AccountId, Region,
ServiceName, CheckID, Severity, Status, ResourceId, StatusExtended). Other shapes fail closed with
UNSUPPORTED_FORMAT. Real-tool compatibility per version is UNVERIFIED (see status.md).
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any

from aisw.adapters.imports_base import (
    ImportAdapter,
    ImportParams,
    ImportParseError,
    Parsed,
    cap,
    clean,
    parse_json,
)
from aisw.adapters.normalized import NormalizedAsset, NormalizedBatch, NormalizedObservation
from aisw.contracts.enums import ProfileClass
from aisw.gateway.registry import AdapterJob, AdapterOutput

REQUIRED = {
    "Provider",
    "AccountId",
    "Region",
    "ServiceName",
    "CheckID",
    "Severity",
    "Status",
    "ResourceId",
}
DENIED_HINTS = (
    "accessdenied",
    "access denied",
    "not authorized",
    "unauthorizedoperation",
    "forbidden",
    "permission",
)
HIGH = {"critical", "high"}


def resource_asset_id(account: str, region: str, resource: str) -> str:
    return "cr-" + hashlib.sha256(f"{account}|{region}|{resource}".encode()).hexdigest()[:14]


class ProwlerImportAdapter(ImportAdapter):
    adapter_id = "prowler_import"
    tool = "aisw-prowler-import"
    domains = frozenset({"cloud"})
    profiles = {"PROWLER_IMPORT": ProfileClass.READ_ONLY}
    target_kinds = frozenset({"cloud_account"})
    import_kinds = frozenset({"prowler_json"})
    formats = (
        "Prowler JSON findings array (per-finding Provider/AccountId/Region/ServiceName/CheckID/Severity/Status/ResourceId)",
    )  # noqa: E501
    param_model = ImportParams

    def parse(self, text: str, job: AdapterJob, params: ImportParams) -> Parsed:
        data = parse_json(text)
        if not isinstance(data, list) or not all(isinstance(f, dict) for f in data):
            raise ImportParseError("UNSUPPORTED_FORMAT")
        findings = cap(data)
        if findings and not all(set(f) >= REQUIRED for f in findings):
            raise ImportParseError("UNSUPPORTED_FORMAT")
        account = job.target_selector
        warnings: list[str] = []
        dropped = 0
        per_resource: dict[tuple[str, str, str], dict[str, Any]] = {}
        coverage: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))
        denied: set[str] = set()
        unsupported: set[str] = set()
        versions: set[str] = set()
        for f in findings:
            acct = clean(f["AccountId"], 40)
            if acct != account:  # a file for several accounts may only contribute the approved one
                dropped += 1
                continue
            region, service = clean(f["Region"], 40), clean(f["ServiceName"], 60)
            status, sev = clean(f["Status"], 20).upper(), clean(f["Severity"], 20).lower()
            check, rid = clean(f["CheckID"], 120), clean(f["ResourceId"], 300)
            if f.get("ProwlerVersion"):
                versions.add(clean(f["ProwlerVersion"], 30))
            coverage[(region, service)][status] += 1
            extended = clean(f.get("StatusExtended"), 200).lower()
            if status == "ERROR" or any(h in extended for h in DENIED_HINTS):
                denied.add(f"{acct}/{region}/{service}")  # a gap: never escalate, never pass
                continue
            if status not in {"PASS", "FAIL"}:  # MANUAL / INFO: not automatically assessable
                unsupported.add(f"{service}/{check}")
                continue
            res = per_resource.setdefault(
                (acct, region, rid),
                {"provider": clean(f["Provider"], 20), "account": acct, "region": region, "service": service,
                 "resource_id": rid, "high_critical_failures": set(), "other_failures": set(), "checks": 0},
            )  # fmt: skip
            res["checks"] += 1
            if status == "FAIL":
                (res["high_critical_failures"] if sev in HIGH else res["other_failures"]).add(check)
        if dropped:
            warnings.append(f"OUT_OF_SCOPE_RECORDS_DROPPED:{dropped}")
        warnings += [f"PERMISSION_DENIED:{d}" for d in sorted(denied)]
        warnings += [f"UNSUPPORTED_SERVICE:{u}" for u in sorted(unsupported)]
        resources = [
            {**{k: v for k, v in r.items() if not isinstance(v, set)},
             "asset_id": resource_asset_id(r["account"], r["region"], r["resource_id"]),
             "high_critical_failures": sorted(r["high_critical_failures"]),
             "other_failures": sorted(r["other_failures"])}
            for r in sorted(per_resource.values(), key=lambda x: (x["region"], x["resource_id"]))
        ]  # fmt: skip
        raw = {
            "account": account, "finding_count": len(findings), "dropped_out_of_scope": dropped,
            "coverage": [{"region": r, "service": s, "results": dict(c)} for (r, s), c in sorted(coverage.items())],
            "resources": resources,
        }  # fmt: skip
        partial = bool(denied or unsupported)
        return Parsed(raw, tool_version=("prowler-" + "+".join(sorted(versions))) if versions else "prowler-unknown",
                      status="PARTIAL" if partial else "SUCCEEDED", warnings=warnings)  # fmt: skip

    def normalize(self, output: AdapterOutput, *, run_id: str, task_id: str) -> NormalizedBatch:
        batch = NormalizedBatch(
            warnings=[w for w in output.warnings if w.startswith("OUT_OF_SCOPE")]
        )
        batch.warnings += [
            w
            for w in output.warnings
            if w.split(":")[0] in {"PERMISSION_DENIED", "UNSUPPORTED_SERVICE"}
        ]
        for r in output.raw.get("resources", []):
            aid = r["asset_id"]
            batch.assets.append(NormalizedAsset(
                aid, r["resource_id"], {"asset_class": "cloud_resource", "provider": r["provider"], "service": r["service"]},
                "SCANNED", None, asset_type="cloud_resource",
                native_ids={"provider": r["provider"], "account": r["account"], "region": r["region"], "resource_id": r["resource_id"]},
            ))  # fmt: skip
            for rule, value in (("cloud.high_critical_failures", r["high_critical_failures"]),
                                ("cloud.other_failures", r["other_failures"])):  # fmt: skip
                oid = hashlib.sha256(f"{run_id}|{task_id}|{aid}|{rule}".encode()).hexdigest()[:24]
                batch.observations.append(NormalizedObservation(f"o-{oid}", aid, rule, value))
        return batch
