"""OWASP ZAP report import (JSON).

Two profiles, matching the safety model: ZAP_BASELINE_IMPORT (read-only: passive/baseline results)
and ZAP_ACTIVE_IMPORT (class ACTIVE: needs explicit approver acknowledgement). The importer
checks the REPORT, not just the label: active-scan rule ids (40000-49999) inside a baseline import
are refused, so active-scan output cannot be smuggled in under the passive profile.
Only alert names, risk levels and counts are kept; descriptions, URIs and parameters are dropped.
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
    parse_json,
)
from aisw.adapters.normalized import NormalizedAsset, NormalizedBatch, NormalizedObservation
from aisw.adapters.url_smoke import url_asset_id
from aisw.authz.net_guard import NetGuardError, canonicalize_url
from aisw.contracts.enums import ProfileClass
from aisw.gateway.registry import AdapterJob, AdapterOutput

ACTIVE_RULES = range(40000, 50000)  # ZAP active-scan rule id block
MAX_LIST = 50


class ZapImportAdapter(ImportAdapter):
    adapter_id = "zap_import"
    tool = "aisw-zap-import"
    domains = frozenset({"url", "web"})
    profiles = {
        "ZAP_BASELINE_IMPORT": ProfileClass.READ_ONLY,
        "ZAP_ACTIVE_IMPORT": ProfileClass.ACTIVE,
    }
    target_kinds = frozenset({"url"})
    import_kinds = frozenset({"zap_json"})
    formats = (
        "ZAP traditional JSON report: @version, site[] (@name,@host,@port,@ssl, alerts[] pluginid/alert/riskcode/instances)",
    )
    param_model = ImportParams

    def parse(self, text: str, job: AdapterJob, params: ImportParams) -> Parsed:
        data = parse_json(text)
        if not isinstance(data, dict) or not isinstance(data.get("site"), list):
            raise ImportParseError("UNSUPPORTED_FORMAT")
        active_allowed = job.profile == "ZAP_ACTIVE_IMPORT"
        sites: list[dict[str, Any]] = []
        dropped = 0
        for site in cap(data["site"]):
            if not isinstance(site, dict):
                continue
            try:
                origin = canonicalize_url(clean(site.get("@name"), 300)).origin
            except NetGuardError:
                dropped += 1
                continue
            if self.scope_drop(job, "url", origin + "/"):
                dropped += 1
                continue
            high: list[str] = []
            medium: list[str] = []
            n_alerts = 0
            for al in cap(list(site.get("alerts") or [])):
                try:
                    pid = int(clean(al.get("pluginid"), 10))
                    risk = int(clean(al.get("riskcode"), 2))
                except (TypeError, ValueError, AttributeError):
                    raise ImportParseError("UNSUPPORTED_FORMAT") from None
                if pid in ACTIVE_RULES and not active_allowed:
                    raise ImportParseError(
                        "SCAN_PROFILE_VIOLATION:ACTIVE_SCAN_RULES_IN_BASELINE_IMPORT"
                    )
                n_alerts += 1
                name = f"{clean(al.get('alert'), 120)} [{pid}]"
                if risk >= 3 and len(high) < MAX_LIST:
                    high.append(name)
                elif risk == 2 and len(medium) < MAX_LIST:
                    medium.append(name)
            sites.append(
                {
                    "origin": origin,
                    "alerts": n_alerts,
                    "high": sorted(high),
                    "medium": sorted(medium),
                }
            )
        warnings = [f"OUT_OF_SCOPE_RECORDS_DROPPED:{dropped}"] if dropped else []
        raw = {"profile": job.profile, "zap_version": clean(data.get("@version"), 20), "sites": sites,
               "dropped_out_of_scope": dropped}  # fmt: skip
        return Parsed(raw, tool_version=f"zap-{raw['zap_version'] or 'unknown'}", warnings=warnings)

    def normalize(self, output: AdapterOutput, *, run_id: str, task_id: str) -> NormalizedBatch:
        b = NormalizedBatch()
        for s in output.raw.get("sites", []):
            u = canonicalize_url(s["origin"] + "/")
            aid = url_asset_id(u)  # same identity as the URL smoke asset for this origin
            b.assets.append(NormalizedAsset(
                aid, u.host, {"asset_class": "web", "scheme": u.scheme}, "SCANNED", None, asset_type="url",
                native_ids={"origin": u.origin, "hostname": u.host},
            ))  # fmt: skip
            for rule, value in (("web.high_alerts", s["high"]), ("web.medium_alerts", s["medium"])):
                oid = hashlib.sha256(f"{run_id}|{task_id}|{aid}|{rule}".encode()).hexdigest()[:24]
                b.observations.append(NormalizedObservation(f"o-{oid}", aid, rule, value))
        return b
