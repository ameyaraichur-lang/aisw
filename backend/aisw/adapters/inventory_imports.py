"""Source-of-truth inventory exports: NetBox and ServiceNow, reconciled exactly like a CMDB export.

Each record is mapped onto the CMDB columns and goes through the same Agent 1 reconciliation, so
owner, criticality and environment are taken only from fields the export actually fills in (never
inferred from a tenant, site or group), and retired or planned records are skipped and counted.
Real-tool compatibility per version is UNVERIFIED (see docs/implementation/status.md).
"""

from __future__ import annotations

import re
from typing import Any

from aisw.adapters.cmdb_import import CmdbImportAdapter, CmdbParams
from aisw.adapters.imports_base import ImportParseError, cap, clean, parse_json
from aisw.contracts.enums import ProfileClass

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
LINUX = (
    "linux",
    "ubuntu",
    "debian",
    "rhel",
    "red hat",
    "centos",
    "rocky",
    "alma",
    "suse",
    "amazon",
)


def os_family(text: str) -> str | None:
    t = text.lower()
    if "windows" in t:
        return "windows"
    if any(k in t for k in LINUX):
        return "linux"
    return None


def _asset_id(name: str, fallback: str) -> str:
    return name if _ID.match(name) else fallback


def _ip(addr: Any) -> str:
    return clean(addr, 60).split("/", 1)[0]


def _field(custom: dict[str, Any], key: str) -> str | None:
    """A NetBox custom field: text, a selection {value, label} or an object {name, display}."""
    v = custom.get(key)
    if isinstance(v, dict):
        v = v.get("value") or v.get("name") or v.get("display")
    return (clean(v, 120) or None) if isinstance(v, str | int) else None


# ================================================================ NetBox
NETBOX_ACTIVE = {"active", "staged"}


class NetboxImportAdapter(CmdbImportAdapter):
    adapter_id = "netbox_import"
    tool = "aisw-netbox-import"
    profiles = {"NETBOX_EXPORT_IMPORT": ProfileClass.READ_ONLY}
    import_kinds = frozenset({"netbox_json"})
    formats = (
        "NetBox REST list JSON {count, next, results: [...]} from /api/dcim/devices/ or /api/virtualization/virtual-machines/ (custom fields owner, criticality, environment)",
    )  # noqa: E501
    param_model = CmdbParams

    def _records(self, text: str) -> tuple[str, list[dict[str, Any]], list[str]]:
        data = parse_json(text)
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise ImportParseError("UNSUPPORTED_FORMAT")
        warnings: list[str] = []
        results = cap([r for r in data["results"] if isinstance(r, dict)])
        if data.get("next"):  # a paginated page is not the inventory
            warnings.append(f"EXPORT_TRUNCATED:{len(results)} of {clean(data.get('count'), 10)}")
        rows: list[dict[str, Any]] = []
        skipped = 0
        for r in results:
            status = r.get("status")
            value = clean(status.get("value") if isinstance(status, dict) else status, 20).lower()
            if value and value not in NETBOX_ACTIVE:
                skipped += 1
                continue
            cf = r.get("custom_fields") or {}
            kind = "vm" if "cluster" in r or "vcpus" in r else "device"
            name = clean(r.get("name"), 64)
            platform = r.get("platform") or {}
            ip = (r.get("primary_ip4") or r.get("primary_ip") or {}).get("address")
            rows.append({
                "asset_id": _asset_id(name, f"netbox-{kind}-{clean(r.get('id'), 12)}"),
                "hostname": name, "ip": _ip(ip),
                "os_family": os_family(f"{clean(platform.get('slug'), 60)} {clean(platform.get('name'), 60)}"),
                "owner": _field(cf, "owner") or _field(cf, "owner_team"),
                "criticality": _field(cf, "criticality"), "environment": _field(cf, "environment"),
                "last_seen": r.get("last_updated"),
                "source": f"netbox-{kind}",
            })  # fmt: skip
        if skipped:
            warnings.append(f"NOT_ACTIVE_SKIPPED:{skipped}")
        return "netbox", rows, warnings


# ================================================================ ServiceNow
SN_RETIRED = {"7", "retired", "8", "missing", "100", "absent", "6", "in stock"}


def _sn(value: Any) -> str:
    """A Table API field, whether exported raw, with display values, or with both."""
    if isinstance(value, dict):
        return clean(value.get("display_value") or value.get("value"), 120)
    return clean(value, 120)


class ServiceNowImportAdapter(CmdbImportAdapter):
    adapter_id = "servicenow_import"
    tool = "aisw-servicenow-import"
    profiles = {"SERVICENOW_CMDB_IMPORT": ProfileClass.READ_ONLY}
    import_kinds = frozenset({"servicenow_json"})
    formats = (
        "ServiceNow Table API JSON {result: [...]} for cmdb_ci_server or a child class (name, ip_address, os, owned_by, busines_criticality, environment or used_for, install_status, last_discovered)",
    )  # noqa: E501
    param_model = CmdbParams

    def _records(self, text: str) -> tuple[str, list[dict[str, Any]], list[str]]:
        data = parse_json(text)
        if not isinstance(data, dict) or not isinstance(data.get("result"), list):
            raise ImportParseError("UNSUPPORTED_FORMAT")
        rows: list[dict[str, Any]] = []
        skipped = 0
        for r in cap([r for r in data["result"] if isinstance(r, dict)]):
            if _sn(r.get("install_status")).lower() in SN_RETIRED:
                skipped += 1
                continue
            name = _sn(r.get("name"))[:64]
            rows.append({
                "asset_id": _asset_id(name, f"sn-{_sn(r.get('sys_id'))[:32]}"),
                "hostname": _sn(r.get("fqdn")) or name, "ip": _sn(r.get("ip_address")),
                "os_family": os_family(_sn(r.get("os"))),
                "owner": _sn(r.get("owned_by")) or None,
                "criticality": _sn(r.get("busines_criticality")) or None,  # sic: the ServiceNow field name
                "environment": _sn(r.get("environment")) or _sn(r.get("used_for")) or None,
                "last_seen": _sn(r.get("last_discovered")) or _sn(r.get("sys_updated_on")),
                "source": f"servicenow-{_sn(r.get('sys_class_name')) or 'cmdb_ci'}",
            })  # fmt: skip
        return "servicenow", rows, [f"NOT_ACTIVE_SKIPPED:{skipped}"] if skipped else []
