"""CMDB export import (CSV or JSON) with Agent 1 reconciliation.

Authoritative for owner/criticality/environment, but only for what the export actually says:
blank or placeholder values stay UNKNOWN, possible duplicates are flagged (never merged), and
records not seen recently are named as stale.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import Field

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
from aisw.agents.discovery import CmdbRow, reconcile_cmdb
from aisw.contracts.enums import ProfileClass
from aisw.gateway.registry import AdapterJob, AdapterOutput

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
CSV_COLUMNS = (
    "asset_id",
    "hostname",
    "ip",
    "os_family",
    "owner",
    "criticality",
    "environment",
    "last_seen",
    "source",
)
BLOCKING_GAPS = {"DUPLICATE_CANDIDATE", "CONFLICTING_RECORDS"}


class CmdbParams(ImportParams):
    stale_days: int = Field(default=90, ge=1, le=3650)


def _when(value: Any) -> datetime | None:
    s = clean(value, 40)
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


class CmdbImportAdapter(ImportAdapter):
    adapter_id = "cmdb_import"
    tool = "aisw-cmdb-import"
    domains = frozenset({"inventory"})
    profiles = {"CMDB_IMPORT": ProfileClass.READ_ONLY}
    target_kinds = frozenset({"asset_group"})
    import_kinds = frozenset({"cmdb_csv", "cmdb_json"})
    formats: tuple[str, ...] = (
        "CSV with header asset_id,hostname,ip,os_family,owner,criticality,environment,last_seen,source",
        "JSON list or {assets: [...]}",
    )  # noqa: E501
    param_model = CmdbParams

    def _records(self, text: str) -> tuple[str, list[dict[str, Any]], list[str]]:
        """(format, records in the CSV column shape, extra warnings)."""
        stripped = text.lstrip("﻿").lstrip()
        if stripped.startswith(("[", "{")):
            data = parse_json(stripped)
            items = data.get("assets") if isinstance(data, dict) else data
            if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
                raise ImportParseError("UNSUPPORTED_FORMAT")
            return "json", cap(items), []
        try:
            csv.field_size_limit(100_000)
            reader = csv.DictReader(io.StringIO(stripped))
            if not reader.fieldnames or "asset_id" not in reader.fieldnames:
                raise ImportParseError("UNSUPPORTED_FORMAT")
            return "csv", cap([dict(r) for r in reader]), []
        except csv.Error as exc:
            raise ImportParseError("MALFORMED_CSV") from exc

    def parse(self, text: str, job: AdapterJob, params: CmdbParams) -> Parsed:
        fmt, items, warnings = self._records(text)
        rows: list[CmdbRow] = []
        for n, it in enumerate(items, 1):
            aid = clean(it.get("asset_id"), 64)
            if not _ID.match(aid):
                warnings.append(f"INVALID_RECORD:{n}:bad asset_id")
                continue
            ip = clean(it.get("ip"), 45) or None
            if ip:
                try:
                    ip = str(ipaddress.ip_address(ip))
                except ValueError:
                    warnings.append(f"INVALID_RECORD:{n}:bad ip")
                    continue
            rows.append(CmdbRow(aid, clean(it.get("hostname"), 253) or None, ip,
                                (clean(it.get("os_family"), 40).lower() or None),
                                clean(it.get("owner"), 120) or None,
                                clean(it.get("criticality"), 40) or None,
                                clean(it.get("environment"), 40) or None, _when(it.get("last_seen")),
                                clean(it.get("source"), 60) or "cmdb"))  # fmt: skip
        rec = reconcile_cmdb(rows, now=self._clock(), stale_after=timedelta(days=params.stale_days))
        warnings += [g.code() for g in rec.gaps]
        raw = {
            "format": fmt, "record_count": len(items), "stale_after_days": params.stale_days,
            "records": [
                {"asset_id": a.row.asset_id, "hostname": a.row.hostname, "ip": a.row.ip,
                 "os_family": a.row.os_family, "owner": a.owner, "criticality": a.criticality,
                 "environment": a.row.environment, "source": a.row.source, "fresh": a.fresh,
                 "last_seen": a.row.last_seen.isoformat() if a.row.last_seen else None,
                 "flags": list(a.flags)}
                for a in rec.assets
            ],
            "gaps": [{"kind": g.kind, "subject": g.subject, "detail": g.detail} for g in rec.gaps],
        }  # fmt: skip
        partial = any(g.kind in BLOCKING_GAPS for g in rec.gaps) or any(
            w.startswith(("INVALID_RECORD", "EXPORT_TRUNCATED")) for w in warnings
        )
        return Parsed(
            raw,
            tool_version=f"cmdb-{fmt}-export",
            status="PARTIAL" if partial else "SUCCEEDED",
            warnings=warnings,
        )

    def normalize(self, output: AdapterOutput, *, run_id: str, task_id: str) -> NormalizedBatch:
        batch = NormalizedBatch()
        batch.warnings = list(
            output.warnings
        )  # named gaps flow to the coverage ledger via the worker
        for r in output.raw.get("records", []):
            aid = r["asset_id"]
            src = f"cmdb:{r['source']}"
            batch.assets.append(NormalizedAsset(
                aid, r["hostname"] or aid, {"asset_class": "host", "os_family": r["os_family"] or "unknown"},
                "SCANNED", None, asset_type="host",
                native_ids={k: v for k, v in {"cmdb_id": aid, "hostname": r["hostname"], "ip": r["ip"]}.items() if v},
                owner=r["owner"], owner_source=src if r["owner"] else None,
                criticality=r["criticality"], criticality_source=src if r["criticality"] else None,
                environment=r["environment"],
            ))  # fmt: skip
            for rule, value in (("cmdb.owner_known", r["owner"] is not None),
                                ("cmdb.criticality_known", r["criticality"] is not None),
                                ("cmdb.record_fresh", bool(r["fresh"]))):  # fmt: skip
                oid = hashlib.sha256(f"{run_id}|{task_id}|{aid}|{rule}".encode()).hexdigest()[:24]
                batch.observations.append(NormalizedObservation(f"o-{oid}", aid, rule, value))
        return batch
