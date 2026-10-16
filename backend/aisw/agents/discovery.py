"""Agent 1 - Discovery & Coverage: deterministic reconciliation. No model, no guessing.

Rules that matter:
* a missing or placeholder owner/criticality stays UNKNOWN; it is never inferred
* two records that might be the same asset are FLAGGED, never silently merged
* a scanner host is attached to a canonical asset only when the match is unambiguous; otherwise it
  stays a separate, low-confidence asset and the ambiguity is named
* stale records are named, and "fresh" is a measured fact, not a default
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal

PLACEHOLDERS = frozenset(
    {"", "unknown", "tbd", "n/a", "na", "none", "null", "-", "?", "unassigned"}
)


def norm_host(h: str | None) -> str | None:
    if not h:
        return None
    return h.strip().lower().rstrip(".") or None


def known_value(v: str | None) -> str | None:
    """A real value, or None for blanks and placeholders ("TBD", "unknown", ...)."""
    if v is None:
        return None
    s = v.strip()
    return None if s.lower() in PLACEHOLDERS else s


@dataclass(frozen=True)
class CmdbRow:
    asset_id: str
    hostname: str | None
    ip: str | None
    os_family: str | None
    owner: str | None
    criticality: str | None
    environment: str | None
    last_seen: datetime | None
    source: str


@dataclass(frozen=True)
class Gap:
    kind: str  # DUPLICATE_CANDIDATE | CONFLICTING_RECORDS | STALE_RECORD | OWNER_UNKNOWN | ...
    subject: str
    detail: str = ""

    def code(self) -> str:
        return f"{self.kind}:{self.subject}" + (f":{self.detail}" if self.detail else "")


@dataclass(frozen=True)
class ReconciledAsset:
    row: CmdbRow
    owner: str | None
    criticality: str | None
    fresh: bool
    flags: tuple[str, ...]


@dataclass
class CmdbReconciliation:
    assets: list[ReconciledAsset] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)


def reconcile_cmdb(
    rows: Sequence[CmdbRow], *, now: datetime, stale_after: timedelta
) -> CmdbReconciliation:
    out = CmdbReconciliation()
    by_id: dict[str, list[CmdbRow]] = defaultdict(list)
    for r in rows:
        by_id[r.asset_id].append(r)
    conflicting = {i for i, rs in by_id.items() if len({(x.hostname, x.ip) for x in rs}) > 1}
    for i in sorted(conflicting):  # same id, different identity: keep NONE, name it
        out.gaps.append(Gap("CONFLICTING_RECORDS", i))

    unique = [rs[0] for i, rs in by_id.items() if i not in conflicting]
    by_ip: dict[str, set[str]] = defaultdict(set)
    by_host: dict[str, set[str]] = defaultdict(set)
    for r in unique:
        if r.ip:
            by_ip[r.ip].add(r.asset_id)
        if (h := norm_host(r.hostname)) is not None:
            by_host[h].add(r.asset_id)
    dup_ids: set[str] = set()
    for key, ids in [*by_ip.items(), *by_host.items()]:
        if len(ids) > 1:
            dup_ids |= ids
            out.gaps.append(Gap("DUPLICATE_CANDIDATE", ",".join(sorted(ids)), key))

    for r in sorted(unique, key=lambda x: x.asset_id):
        flags: list[str] = []
        owner, crit = known_value(r.owner), known_value(r.criticality)
        if owner is None:
            flags.append("OWNER_UNKNOWN")
            out.gaps.append(Gap("OWNER_UNKNOWN", r.asset_id))
        if crit is None:
            flags.append("CRITICALITY_UNKNOWN")
        fresh = r.last_seen is not None and now - r.last_seen <= stale_after
        if not fresh:
            flags.append("STALE_RECORD" if r.last_seen else "NO_LAST_SEEN")
            out.gaps.append(
                Gap(
                    "STALE_RECORD",
                    r.asset_id,
                    r.last_seen.date().isoformat() if r.last_seen else "never",
                )
            )
        if r.asset_id in dup_ids:
            flags.append("DUPLICATE_CANDIDATE")
        out.assets.append(ReconciledAsset(r, owner, crit, fresh, tuple(flags)))
    return out


# ---- identity resolution for scanner hosts -----------------------------------------------------
@dataclass(frozen=True)
class KnownAsset:
    asset_id: str
    ip: str | None
    hostname: str | None


@dataclass(frozen=True)
class Resolution:
    status: Literal["MATCHED", "NEW", "AMBIGUOUS"]
    asset_id: str | None
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    reason: str


def resolve_identity(
    known: Sequence[KnownAsset], *, ip: str | None, hostname: str | None
) -> Resolution:
    host = norm_host(hostname)
    ids_ip = {k.asset_id for k in known if ip and k.ip == ip}
    ids_host = {k.asset_id for k in known if host and norm_host(k.hostname) == host}
    if host and "." not in host and not ids_host:  # short name: only if it identifies ONE asset
        ids_host = {
            k.asset_id for k in known if (kh := norm_host(k.hostname)) and kh.startswith(host + ".")
        }
    if ids_ip and ids_host:
        both = ids_ip & ids_host
        if len(both) == 1 and len(ids_ip) == 1 and len(ids_host) == 1:
            return Resolution("MATCHED", next(iter(both)), "HIGH", "ip and hostname agree")
        return Resolution(
            "AMBIGUOUS", None, "LOW", "ip and hostname identify different or multiple assets"
        )
    only = ids_ip or ids_host
    if len(only) == 1:
        return Resolution(
            "MATCHED",
            next(iter(only)),
            "MEDIUM",
            "matched on " + ("ip" if ids_ip else "hostname") + " only",
        )
    if len(only) > 1:
        return Resolution("AMBIGUOUS", None, "LOW", "identity matches several assets")
    return Resolution("NEW", None, "LOW", "no known asset matches")
