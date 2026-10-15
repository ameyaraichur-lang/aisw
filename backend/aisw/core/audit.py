"""Hash-chained, append-only audit trail. Linkage is enforced by DB triggers as well."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import Connection, text

from aisw.contracts.audit import GENESIS_HASH, AuditEventRecord
from aisw.contracts.base import canonical_hash

Result = Literal["SUCCESS", "DENIED", "FAILURE"]


def _hash_fields(ev: dict[str, Any]) -> str:
    keys = (
        "event_id", "tenant_id", "seq", "actor", "action", "resource", "before_hash",
        "after_hash", "correlation_id", "result", "occurred_at", "prev_hash",
    )  # fmt: skip
    return canonical_hash({k: ev[k] for k in keys})


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).isoformat(timespec="microseconds")


def append_audit(
    conn: Connection,
    *,
    tenant_id: str,
    actor: str,
    action: str,
    resource: str,
    result: Result,
    correlation_id: str,
    before_hash: str | None = None,
    after_hash: str | None = None,
    now: datetime | None = None,
) -> AuditEventRecord:
    """Append within the caller's tenant-scoped transaction (so audit commits with the action)."""
    conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:t, 0))"), {"t": tenant_id})
    last = conn.execute(
        text(
            "SELECT seq, event_hash FROM audit_events WHERE tenant_id=:t ORDER BY seq DESC LIMIT 1"
        ),
        {"t": tenant_id},
    ).first()
    seq, prev = (last[0] + 1, last[1]) if last else (1, GENESIS_HASH)
    occurred = (now or datetime.now(UTC)).astimezone(UTC)
    ev: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "seq": seq,
        "actor": actor,
        "action": action,
        "resource": resource,
        "before_hash": before_hash,
        "after_hash": after_hash,
        "correlation_id": correlation_id,
        "result": result,
        "occurred_at": _iso(occurred),
        "prev_hash": prev,
    }
    ev["event_hash"] = _hash_fields(ev)
    conn.execute(
        text(
            "INSERT INTO audit_events (event_id, tenant_id, seq, actor, action, resource, "
            "before_hash, after_hash, correlation_id, result, occurred_at, prev_hash, event_hash) "
            "VALUES (:event_id, :tenant_id, :seq, :actor, :action, :resource, :before_hash, "
            ":after_hash, :correlation_id, :result, :occurred_dt, :prev_hash, :event_hash)"
        ),
        {**ev, "occurred_dt": occurred},
    )
    return AuditEventRecord.model_validate({**ev, "occurred_at": occurred})


@dataclass(frozen=True)
class ChainReport:
    ok: bool
    checked: int
    broken_at_seq: int | None = None
    reason: str | None = None


def verify_chain(conn: Connection, tenant_id: str) -> ChainReport:
    rows = conn.execute(
        text(
            "SELECT event_id::text AS event_id, tenant_id, seq, actor, action, resource, "
            "before_hash, after_hash, correlation_id, result, occurred_at, prev_hash, event_hash "
            "FROM audit_events WHERE tenant_id=:t ORDER BY seq"
        ),
        {"t": tenant_id},
    ).mappings()
    prev, expected_seq, n = GENESIS_HASH, 1, 0
    for r in rows:
        ev = dict(r)
        ev["occurred_at"] = _iso(ev["occurred_at"])
        n += 1
        if ev["seq"] != expected_seq:
            return ChainReport(False, n, ev["seq"], "sequence gap")
        if ev["prev_hash"] != prev:
            return ChainReport(False, n, ev["seq"], "prev_hash mismatch")
        if _hash_fields(ev) != ev["event_hash"]:
            return ChainReport(False, n, ev["seq"], "event_hash mismatch (content altered)")
        prev, expected_seq = ev["event_hash"], expected_seq + 1
    return ChainReport(True, n)
