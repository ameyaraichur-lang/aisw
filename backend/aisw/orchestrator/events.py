"""Persisted, replayable run events (ADR-007). Notifications only: state lives in the tables.

Per-run monotonically increasing ``seq`` doubles as the replay cursor. Payloads are redacted and
carry no raw evidence. Appends run inside the caller's transaction, so an event exists iff the
state change it describes was committed.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import Connection, text

from aisw.core.redaction import redact_obj

EVENT_TYPES = frozenset(
    {
        "assessment.accepted", "preflight.started", "preflight.completed", "phase.changed",
        "task.queued", "task.started", "task.progress", "evidence.batch.stored",
        "task.completed", "task.partial", "task.failed", "approval.required",
        "approval.completed", "report.ready", "report.partial", "assessment.cancelled",
        "assessment.closed",
    }
)  # fmt: skip


def append_event(
    conn: Connection,
    *,
    tenant_id: str,
    run_id: str,
    event_type: str,
    payload: dict[str, Any],
    now: datetime,
) -> int:
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown event type {event_type!r}")
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"), {"k": f"run-events:{run_id}"}
    )
    seq = conn.execute(
        text("SELECT COALESCE(MAX(seq), 0) + 1 FROM run_events WHERE run_id=:r"), {"r": run_id}
    ).scalar_one()
    conn.execute(
        text(
            "INSERT INTO run_events (tenant_id, run_id, seq, event_type, payload, occurred_at) "
            "VALUES (:t, :r, :s, :e, CAST(:p AS jsonb), :o)"
        ),
        {
            "t": tenant_id, "r": run_id, "s": seq, "e": event_type,
            "p": json.dumps(redact_obj(payload), default=str), "o": now,
        },
    )  # fmt: skip
    return int(seq)
