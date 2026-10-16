"""Server-sent-events stream over the persisted run event log (ADR-007).

The log is the source of truth; the stream is only a delivery channel. Every message carries the
per-run ``seq`` as its SSE id, so a client that reconnects with ``Last-Event-ID`` (or ``cursor``)
resumes exactly after what it already processed: no gaps, no repeats. The stream ends once the run
has reached a state where no further work events are expected AND the log has been drained.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator

from sqlalchemy import Engine, text

from aisw.core.db import tenant_connection

STREAM_END_STATES = frozenset(
    {"CLOSED", "FAILED", "CANCELLED", "EXPIRED", "PARTIAL", "REPORT_READY"}
)


def format_sse(*, event_id: int | None, event: str, data: object) -> str:
    lines = []
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.append(f"event: {event}")
    lines.append("data: " + json.dumps(data, separators=(",", ":"), default=str))
    return "\n".join(lines) + "\n\n"


def stream_events(
    engine: Engine,
    *,
    tenant_id: str,
    run_id: str,
    cursor: int,
    poll_seconds: float = 0.5,
    heartbeat_seconds: float = 10.0,
    max_seconds: float = 300.0,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> Iterator[str]:
    started = last_write = monotonic()
    while True:
        with tenant_connection(engine, tenant_id) as conn:
            rows = conn.execute(
                text(
                    "SELECT seq, event_id::text, event_type, payload, occurred_at FROM run_events "
                    "WHERE run_id=:r AND seq > :c ORDER BY seq LIMIT 200"
                ),
                {"r": run_id, "c": cursor},
            ).all()
            state = conn.execute(
                text("SELECT state FROM assessment_runs WHERE run_id=:r"), {"r": run_id}
            ).scalar()
        for seq, event_id, etype, payload, occurred in rows:
            yield format_sse(
                event_id=seq, event=etype,
                data={"seq": seq, "event_id": event_id, "type": etype, "payload": payload,
                      "occurred_at": occurred.isoformat()},
            )  # fmt: skip
            cursor = seq
            last_write = monotonic()
        if rows:
            continue  # drain the backlog before deciding anything
        if state is None or state in STREAM_END_STATES:
            yield format_sse(event_id=None, event="end", data={"state": state, "cursor": cursor})
            return
        now = monotonic()
        if now - started > max_seconds:
            yield format_sse(event_id=None, event="reconnect", data={"cursor": cursor})
            return
        if now - last_write > heartbeat_seconds:
            yield ": heartbeat\n\n"
            last_write = now
        sleep(poll_seconds)
