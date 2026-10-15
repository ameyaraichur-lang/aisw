# ADR-007: Run events

**Status:** Accepted (M0, approved with development plan)

## Decision
Persisted run_events table with per-run monotonic cursor, event_id for dedupe, redacted payloads; SSE with polling fallback; status snapshot endpoint for reconnect.

## Context
Appendix H: events are notifications, not source of truth; reconnect must recover from snapshot.

## Consequences
Event schema is the union of the addendum and Appendix H.1 lists.

## Alternatives considered
WebSocket-only live stream.
