# ADR-014: Assessment pipeline design (M3)

**Status:** Accepted (M3)

## Decision
1. **Queue = PostgreSQL table (`run_tasks`) + lease.** Workers claim with `FOR UPDATE SKIP LOCKED`; a lease (default 5 min) lets a dead worker's task be re-claimed; attempts are bounded (3). Adapter exceptions retry with exponential backoff + jitter; gateway denials never retry (except `AUDIT_UNAVAILABLE`).
2. **Fencing token = (worker id, attempt number).** Every write a worker makes for a task first re-checks it still owns the task (`status=RUNNING AND locked_by AND attempts`). A slow worker whose lease expired and whose task was re-claimed writes nothing. Found by a mutation check: without it a late worker double-wrote events.
3. **Dedicated `aisw_worker` role** (inherits `aisw_app` grants). RLS policy `worker_discover` lets it see only OPEN tasks/runs across tenants so it can find work; all other access happens inside a tenant context. The API role never gets this policy.
4. **Phase commit model.** Claim (state persisted before dispatch) -> gateway dispatch (outside any DB transaction) -> ONE transaction for evidence metadata, assets, observations, task status and events. Phases (policy, assurance, report) are each one transaction guarded by `state=:old`.
5. **Observation outcomes are evaluated at ingest** against the run's pinned policy pack; controls, findings and coverage are aggregated in the policy phase. Missing observations become NOT_ASSESSED, never PASS. Roll-up precedence: FAIL > ERROR > UNKNOWN > NOT_ASSESSED > PASS.
6. **Evidence is redacted before it is hashed or stored**; the stored artifact is the redacted canonical JSON. Evidence files are content-addressed and write-once; reads re-hash.
7. **A minimal deterministic assurance gate ships in M3** (not M7) so that N7 holds from the first slice: only ACCEPT findings enter the report; REJECT is preserved (auditor-visible); NEEDS_REVIEW (stale evidence, store outage) is disclosed in the report as pending, never silently dropped.
8. **Events** are the union of the addendum and Appendix H.1 lists plus `phase.changed`; per-run `seq` is the replay cursor; append-only at the database level.
9. **Fixture adapter exists only outside prod** (`AISW_ENV != prod`) and is never evidence of a real integration.

## Known limitations (tracked in status.md)
- Execution permits last 15 minutes and are not renewed mid-run; long runs need permit renewal (M8).
- No SSE yet (cursor polling only); the UI slice (M4) adds SSE on top of the same cursor.
- Quotas in the gateway are in-memory per process.
- Coverage ledger is per target segment from an inventory snapshot; richer discovery/reconciliation (Agent 1) is M6.
- The worker process entry point (`python -m aisw.orchestrator`) has not been run against a live deployment.
