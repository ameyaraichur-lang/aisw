# ADR-002: Orchestrator

**Status:** Accepted (M0, approved with development plan)

## Decision
PostgreSQL-backed durable worker: persisted state before/after dispatch, outbox, SELECT ... FOR UPDATE SKIP LOCKED, bounded retries, cooperative cancel.

## Context
Blueprint 5/J.2 allows Temporal OSS or a DB-backed worker; Temporal adds operational footprint not justified for the PoC.

## Consequences
Orchestration sits behind an interface so Temporal can replace it later. We own retry/idempotency correctness and must test it (crash-resume tests in M3/M8).

## Alternatives considered
Temporal OSS.
