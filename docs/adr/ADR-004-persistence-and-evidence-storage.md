# ADR-004: Persistence and evidence storage

**Status:** Accepted (M0, approved with development plan)

## Decision
PostgreSQL with Row-Level Security per tenant; evidence stored content-addressed (sha256) on local filesystem; SeaweedFS optional later.

## Context
Tenant isolation must hold even if application code has a bug; evidence integrity needs hashes.

## Consequences
RLS must be tested against a real Postgres (embedded in tests), not SQLite. psql/docker are not installed on the dev machine, so test infrastructure is added in M1.

## Alternatives considered
App-layer-only tenant filtering; SQLite.
