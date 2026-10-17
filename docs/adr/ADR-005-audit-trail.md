# ADR-005: Audit trail

**Status:** Accepted (M0, approved with development plan)

## Decision
Append-only audit table with hash chain (prev_hash), no UPDATE/DELETE grants to the app role.

## Context
Blueprint 4.1/8 requires tamper-evident audit with no secrets/raw tokens.

## Consequences
Chain verification job and tests in M1. Anchoring the chain head externally is a later hardening option. **Update (ADR-042):** signed anchors recorded with an external witness; production witness pending sign-off.

## Alternatives considered
Plain log table.
