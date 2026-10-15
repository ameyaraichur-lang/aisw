# ADR-011: Tool gateway

**Status:** Accepted (M0, approved with development plan)

## Decision
In-process gateway module first: strict adapter allowlist, parameter validation, permit re-check per call, quotas, timeouts. Designed to be extractable into a service.

## Context
Appendix D.3: avoid scaffolding microservices before a working vertical slice.

## Consequences
Single process boundary initially; collectors in restricted zones will need the extracted form later.

## Alternatives considered
Separate gateway service from day one.
