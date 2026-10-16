# ADR-006: Authentication

**Status:** Accepted (M0, approved with development plan); amended by [ADR-026](ADR-026-oidc-sign-in-through-the-bff.md): generic OIDC, not Keycloak-specific

## Decision
Keycloak OIDC in deployments. Dev/test only: a local identity stub with seeded users/roles, gated by AISW_ENV in {dev,test}; config validation rejects it when env=prod.

## Context
No customer SSO available during development; RBAC and tenant tests must still be real.

## Consequences
Server derives actor/tenant from the validated token or stub context only; UI hiding is never authorization. Stub must never ship enabled.

## Alternatives considered
Require Keycloak locally (needs Docker, unavailable).
