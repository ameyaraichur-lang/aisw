# ADR-012: URL and SSRF safety

**Status:** Accepted (M0, approved with development plan)

## Decision
Shared net_guard library: scheme/port/userinfo/IDN canonicalisation, A/AAAA resolution at preflight and dispatch, IPv4-mapped IPv6 handling, block loopback/private/link-local/multicast/unspecified/reserved/metadata ranges, redirect re-validation, connect to pinned resolved IP. Internal ranges only via an explicit, human-approved, hash-bound manifest field. Egress firewall documented for deployments.

## Context
Appendix J.6. Conflict G9: a localhost test target conflicts with the loopback block unless explicitly authorised.

## Consequences
Application checks are not the only control; deployment must also enforce egress rules (runbook in M8).

## Alternatives considered
Per-adapter ad hoc checks.
