# Scorecard (generated from actual results: do not edit by hand)

Based on commit `9fa075c` **plus uncommitted changes**. Regenerate with `tools/scorecard.py` (see its docstring). A pass here means an automated test passed in this repository's environment; it is not evidence about any customer environment.

## Backend (pytest)
| Area | Passed | Failed | Skipped |
|---|---|---|---|
| Contracts and schemas | 82 | 0 | 0 |
| Hardening: retention, export, retries, cancellation | 17 | 0 | 0 |
| Import adapters and reconciliation | 192 | 0 | 0 |
| LLM controls (stub model only) | 49 | 0 | 0 |
| Other | 2 | 0 | 0 |
| Pipeline, evidence and assurance | 98 | 0 | 0 |
| Risk, correlation, recommendations, assurance (M7) | 85 | 0 | 0 |
| Scope gate, signing, permits and renewal | 82 | 0 | 0 |
| Supply chain and secrets | 22 | 0 | 0 |
| Tenant isolation, RBAC, audit, idempotency | 59 | 0 | 0 |
| Tool gateway and SSRF/URL safety | 211 | 0 | 0 |
| **Total** | **899** | **0** | **0** |

## Web
| Suite | Passed | Failed | Skipped |
|---|---|---|---|
| Unit (vitest) | 14 | 0 | 0 |
| End-to-end + axe WCAG 2.2 AA (Playwright, system Chrome) | 20 | 0 | 0 (flaky: 0) |

## Mutation checks (one-line breaks of a control; tests must fail)
| Milestone | Mutations | Caught at the end | Survived on first run (test strengthened) |
|---|---|---|---|
| M7 | 23 | 23 | 3 |
| M8 | 15 | 15 | 1 |

## Not measured / unverified
- Any real scanner, real Prowler/Greenbone/Wazuh/OpenSCAP/Nmap/ZAP output or live URL (M9 needs your explicit authorisation)
- Any real language model: quality, latency, licence review of weights
- Production sign-in (OIDC), key custody/rotation (OpenBao), egress firewall enforcement
- Docker/compose deployment, OPA, object-lock evidence storage, multi-node worker soak
- CI workflow has never run on a CI runner
- Screen-reader/manual accessibility testing (automated axe only)
- Syft/ScanCode scan (a lockfile-based SBOM is used); legal review of LGPL (psycopg)
