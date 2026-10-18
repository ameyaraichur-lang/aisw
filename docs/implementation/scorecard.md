# Scorecard (generated from actual results: do not edit by hand)

Based on commit `f3d6f44`. Regenerate with `tools/scorecard.py` (see its docstring). A pass here means an automated test passed in this repository's environment; it is not evidence about any customer environment.

## Backend (pytest)
| Area | Passed | Failed | Skipped |
|---|---|---|---|
| Contracts and schemas | 92 | 0 | 0 |
| Evaluation targets on the Maple Trust estate | 12 | 0 | 0 |
| Hardening: retention, export, retries, cancellation | 24 | 0 | 0 |
| Import adapters and reconciliation | 195 | 0 | 0 |
| LLM controls (stub model only) | 128 | 0 | 0 |
| Other | 481 | 0 | 0 |
| Pipeline, evidence and assurance | 139 | 0 | 0 |
| Risk, correlation, recommendations, assurance (M7) | 87 | 0 | 0 |
| Scope gate, signing, permits and renewal | 82 | 0 | 0 |
| Supply chain and secrets | 22 | 0 | 0 |
| Tenant isolation, RBAC, audit, idempotency | 62 | 0 | 0 |
| Tool gateway and SSRF/URL safety | 221 | 0 | 0 |
| **Total** | **1545** | **0** | **0** |

## Web
| Suite | Passed | Failed | Skipped |
|---|---|---|---|
| Unit (vitest) | 14 | 0 | 0 |
| End-to-end + axe WCAG 2.2 AA (Playwright, system Chrome) | 40 | 0 | 0 (flaky: 0) |

## Mutation checks (one-line breaks of a control; tests must fail)
| Milestone | Mutations | Caught at the end | Survived on first run (test strengthened) |
|---|---|---|---|
| M7 | 23 | 23 | 3 |
| M8 | 15 | 15 | 1 |

## Not measured / unverified
- Any real scanner, real Prowler/Greenbone/Wazuh/OpenSCAP/Nmap/ZAP output or live URL: the M9 harness is proven on loopback only and refuses every target until sign-off live-validation (ADR-045)
- Real-model quality on real evidence (only the synthetic labelled set is measured, docs/implementation/evaluation.md); licence review of weights
- Production sign-in against a real IdP, key custody/rotation in a real KMS, egress firewall rules loaded on a host (mock IdP and KMS emulator only)
- Docker/compose deployment; object-lock storage and an external audit witness (emulators only); worker soak across separate hosts (one machine only, docs/implementation/soak.md)
- Manual screen-reader pass (axe WCAG 2.2 AA and structural rules automated; checklist awaiting sign-off accessibility-screen-reader)
- OS packages in the base images (175 found by Syft) are not in the lockfile SBOM; release artefacts are unsigned; legal review of LGPL (psycopg)
