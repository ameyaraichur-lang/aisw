# Scorecard (generated from actual results: do not edit by hand)

Based on commit `e459d80`. Regenerate with `tools/scorecard.py` (see its docstring). A pass here means an automated test passed in this repository's environment; it is not evidence about any customer environment.

## Backend (pytest)
| Area | Passed | Failed | Skipped |
|---|---|---|---|
| Contracts and schemas | 92 | 0 | 0 |
| Evaluation targets on the Maple Trust estate | 12 | 0 | 0 |
| Hardening: retention, export, retries, cancellation | 24 | 0 | 0 |
| Import adapters and reconciliation | 199 | 0 | 0 |
| LLM controls (stub model only) | 128 | 0 | 0 |
| Other | 481 | 0 | 0 |
| Pipeline, evidence and assurance | 140 | 0 | 0 |
| Risk, correlation, recommendations, assurance (M7) | 87 | 0 | 0 |
| Scope gate, signing, permits and renewal | 82 | 0 | 0 |
| Supply chain and secrets | 22 | 0 | 0 |
| Tenant isolation, RBAC, audit, idempotency | 62 | 0 | 0 |
| Tool gateway and SSRF/URL safety | 224 | 0 | 0 |
| **Total** | **1553** | **0** | **0** |

## Web
| Suite | Passed | Failed | Skipped |
|---|---|---|---|
| Unit (vitest) | 22 | 0 | 0 |
| End-to-end + axe WCAG 2.2 AA (Playwright, system Chrome) | 40 | 0 | 0 (flaky: 2) |

## Mutation checks (one-line breaks of a control; tests must fail)
| Milestone | Mutations | Caught at the end | Survived on first run (test strengthened) |
|---|---|---|---|
| M7 | 23 | 23 | 3 |
| M8 | 15 | 15 | 1 |

## Not measured / unverified
- Real output of every importer except Nmap and Trivy (one real report each on 2026-10-18, docs/implementation/live-validation/2026-10-18-live-runs.md); the M9 plan's targets (scanme.nmap.org, Juice Shop) through the harness, which refuses them until sign-off live-validation (ADR-045)
- A real-CA certificate chain over a direct connection: the only public URL probed (example.com) went through a TLS-inspecting proxy, so its certificate controls were not assessed
- Real-model quality on real evidence: the 34 Astra calls on the 2026-10-18 live runs were schema-validated, not scored against an answer key (only the synthetic labelled set is scored, docs/implementation/evaluation.md); licence review of weights
- Production sign-in against a real IdP, key custody/rotation in a real KMS, egress firewall rules loaded on a host (mock IdP and KMS emulator only)
- Docker/compose deployment; object-lock storage and an external audit witness (emulators only); worker soak across separate hosts (one machine only, docs/implementation/soak.md)
- Manual screen-reader pass (axe WCAG 2.2 AA and structural rules automated; checklist awaiting sign-off accessibility-screen-reader)
- OS packages in the base images (175 found by Syft) are not in the lockfile SBOM; release artefacts are unsigned; legal review of LGPL (psycopg)
