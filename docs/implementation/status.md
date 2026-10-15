# Implementation status (honesty matrix)

Legend: **Implemented** (tested here) · **Mocked** · **Unverified** (written, not run) · **Planned**

| Capability | State | Evidence / note |
|---|---|---|
| Repo skeleton, layout, ADR-001…012 | Implemented (M0) | `docs/adr/` |
| Fail-closed typed configuration | Implemented | `tests/security/test_config_fail_closed.py` |
| Health/readiness endpoints | Implemented | `tests/unit/test_health.py` |
| UI shell + outcome vocabulary (no data) | Implemented | `web/src/lib/status.test.ts`; build passes |
| Repo secret scanner | Implemented (stopgap) | `tests/security/test_secret_scan.py`; gitleaks planned |
| CI workflow | Unverified | `.github/workflows/ci.yml` written, never run on a CI runner |
| Contracts, RLS, RBAC, audit chain, idempotency | Planned (M1) | |
| Agent 0, tool gateway, net_guard | Planned (M2) | |
| Vertical slice, orchestrator, policy, coverage, report | Planned (M3) | |
| UI features, Playwright | Planned (M4) | |
| URL smoke adapter | Planned (M5) | |
| Scanner/CMDB import adapters | Planned (M6) | |
| Agents 2–8, assurance, LLM gateway | Planned (M7) | |
| SBOM / licence gate, runbooks, scorecard | Planned (M8) | |
| Live external tests (example.com, scanme.nmap.org, Juice Shop) | Not started (M9; needs explicit authorisation) | |
| Docker/compose, OPA, Postgres | Not available locally | see reconnaissance.md |
