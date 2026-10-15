# Implementation status (honesty matrix)

Legend: **Implemented** (tested here) · **Mocked** · **Unverified** (written, not run) · **Planned**

| Capability | State | Evidence / note |
|---|---|---|
| Repo skeleton, layout, ADR-001…012 | Implemented (M0) | `docs/adr/` |
| Fail-closed typed configuration | Implemented | `tests/security/test_config_fail_closed.py` |
| Health/readiness endpoints | Implemented | `tests/unit/test_health.py` |
| UI shell + outcome vocabulary (no data) | Implemented | `web/src/lib/status.test.ts`; build passes |
| Repo secret scanner | Implemented (stopgap) | `tests/security/test_secret_scan.py`; gitleaks planned |
| CI workflow | Unverified | `.github/workflows/ci.yml` written (now incl. schema-drift check), never run on a CI runner |
| Strict contracts (envelope 1.1, manifest, permit, decision, domain entities, assurance, report) + exported JSON Schemas | Implemented (M1) | `tests/contract/` (53 tests), `schemas/` drift gate |
| Tenant isolation via PostgreSQL RLS (forced, fail-closed when no tenant set) | Implemented (M1) | `tests/security/test_tenant_isolation_db.py`; real PG 16 via pgserver |
| RBAC roles/permissions, separation of duties, dev identity stub (dev/test only) | Implemented (M1) | `tests/security/test_api_authz.py` |
| Hash-chained append-only audit (DB triggers + verifier) | Implemented (M1) | `tests/security/test_audit_chain.py` incl. tamper/gap detection |
| Idempotent commands (same-txn key record, conflict on body change, race-safe) | Implemented (M1) | `tests/security/test_api_authz.py` incl. 6-thread race |
| Scope-manifest immutability + approval invariants in DB | Implemented (M1) | `tests/security/test_manifest_db.py` |
| Redaction (text/objects/log filter) | Implemented (M1) | `tests/security/test_redaction.py` |
| Alembic migration 0001 (reversible) | Implemented (M1) | `tests/integration/test_migrations.py` |
| Projects API (create/list/get, audit verify) | Implemented (M1) | first endpoints exercising the foundation |
| Execution-permit table | Implemented structurally only (M1) | no issuance logic or behavioural tests until Agent 0 (M2) |
| Domain data tables (assets, findings, coverage, evidence, runs) | Planned (M3) | contracts exist; persistence deferred per plan |
| OIDC / Keycloak authentication | Planned | dev stub only; refused unless env in dev/test and flag on |
| Manifest signing/key custody | Planned (M2) | contract fields exist, no signer yet |
| `net_guard` URL canonicalisation + SSRF/egress vetting (A/AAAA at preflight and dispatch, redirects, rebinding, IPv4-mapped/6to4/NAT64) | Implemented (M2) | `tests/security/test_net_guard.py` (98 cases, fake resolver; no real DNS/network touched) |
| Agent 0 scope gate (resolve, policy caps, wildcard/exclusion rules, approvals, hash of resolved manifest) | Implemented (M2) | `tests/security/test_agent0_gate.py` (43 cases) |
| Manifest signing (Ed25519, payload bound to tenant/project/id/version/hash) + key ring | Implemented (M2) dev/test custody only | `tests/unit/test_signing.py`; OpenBao Transit custody Planned (M8) |
| Manifest/permit lifecycle service (draft, preflight, approve, idempotent launch authorisation, revoke) | Implemented (M2) | persisted with RLS + audit; no HTTP routes yet (M3) |
| Tool gateway (allowlist, permit/manifest/signature re-check, scope, windows, params, quotas, audit) + zero-dispatch guarantee | Implemented (M2) | `tests/security/test_tool_gateway.py`; adapters are test doubles |
| Adapter registry refuses mutating adapters (no remediation path) | Implemented (M2) | `test_mutating_adapters_cannot_be_registered` |
| Real adapters (url_smoke, nmap, prowler, ...) | Planned (M3 fixture, M5/M6 others) | none exist yet; gateway verified only against fakes |
| Gateway quota state | Mocked | in-memory per process; durable counters arrive with the orchestrator (M3) |
| Egress firewall enforcement | Planned (M8 runbook) | application-layer checks only so far |
| Vertical slice, orchestrator, policy, coverage, report | Planned (M3) | |
| UI features, Playwright | Planned (M4) | |
| URL smoke adapter | Planned (M5) | |
| Scanner/CMDB import adapters | Planned (M6) | |
| Agents 2–8, assurance, LLM gateway | Planned (M7) | |
| SBOM / licence gate, runbooks, scorecard | Planned (M8) | |
| Live external tests (example.com, scanme.nmap.org, Juice Shop) | Not started (M9; needs explicit authorisation) | |
| Docker/compose, OPA, Postgres | Not available locally | see reconnaissance.md |
