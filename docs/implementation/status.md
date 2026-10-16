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
| Migration 0002: inventory, runs, task queue, events, evidence, assets, observations, controls, findings, assurance, coverage, reports (forced RLS, worker role) | Implemented (M3) | `tests/integration/test_migrations.py` (independently reversible) |
| Durable PostgreSQL worker (lease, bounded attempts, backoff+jitter, fencing, crash resume) | Implemented (M3) | `tests/security/test_pipeline_security.py` (crash, repeated crash, late worker, retries) |
| Run state machine + persisted replayable events (cursor) | Implemented (M3) | polling API only; SSE Planned (M4) |
| Evidence ingest: validate, redact, canonicalise, hash, write-once content-addressed store | Implemented (M3) | `tests/unit/test_evidence.py`; secret never reaches disk/DB/report |
| Deterministic policy evaluation (JSON packs, pinned + hashed) | Implemented (M3) interim | Python evaluator behind `PolicyEvaluator`; OPA not installed (ADR-003) |
| Findings, controls, coverage ledger (per segment) | Implemented (M3) | partial/zero/unreachable/unsupported/absent/unexpected all visible |
| Minimal independent assurance (hash, freshness, scope, control IDs) | Implemented (M3 subset) | tamper/missing/stale/outage tests; full Agent 7 Planned (M7) |
| Report JSON + escaped HTML, partial banner, approval bound to report hash, SoD | Implemented (M3) | counts reconcile to DB in tests |
| API: scope manifests, inventory, assessments, events, cancel, coverage, findings, reports | Implemented (M3) | `tests/integration/test_vertical_slice.py` |
| Fixture adapter (synthetic scanner replay; non-prod only) | Implemented (M3), **Mocked data** | proves the pipeline, not any real tool |
| Worker process entry point (`python -m aisw.orchestrator`) | Unverified | written, not run live |
| Permit renewal for runs longer than 15 min | Planned (M8) | permits are not renewed mid-run |
| Console API read models: me/auth-mode, connectors, policy packs, inventory/manifest/run lists, tasks, controls, finding detail (evidence + matched observation + assurance), tenant-wide findings, overview with denominators, audit events | Implemented (M4) | `tests/integration/test_console_api.py` |
| SSE stream with cursor resume, heartbeat, rotation and clean end | Implemented (M4) | `tests/integration/test_console_api.py`; browser side in e2e |
| Web shell: role-aware nav, skip link, landmarks, focus management, route guards | Implemented (M4) | `e2e/permissions.spec.ts`, `e2e/a11y.spec.ts` |
| Command Center (coverage with denominator + as-of, authoritative critical/high, active/partial runs, connector health) | Implemented (M4) | exceptions card omitted (no exception feature yet) |
| New Assessment wizard (6 steps, server preflight, explicit review, idempotent launch) | Implemented (M4) | `e2e/happy-path.spec.ts`, `e2e/blocked-and-partial.spec.ts`, double-click test |
| Approvals inbox (signs exact hash; active-profile acknowledgement) | Implemented (M4) | |
| Live run timeline (events-derived stages, task panel, event log), reconnect/stale/polling fallback, cancel | Implemented (M4) | `e2e/reconnect.spec.ts`, `src/lib/events.test.ts` |
| Coverage, findings, evidence explorer, controls, report preview/download/approve | Implemented (M4) | partial/failed/denied/empty states covered |
| Accessibility: axe WCAG 2.2 AA on 24 screens (0 violations), keyboard, reduced motion, non-colour status | Implemented (M4) | automated checks only; no manual screen-reader pass |
| Review actions on findings, exceptions, asset graph, recommendations UI | Planned (M6/M7) | shown as planned, nothing simulated |
| Production sign-in (OIDC via BFF cookie) | Planned | dev stub only |
| Silent-stall detection for an open-but-dead stream | Planned | documented limitation (ADR-015) |
| CI job for e2e | Unverified | written, never run on a runner |
| PASSIVE_HTTP_SMOKE adapter: pinned-address connect, TLS verify-before-send + certificate metadata, one GET/HEAD per hop, per-hop redirect vetting, header allow-list, no body, evidence of DNS/TLS/HTTP/chain/tool version | Implemented (M5), **tested against a local server only** | `tests/security/test_url_smoke_adapter.py` (42), `test_url_smoke_pipeline.py` (47); no public host contacted |
| URL smoke policy pack (7 controls) + report notice "not a security certification" | Implemented (M5) | |
| Generic asset attributes (migration 0003) | Implemented (M5) | independently reversible |
| URL negative suite: unapproved/unregistered URL, bad scheme/userinfo/ambiguous IP, unapproved port, loopback/private/metadata DNS, DNS rebinding after approval, expired manifest/permit, scope-hash mismatch, unapproved profile/adapter, hostile params, request budget, hostile redirects | Implemented (M5) | each asserts zero server requests and zero connection attempts |
| Live validation against https://example.com | Not started | M9 only; needs your explicit authorisation |
| Real-CA, IPv6-only, HTTP/2-only, proxy and unusual-server behaviour | Unverified | local self-signed test PKI only |
| Scanner/CMDB import adapters | Planned (M6) | |
| Agents 2–8, assurance, LLM gateway | Planned (M7) | |
| SBOM / licence gate, runbooks, scorecard | Planned (M8) | |
| Live external tests (example.com, scanme.nmap.org, Juice Shop) | Not started (M9; needs explicit authorisation) | |
| Docker/compose, OPA, Postgres | Not available locally | see reconnaissance.md |
