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
| Independent assurance of findings (hash, freshness, scope, control IDs) | Implemented (M3) | tamper/missing/stale/outage tests; extended to risks, scenarios, recommendations and narratives in M7 |
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
| Review actions on findings, exceptions, asset graph | Planned | shown as planned, nothing simulated |
| Production sign-in (OIDC via BFF cookie) | Planned | dev stub only |
| Silent-stall detection for an open-but-dead stream | Planned | documented limitation (ADR-015) |
| CI job for e2e | Unverified | written, never run on a runner |
| PASSIVE_HTTP_SMOKE adapter: pinned-address connect, TLS verify-before-send + certificate metadata, one GET/HEAD per hop, per-hop redirect vetting, header allow-list, no body, evidence of DNS/TLS/HTTP/chain/tool version | Implemented (M5), **tested against a local server only** | `tests/security/test_url_smoke_adapter.py` (42), `test_url_smoke_pipeline.py` (47); no public host contacted |
| URL smoke policy pack (7 controls) + report notice "not a security certification" | Implemented (M5) | |
| Generic asset attributes (migration 0003) | Implemented (M5) | independently reversible |
| URL negative suite: unapproved/unregistered URL, bad scheme/userinfo/ambiguous IP, unapproved port, loopback/private/metadata DNS, DNS rebinding after approval, expired manifest/permit, scope-hash mismatch, unapproved profile/adapter, hostile params, request budget, hostile redirects | Implemented (M5) | each asserts zero server requests and zero connection attempts |
| Live validation against https://example.com | Not started | M9 only; needs your explicit authorisation |
| Real-CA, IPv6-only, HTTP/2-only, proxy and unusual-server behaviour | Unverified | local self-signed test PKI only |
| Import foundation: upload API (size/UTF-8/redaction/RBAC/audit), immutable `imports` table (migration 0004), gateway-mediated tenant/project/kind/hash-verified reader, `in_scope` hook | Implemented (M6) | `tests/security/test_import_pipeline.py` (23) |
| Import adapters: CMDB CSV/JSON, Prowler JSON, Greenbone XML, OpenSCAP XCCDF, Wazuh JSON, Nmap XML, ZAP JSON | Implemented (M6), **synthetic fixtures only** | `tests/security/test_import_adapters.py` (144); real-tool version compatibility **Unverified** |
| Hostile-input handling: XXE/entity bombs/external DTD refused, garbage fails closed, 20k record cap, scope drop for IP/account/URL, profile violations (Nmap args, ZAP active rules) refused | Implemented (M6) | per-adapter parametrised tests; 12 mutation checks |
| Agent 1: CMDB reconciliation (unknown stays unknown, duplicates flagged not merged, conflicts untrusted, stale named) + identity resolver; confidence only from authoritative inventory | Implemented (M6) | `tests/unit/test_discovery.py`; multi-source pipeline test |
| Registry hardening (registration refusals, health, capability metadata, contract test for every adapter) | Implemented (M6) | `tests/contract/test_adapter_contract.py` |
| Policy pack `import-baseline:1.0.0` (13 controls) + `disjoint` operator; per-adapter coverage ledgers; gap warnings in ledger | Implemented (M6) | |
| Task dependency ordering between imports | Planned | import the CMDB first |
| Upload / import-parameter UI | Planned | API only; wizard cannot supply import ids |
| Retention/purge of raw uploads | Planned (M8) | raw uploads keep the original (secret-redacted) file |
| Live Nmap / Greenbone / ZAP / Wazuh / Prowler execution | Not planned for MVP imports; live Nmap only in M9 with authorisation | |
| Migration 0005: risk assessments, scenarios, recommendations, narratives, append-only `llm_calls`, ticket outbox (forced RLS, least-privilege grants, CHECKs against fabricated tiers/unreviewed acceptance) | Implemented (M7) | `tests/security/test_analysis_security.py` (17), `test_migrations.py` (reversible) |
| Versioned risk rubric `risk-rubric-1.0.0`; tier never fabricated (unknown criticality -> no tier, labelled severity-only indication) | Implemented (M7), **sample weights need policy-owner approval** | `tests/unit/test_rubric.py` (25) |
| Agent 5: evidence-backed same-asset scenarios, OBSERVED links only | Implemented (M7) | `tests/unit/test_correlation.py`; no attack-path/graph reasoning |
| Agent 6: draft recommendations from a **sample** pattern catalog (traceable, effort unknown, owner questions, rollback, acceptance test, no commands/compliance/EOL claims) | Implemented (M7), **sample catalog** | `tests/unit/test_architecture.py` (18) |
| Agent 7: full deterministic assurance (risk recomputation, scenario/recommendation/narrative checks, constituent rule, only ACCEPT reaches the report) | Implemented (M7) | `tests/unit/test_assurance_m7.py` (11), pipeline and API tests |
| Agents 2-4 registry mapping (`GET /api/v1/agents`: agent -> adapters, AI state) | Implemented (M7) | every registered adapter must map to one agent (tested) |
| LLM gateway: disabled by default, loopback-only client, no tools, no redirects, strict output schema, one retry, provenance | Implemented (M7), **stub model and local fake runtime only; no weights downloaded** | `tests/evaluation/` (40: groundedness, hallucinated CVE/control/IP/URL/port/tier/asset, prompt injection, tool-call attempts, malformed/timeout/outage, secrets never reach the model) |
| AI on/off equivalence: outage or rejection leaves deterministic report identical; model never called under the run lock | Implemented (M7) | `tests/integration/test_analysis_pipeline.py` (13) |
| Recommendation decisions (ACCEPT/DEFER/REJECT with reason, approver only, never executes) and ticket **drafts** (off by default, outbox DRAFT only) | Implemented (M7) | `tests/integration/test_analysis_api.py` (12) |
| UI: Architecture & Modernization workbench, run Analysis tab, finding risk panel, analysis timeline stages, AI labelling | Implemented (M7) | `e2e/analysis.spec.ts` (3), axe on new screens |
| Real model behaviour, quality and latency; model licence review | Unverified / Planned | needs an approved open-source model and your go-ahead to run one locally |
| Approved architecture catalog and rubric weights (policy owner) | Planned | the shipped ones are samples |
| SBOM / licence gate, runbooks, scorecard | Planned (M8) | |
| Live external tests (example.com, scanme.nmap.org, Juice Shop) | Not started (M9; needs explicit authorisation) | |
| Docker/compose, OPA, Postgres | Not available locally | see reconnaissance.md |
