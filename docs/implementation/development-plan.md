# AISW v2.1 — Development Plan (DRAFT FOR REVIEW)

**Status:** Proposal only. No code has been written and no external target has been contacted.
**Sources analysed:** `Agentic_Infrastructure_Security_Warden_Proof_Blueprint_v2_1_Open_Source.docx` (main blueprint, incl. Appendices A–J) and `AISW_v2_1_Open_Source_Public_URL_Test_Profile.md` (addendum).
**Author role:** Senior developer / security architect.

---

## 1. What we are building (one paragraph)

A customer-hosted, **read-only**, evidence-first assessment platform. A human drafts a scope in a web console, preflight checks it, an approver signs a versioned manifest, a durable orchestrator dispatches allowlisted adapters via a tool gateway, evidence is validated/redacted/hashed, OPA-style deterministic policy produces findings and a coverage ledger, bounded (optional, feature-flagged) LLM steps correlate and recommend, a deterministic assurance gate accepts or rejects every claim, and a human approves the report. Nothing — browser, model, or finding — has a path to infrastructure change.

**The single most important design rule:** scope authorization, normalization, policy, scoring, assurance and counts are *deterministic code*. The LLM is optional, sandboxed, and its output is only a "candidate" until deterministic validation passes.

---

## 2. Analysis summary — what the documents agree on, and where they don't

### 2.1 Non-negotiables (I will encode these as automated tests, not just docs)
| # | Invariant | Enforced by |
|---|---|---|
| N1 | No tool dispatch without a valid, unexpired execution permit bound to the manifest hash | Tool Gateway re-checks on *every* adapter call; negative tests assert zero dispatch |
| N2 | UNKNOWN / NOT_ASSESSED / ERROR / partial never becomes PASS | Status enum + coverage-ledger invariants + report reconciliation tests |
| N3 | Tenant/scope claims from a model or from evidence are ignored | Tenant derived only from server auth context; Postgres RLS |
| N4 | Scanner output, banners, config comments are untrusted data | Evidence pipeline strips/never executes; prompt-injection test corpus |
| N5 | No remediation executor exists in MVP | No such adapter type is registerable; test that gateway rejects "propose a command" |
| N6 | Secrets never in repo, logs, prompts, URLs, browser storage | Redaction layer + secret-scanning in CI + vault references only |
| N7 | Only Agent-7 `ACCEPT` records enter the authoritative report dataset | DB view / query layer, not UI filter |

### 2.2 Inconsistencies and gaps I found (need your decision or I will apply the stated default)
| # | Issue | Where | My default resolution |
|---|---|---|---|
| G1 | Phase numbering differs in 4 places (§13 four-week PoC, §17 phases A–H, Appendix A phases A–G, Appendix I phases A–G, addendum 7-step list) | multiple | One unified milestone list (§4 below) mapped back to each source |
| G2 | Task status enum: 4 values (§7.1) vs 8 values (App. G) | §7.1 vs G | Use the 8-value set; envelope `contract_version: "1.1"` |
| G3 | Event list differs between addendum §6 and App. H.1 (e.g. `preflight.started`, `approval.completed`, `report.partial`, `assessment.cancelled` missing from addendum) | addendum vs H.1 | Union of both |
| G4 | Coverage endpoint: `GET /coverage?assessment_id=` (§9) vs `/assessments/{run_id}/coverage` (H); `assessment_id` vs `run_id` naming | §9 vs H | App. H routes; `run_id` everywhere |
| G5 | Launch response status: `ACCEPTED` (§9.2) vs `AUTHORIZATION_PENDING|ACCEPTED|REJECTED` (H.2) | §9.2 vs H.2 | H.2 |
| G6 | Example finding uses `status: OPEN`; lifecycle (§8.1) is NEW→TRIAGED→… | §8.1/8.2 | Separate fields: `policy_outcome` (PASS/FAIL/…), `lifecycle` (NEW…RESOLVED); drop `OPEN` |
| G7 | State machine (§7.2) lists linear states; PARTIAL/CANCELLED/EXPIRED/FAILED are "any state" overlays; App. E.4 treats them as states | §7.2 vs E.4 | Model as terminal/resumable states with `last_phase` + `reason` |
| G8 | Appendix I still says "v2.docx" and targets Cursor | App. I | Treat as v2.1; same constraints apply to Claude Code |
| G9 | **SSRF gate vs local test target:** J.6 blocks loopback/private IPs unless "explicitly authorized", but a local Juice Shop (needed for DAST dev without owning a public domain) lives on loopback | J.5 vs J.6 | Add an explicit, hash-bound `internal_range_authorization` field in the manifest (human-approved). Never a global bypass |
| G10 | Port approval for `example.com`: manifest must list 443 (and 80 only if the redirect-to-https check is wanted) | J.3/9.4 | Manifest `allowed_ports` is explicit; default 443 only |
| G11 | "Signed manifest" – signing key custody unspecified | §4, E.2 | Dev: Ed25519 key in OS keychain/file *outside* repo; Prod: OpenBao Transit. Key-id stored in manifest |
| G12 | "Progress %" and "security score" — blueprint forbids unmeasured/uncalibrated values | F.1, F.3 | UI shows counts + denominators only; no synthetic score |
| G13 | Four-week PoC plan assumes customer environment (real CMDB, cloud account, 2 on-prem zones) that we don't have | §13 | Build/prove on fixtures; customer integration = separate, authorized phase (M8) |
| G14 | Open-source-only gate vs licences: **Nmap uses the Nmap Public Source License (not OSI-approved)**; Grafana OSS and iTop are AGPL; Greenbone feeds have their own terms; model weights are separate licences | §5, J.1, J.9 | Don't redistribute Nmap in our images (invoke a customer-installed binary); legal/licence review row per component in SBOM; flagged for your call (I'm confident on NPSL but will verify at SBOM time) |

### 2.3 Environment reality check (this machine)
`docker`, `psql`, `opa`, `nmap`, `pnpm` are **not installed**; system Python is 3.9; `uv` 0.12, Node 24, npm 11, git are present. Workspace is not a git repo and `aisw/` doesn't exist yet. Consequences:
- Phase 0 recon is trivial (greenfield) — I'll still write `reconnaissance.md` + ADRs.
- Walking skeleton must run **without Docker**: SQLite for unit tests is *not* acceptable for RLS testing, so I propose **embedded Postgres via `pgserver`/`testing.postgresql`-style tooling in tests**, with docker-compose provided for deployment but not required for dev. If you can install Docker Desktop later, CI gets the full stack.
- OPA: use the single static `opa` binary (downloadable, Apache-2.0) — needs your OK to download. Fallback until then: Rego-free Python rule evaluator behind the same `PolicyEvaluator` interface (swap-in, same tests).
- Nmap adapter: built and contract-tested against golden output fixtures; live run (§9.2) needs `nmap` installed + your explicit go-ahead.

---

## 3. Key architecture decisions (proposed ADRs — please confirm)

| ADR | Decision | Rationale / alternative |
|---|---|---|
| ADR-001 Stack | **Backend: Python 3.12 + FastAPI + Pydantic v2 + SQLAlchemy/Alembic. UI: React + TypeScript + Vite.** | Blueprint recommends React/TS/Vite; Python has the strongest adapter/parsing ecosystem (Prowler, SCAP, nmap XML). Alt: all-TypeScript — fewer languages but weaker security-tooling ecosystem |
| ADR-002 Orchestrator | **PostgreSQL-backed durable worker** (outbox + `SELECT … FOR UPDATE SKIP LOCKED`, persisted state before/after dispatch) | Blueprint permits; Temporal adds ops footprint. Interface designed so Temporal can replace it later |
| ADR-003 Policy engine | OPA (Rego bundles, pinned version/digest) behind `PolicyEvaluator`; Python fallback stub | Deterministic, auditable; version pinned per run |
| ADR-004 Persistence | PostgreSQL with **Row-Level Security** per tenant; evidence on local FS (content-addressed, sha256), SeaweedFS optional later | Tenant isolation enforced in the DB, not just app code |
| ADR-005 Audit | Append-only table with hash chain (`prev_hash`), no UPDATE/DELETE grants | "Tamper-evident" requirement |
| ADR-006 Auth | Keycloak (OIDC) in deployment; **dev mode = local OIDC-compatible stub with seeded test users/roles**, clearly flagged, disabled when `AISW_ENV!=dev` | No customer SSO available; keeps RBAC tests real |
| ADR-007 Events | Persisted `run_events` table with per-run monotonic cursor; SSE endpoint + polling fallback; snapshot endpoint for reconnect | Events are notifications, not source of truth |
| ADR-008 Agent model | Agents = typed task handlers registered with orchestrator; **no agent-to-agent calls**; LLM client only reachable from 3 handlers (5, 6, 8-narrative) behind feature flags | Reduces privilege surface |
| ADR-009 LLM | Ollama/vLLM local only, **disabled by default**; enable only after approved model weights + licence recorded | Blueprint: disable AI if no approved model |
| ADR-010 Graph | Relational edge tables; no graph DB | Blueprint: defer |
| ADR-011 Tool gateway | In-process gateway module first (strict allowlist, permit check, quotas), separable later into a service | Avoid premature microservices (App. D.3) |
| ADR-012 URL/SSRF | Shared `net_guard` library: scheme/port/userinfo/IDN checks, A/AAAA resolution at preflight **and** dispatch, IPv4-mapped IPv6, redirect re-validation, pinned-IP connect; egress firewall rule documented for deployment | J.6 |

---

## 4. Milestones (unified build order)

Each milestone ends with a **gate** and a **handoff report** (files changed, behavior, exact commands + results, negative tests, gaps/mocks/unverified, next step). No success claim without passing evidence. I will pause for your review at the milestones marked 🛑.

| M | Name | Delivers | Gate (must pass to proceed) | Maps to |
|---|---|---|---|---|
| **M0** 🛑 | Recon, ADRs, repo skeleton | `reconnaissance.md`, ADR-001…012, monorepo layout, CI (lint/type/test/secret-scan/SBOM stub), typed config, pinned toolchain, `README` with local-dev w/o credentials | CI green on empty skeleton; plan approved | A / Phase 0 / addendum §7.1 |
| **M1** | Contracts & security foundation | JSON-schema/Pydantic contracts (envelope 1.1, ScopeManifest, ExecutionPermit, AuthorizationDecision, Asset, Relationship, Observation, Finding, ControlAssessment, Recommendation, Coverage, AuditEvent, AssuranceResult, ReportBundle); Alembic migrations; tenant context + RLS; RBAC; idempotency store; hash-chain audit; strict unknown-field rejection | Contract tests; **cross-tenant, RBAC, replay, idempotency negative tests pass** | B / App. I-A |
| **M2** | Agent 0 + Tool Gateway + `net_guard` | Deterministic scope gate (resolve targets, wildcard/exclusion rules, active-check approval, canonical manifest + hash + signature, expiring permit); gateway with allowlist & permit re-check; SSRF library | Agent 0 test matrix (cross-tenant, excluded target, wildcard escalation, stale hash, expired permit, denied source, active-scan approval, replay) **asserting zero dispatch**; URL/SSRF matrix (private IP, redirect, DNS-rebind simulation) | Agent 0, J.6, N1 |
| **M3** | **Vertical slice #1 (API only)** | Project → fixture source → preflight → approve → launch → durable run → fixture adapter → evidence ingest (validate/redact/hash) → policy eval → findings + coverage ledger → report JSON/HTML. Partial fixture source ⇒ visible UNKNOWN/PARTIAL | End-to-end API integration test with no scanner/credentials; rejected scope = 0 tool calls; report counts reconcile to DB | C / App. I-B |
| **M4** 🛑 | UI slice | App shell + route guards; Command Center; New Assessment wizard (6 steps); Integrations health; Assessments + live AgentOps timeline (SSE + cursor replay); Coverage; Findings table + Evidence Explorer; Report preview. Loading/empty/denied/stale/partial/failed/reconnect states; WCAG 2.2 AA basics | Playwright: launch happy path, blocked preflight, reload/reconnect, partial run, permission denial; axe checks | C / App. I-C / addendum §7.4 |
| **M5** | **Public URL path** (`PASSIVE_HTTP_SMOKE`) | URL source type; passive-HTTP adapter (DNS, TLS metadata, single GET/HEAD, redirect revalidation, no body storage); report banner "not a security certification" | Unit/contract tests against a local test server and mocked DNS; negative suite (unapproved URL, private-IP redirect, expired approval, hash mismatch, blocked DNS, unapproved profile) = zero dispatch | J.3, J.6 |
| **M6** | Adapter hardening & more sources | Adapter registry + capability matrix + health; CSV/JSON inventory (CMDB) adapter + Agent 1 reconciliation/coverage; Prowler JSON import; Greenbone/OpenVAS report import; Wazuh/OpenSCAP import; Nmap XML adapter; ZAP baseline import. All via golden sanitized fixtures first | Adapter contract tests; scanner-says-success-but-zero-assets ⇒ coverage anomaly; no denied permission escalated | D / App. I-D |
| **M7** | Bounded agents 2–8 + assurance | Handlers for Agents 2–8; deterministic risk rubric (versioned); **Agent 7 deterministic assurance** (schema, evidence resolve, hash, freshness, control-ID validity, ungrounded claims); LLM gateway behind flags with injection-hardened prompts and schema validation; ticket outbox (disabled by default) | Eval suite: groundedness, hallucinated CVE/control rejected, prompt-injection-in-evidence, model outage leaves deterministic results intact; only ACCEPT reaches report | E / App. I-E |
| **M8** 🛑 | Hardening + PoC evidence | Cancellation, retry storms, event dedupe, export authorization/watermark, SBOM + licence report (Syft + ScanCode), threat model, runbooks, scorecard populated from *actual* results, honest implemented/mock/unverified matrix | All App. E/J gates; no unresolved critical security test | F–G / H / J.7, J.9 |
| **M9** (needs your explicit authorization) | Live external validation | (a) `example.com` passive smoke (b) one bounded Nmap run on `scanme.nmap.org` (c) ZAP baseline→active against *your own* Juice Shop deployment | Evidence package per J.7 / addendum §9.5 | J.3–J.5 |

### Deliberately deferred (per App. D.3)
Agent-to-agent negotiation, graph database, active network probing beyond the three approved profiles, remediation executor, model fine-tuning, 3D graphs (still deferred; the decorative 3D view of ADR-047 draws no relationships), Temporal, DefectDojo/SeaweedFS (optional hooks only).

---

## 5. Repository layout (adapted from §12; fewer top-level services than the sample)

```
aisw/
  docs/{implementation,adr,architecture,runbooks,standards-mapping}/
  backend/
    aisw/
      api/            # FastAPI routers, auth deps, idempotency
      contracts/      # Pydantic models + exported JSON Schemas (source of truth for UI types)
      core/           # tenant ctx, RBAC, audit chain, config, redaction
      authz/          # Agent 0: manifest, permit, signing, net_guard
      orchestrator/   # state machine, durable worker, events
      gateway/        # tool gateway, adapter registry
      adapters/       # fixture, url_smoke, nmap, prowler, greenbone, wazuh, openscap, zap, cmdb_csv
      evidence/       # ingest, redaction, hashing, object store
      policy/         # evaluator iface, OPA client, policy-packs/
      agents/         # handlers 1–8 (+ llm/ gateway, prompts/ versioned)
      reporting/
    migrations/  tests/{unit,contract,integration,security,evaluation,fixtures}
  web/              # React + TS + Vite, Playwright tests, design tokens
  deploy/           # docker-compose, OPA bundle, Keycloak realm export, egress-firewall notes
  tools/            # sbom, licence-check, schema-export scripts
```

---

## 6. Security & test strategy (cross-cutting)

- **Negative tests are first-class:** every "must reject" in the blueprint (§14.1, Agent 0 matrix, J.6) becomes a named test that asserts both the rejection *and* `dispatch_count == 0` *and* an audit event.
- **Test layers:** unit → contract (schemas, adapters, golden fixtures) → integration (real Postgres, OPA) → security (tenant isolation, RBAC, SSRF, injection, replay) → evaluation (LLM groundedness; skipped when AI disabled) → UI (Playwright + axe).
- **CI gates:** lint, strict typing (mypy/ruff, tsc), secret scan, dependency audit, SBOM, licence check (fail on unknown/NOASSERTION), schema-drift check (UI types generated from backend schemas).
- **Redaction:** single `redact()` used before model input, logs, and UI payloads; property-tested with seeded secret patterns.
- **Honesty matrix:** `docs/implementation/status.md` listing each capability as *Implemented / Mocked / Unverified / Planned* — updated every milestone.

---

## 7. Risks to the plan

| Risk | Mitigation |
|---|---|
| Scope is very large vs one engineer | Vertical slice first; M3 is the real proof point; agents 2–8 are thin deterministic handlers initially |
| No Docker → can't run full stack locally | Embedded Postgres for tests; compose files authored but marked *unverified* until run; ask you to install Docker if you want M9/deploy verification |
| Live tool behaviour unverifiable (Greenbone, Wazuh, Prowler) | Golden fixtures + import adapters; documented as *Mocked/Unverified* — no claim of live validation |
| Licence ambiguity (Nmap NPSL, AGPL components, feeds, model weights) | SBOM + owner review gate; don't bundle questionable components |
| LLM unavailable/unapproved | AI disabled by default; product fully functional deterministically |

---

## 8. Decisions I need from you before M0

1. **Stack (ADR-001):** Python/FastAPI + React/TS/Vite — OK? (or all-TypeScript?)
2. **Location:** create the repo at `Claude Projects/aisw/` and `git init` it — OK?
3. **Downloads:** OK for me to download static `opa` binary and Python/npm dependencies (from official registries) during M0–M2? Docker/Nmap I will *not* install without your say-so.
4. **Dev identity:** accept the dev-only OIDC stub (ADR-006) until you have a Keycloak instance?
5. **LLM:** keep AI disabled/stubbed through M6, and decide on an approved local model only at M7?
6. **Review cadence:** pause at M0, M4, M8 (🛑 above) — or at every milestone?
7. **Live tests (M9):** do you own a public hostname + host for Juice Shop? If not, I'll validate DAST only against a localhost Juice Shop using the explicit `internal_range_authorization` (G9), pending Docker/Node availability.
8. **Doc conflicts G1–G14:** accept my default resolutions?

*External actions policy:* nothing in M0–M8 contacts a public target. M9 steps each require your explicit confirmation at the time, and the Nmap run will re-check the official `scanme.nmap.org` terms first.
