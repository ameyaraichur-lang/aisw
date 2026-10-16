# Pending work plan (post-M8)

Date: 2026-10-16. Baseline: `main` at `956489d` (M0–M8 complete), plus the Astra provider (ADR-020) and the AI validation pass over Agents 1–7 (ADR-021), both run live on synthetic data.
Sources: this repository's README "prepared / not prepared" matrix, `status.md`, the threat model's residual risks, ADRs 001–020, the runbooks, and the WARDEN rev 3 implementation plan kept beside the repository (`../docs/implementation/implementation-plan.md` in the parent workspace).

## 1. Where the project stands

The proof-of-concept pipeline is complete end to end on **synthetic data**: signed scope, tool gateway, durable worker, evidence store, policy evaluation, Agents 0–8, independent assurance, report with human approval, and the operator console. Measured on 2026-10-16 in this checkout: backend ruff, ruff format and strict mypy clean, **899 tests passed** before the Astra change and **964** after it (65 added for Astra configuration, client and API). Web: lint, type drift, `tsc` and 14 vitest tests pass, and the build succeeds.

Nothing has touched a real host, real scanner output, a real model, a real identity provider or a real deployment. Everything below is what stands between this state and a usable product.

## 2. Decision needed first: which plan governs

Two plans describe this product, and they disagree:

| Topic | Built in this repo (blueprint v2.1 open-source, `development-plan.md`) | WARDEN rev 3 plan in the parent workspace (blueprint v1.1) |
|---|---|---|
| LLM | Optional, local only (ADR-009); explains, never decides. Astra now opt-in (ADR-020) | Astra on every agent: generation for A4/A5/A6/A8 plus an "Astra validation pass" (AVP) for A0–A8 |
| Policy | Python evaluator over pinned JSON packs; OPA not installed | OPA + Rego bundles, `opa test` |
| UI | React/TypeScript/Vite console, SSE, ~10 screens | Vanilla JS, Socket.IO, APEX look, 13 pages (Estate Map, Control Matrix, Evaluation Lab, ...) |
| Frameworks | Control ids in packs; mappings not curated | NIST CSF 2.0, CIS v8.1, 800-53r5, ATT&CK mappings with approval state |
| Branding/data | Generic AISW, synthetic fixtures | "WARDEN by Amdocs", Maple Trust estate fixtures (~60 assets) |

**Recommendation:** keep this repository as the base, since it is built, tested and hardened, and adopt only the rev 3 items you still want as explicit milestones (Astra phases in §4, OPA, framework mappings, the extra UI pages). Record the choice in an ADR. Until then, §3 and §4 are needed under either plan, and §5–§6 are rev 3-specific.

## 3. Required before any real use (P0)

| # | Item | Why it is open | Done when |
|---|---|---|---|
| P0-1 | Production sign-in (OIDC via BFF cookie, Keycloak or the customer IdP) | Only the dev identity picker exists; the app refuses it outside dev/test, so it **cannot be deployed** (T1, ADR-006) | OIDC login, role mapping, session expiry, logout; RBAC tests run against real tokens |
| P0-2 | Signing-key custody and rotation (OpenBao Transit or HSM) | Ed25519 key is a local file; no rotation or revocation procedure tested (T20) | Key in KMS, rotation drill passes, old manifests still verify via key ring |
| P0-3 | Egress enforcement at host or network level | Application-layer checks only (T6, T12); now also needed for the Astra host | Firewall rules allow only approved targets and the Astra host; a test from the host proves denial |
| P0-4 | Deployment: Dockerfiles/compose or native service units, Postgres, worker process | `deploy/` is absent; `python -m aisw.orchestrator` was never run as a live process | Clean-machine install from the runbook; API, worker and UI up; doctor/health checks green |
| P0-5 | First real CI run | `.github/workflows/ci.yml` (backend, web, hygiene, e2e) was never run on a runner; SBOM gate may differ by platform | All four jobs green on GitHub Actions (or a GitLab equivalent) |
| P0-6 | Policy-owner approval of risk rubric `1.0.0` weights/thresholds and the architecture catalog | Both are labelled samples in UI and report | Signed-off versions committed; "sample" labels removed by version bump |
| P0-7 | Legal review of licences (LGPL `psycopg`, MPL dev tools, three packages without metadata) | Recorded as pending in the SBOM report | Named reviewer's decision recorded in `licence-policy.json` |

## 4. Astra follow-ups

Done on 2026-10-16:
- **Live connectivity.** `tools/astra_smoke.py` gets a validated narrative on its first attempt from gpt-6-astra, gpt-5.4 and gpt-4.1-mini on `dev-agentic`, API `2025-04-01-preview`.
- **AI validation pass for Agents 1–7 (ADR-021).** Built, tested, and run live with `tools/astra_live_run.py` on the `baseline-ok` and `baseline-injection` fixtures.
- **Data approval.** The dev approval ref is a placeholder for synthetic data only (`product-owner-2026-10-16-synthetic-data-only`).

| # | Item | Notes |
|---|---|---|
| A-1 | Data-handling approval for Astra (open item O3) covering real evidence | Synthetic data only until then |
| A-2 | Validation pass for Agent 0 (manifest preflight) and Agent 8 (report narrative) | Deferred in ADR-021; A8 needs an executive narrative to exist first |
| A-9 | Human resolution of held items | A reviewer can see the held items, but there is no "resolve AI dissent" action yet; resolution means re-running today |
| A-3 | Usage and latency in provenance | Persist Responses API `usage` (input/output tokens) and latency on `llm_calls` (new migration) |
| A-4 | Per-run token budget (rev 3 default 400k) with a priority order | Budget exhaustion must become `UNAVAILABLE`, never a partial narrative |
| A-5 | Tier routing with one-hop failover (fast / reasoning / fallback deployments) | Provenance must record the deployment that actually answered, not the configured one |
| A-6 | Record/replay cache (`AISW_LLM_MODE=auto|replay|off`) for offline demos and CI | Replay keyed by input hash; never used in production mode |
| A-7 | Corporate proxy support | The client ignores proxy variables by design; if a proxy is mandatory, add an explicit, allow-listed proxy setting |
| A-8 | Evaluation on real output | Measure rejection rate of the grounding validator on Astra output; tune prompts, not the validator |

## 5. Rev 3 scope not built (only if the WARDEN plan is adopted, see §2)

- **Rest of the Astra validation pass:** A0/A8 coverage (A-2), a trigger policy file, and an Engine-vs-Astra disagreement queue with resolve actions (A-9). Agents 1–7, the effect rules and the issue-code allowlist are built (ADR-021).
- **Generation agents:** A4 human-verification questions, A8 executive narrative (only scenario and recommendation narratives exist today).
- **OPA + Rego bundles** for network, storage, logging/encryption, IAM, lifecycle, hardening and K8s RBAC, plus `opa test` in CI (ADR-003 seam exists).
- **Framework mappings** (NIST CSF 2.0, CIS v8.1, 800-53r5, ATT&CK) with approval state, and a Control Matrix page.
- **Exceptions with expiry** (an expired exception becomes FAIL), plus review actions on findings (confirm, reject, request exception).
- **Additional adapters:** Kubernetes (kubescape), firewall exports, LDAP/AD/IAM, NetBox/ServiceNow CMDB APIs, Trivy, Tenable/Qualys/Nessus imports.
- **UI pages:** Estate Map / Asset Explorer (route exists as "planned"), Coverage Ledger view, Exposure Scenarios chain view, Modernization Roadmap swimlanes, Assurance Console, Audit & Provenance with model-call ledger, Evaluation Lab scorecard.
- **Reporting:** PDF/DOCX exports, control-gap matrix, architecture delta; ITSM draft delivery to Jira/ServiceNow (still draft-only, off by default).
- **Maple Trust fixture estate** (~60 assets) and `scripts/eval_targets.py` scorecard against an answer key.

## 6. Product and engineering gaps under either plan (P2)

| Area | Gap |
|---|---|
| Live validation (M9) | `example.com` passive smoke, one bounded Nmap on `scanme.nmap.org` (re-check terms), ZAP against your own Juice Shop. Each needs your explicit authorisation and an approved manifest |
| Imports | Upload/import-parameter UI; task dependency ordering (CMDB must be imported first today); real tool-version compatibility of the seven importers |
| Analysis | Real reachability for exposure scoring (most host findings score exposure 0); graph/attack-path reasoning (ADR-010); separation of duties for recommendation decisions |
| Retention | UI and scheduler; quarantine deletion is manual |
| Evidence | Object-lock/WORM storage; externally witnessed audit-chain anchor |
| Events | Silent-stall detection for an open but dead SSE stream (ADR-015) |
| Authorisation | Per-project roles (roles are tenant-wide today) |
| URL probe | Real CA, IPv6-only, HTTP/2-only and proxy behaviour (tested on local PKI only) |
| Supply chain | Syft/ScanCode SBOM instead of the lockfile-based one; gitleaks instead of the stopgap secret scanner |
| Scale | Multi-node worker soak test; DoS sizing |
| Accessibility | Manual screen-reader pass (axe WCAG 2.2 AA automated only) |
| Hygiene | Starlette `TestClient`/`httpx` deprecation warning in every test run |

## 7. Suggested sequence

1. **Decide the rest of §2.** Astra on the agents is decided (ADR-021); OPA, framework mappings and the rev 3 UI pages are not.
2. **M9a: Astra hardening** (A-3 usage and latency, A-4 budget, A-6 replay for CI, A-9 resolve held items), then the first real CI run (P0-5).
3. **M9b: live validation**, one authorised target at a time.
4. **M10: deployability** (P0-1 OIDC, P0-2 key custody, P0-3 egress, P0-4 deployment).
5. **M11: governance** (P0-6 rubric and catalog sign-off, P0-7 licence review).
6. **M12+: scope growth** from §5 and §6 in the order the product owner ranks them. Astra budget/routing/replay (A-4 to A-6) go before any per-agent validation pass.

## 8. Open questions for the product owner

1. Which plan governs (§2)? If WARDEN rev 3, should the model be allowed to validate agent outcomes (amending ADR-018)?
2. Who approves the Astra data boundary, and does it cover owner-supplied target evidence or synthetic data only?
3. Which Astra deployments and API version should be the defaults (rev 3 named `gpt-6-astra`, `gpt-4.1-mini`, `gpt-5.4`)?
4. GitHub Actions or GitLab CI as the system of record (the repo has a GitHub workflow; the rev 3 plan prepared `.gitlab-ci.yml`)?
5. Which targets, and in which windows, are authorised for M9?
