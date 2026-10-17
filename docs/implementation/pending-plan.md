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
| Policy | Python evaluator and OPA (ADR-031) over pinned packs; Rego domain rules with `opa test` in CI | Importers feed network, IAM and K8s facts (ADR-034); storage, logging, TLS, hardening and lifecycle facts still need a feeder; mapping review |
| UI | React/TypeScript/Vite console, SSE, ~10 screens | Vanilla JS, Socket.IO, APEX look, 13 pages (Estate Map, Control Matrix, Evaluation Lab, ...) |
| Frameworks | Curated catalog over all packs with per-tenant review (ADR-032) | Policy-owner review of the proposals |
| Branding/data | Generic AISW, synthetic fixtures | "WARDEN by Amdocs", Maple Trust estate fixtures (~60 assets) |

**Recommendation:** keep this repository as the base, since it is built, tested and hardened, and adopt only the rev 3 items you still want as explicit milestones (Astra phases in §4, OPA, framework mappings, the extra UI pages). Record the choice in an ADR. Until then, §3 and §4 are needed under either plan, and §5–§6 are rev 3-specific.

## 3. Required before any real use (P0)

| # | Item | Why it is open | Done when |
|---|---|---|---|
| P0-1 | Production sign-in (OIDC via BFF cookie, Keycloak or the customer IdP) | **Built (ADR-026)**: generic OIDC, role map, session expiry, revocable logout, RBAC tests on real tokens, all against a loopback mock IdP. **Pending:** register a client at the customer IdP and confirm its claim names, group mapping and logout (owner: platform admin; next step: IdP client registration) | Sign-in, role mapping and logout verified against the real IdP tenant using `docs/runbooks/sign-in.md` |
| P0-2 | Signing-key custody and rotation (OpenBao Transit or HSM) | **Built (ADR-027)**: Transit signer, local verification, revocation list, rotation drill passing on the loopback emulator (`key-rotation-drill.md`); local file keys stay the dev/test default. **Pending:** provision a real Transit key and app/admin tokens, then run the drill against it (owner: platform admin) | Drill passes against the real KMS; old manifests still verify via key ring |
| P0-3 | Egress enforcement at host or network level | **Built (ADR-028)**: scan zones enforced at preflight and dispatch, IdP endpoints bound to allowed hosts, nftables/iptables rules generated per role from settings, `egress_check verify` probe. **Pending:** load the rules on a real host and run `verify` with a deny canary (owner: platform admin) | `verify` passes on the API and worker hosts, with a canary that is reachable without the firewall being refused |
| P0-4 | Deployment: Dockerfiles/compose or native service units, Postgres, worker process | **Built (ADR-029)**: `deploy/` has backend and web images, compose, systemd units and an install runbook; bootstrap, doctor, `/readyz`, worker heartbeat and graceful shutdown. The API and worker are proven as live processes against Postgres, driving a run to REPORT_READY. **Pending:** build the images and run the clean-machine install on a host with Docker or systemd (owner: platform admin) | Clean-machine install from the runbook; API, worker and UI up; doctor/health checks green |
| P0-5 | First real CI run | **Built (ADR-030)**: five jobs (backend, web, e2e, deploy images, hygiene), SHA-pinned actions, read-only token, the drill and image checks added; actionlint and zizmor clean locally. **Pending:** push the branch and get a green run on GitHub Actions; the SBOM gate, pgserver and Chrome may differ on the runner (owner: repository owner) | All five jobs green on GitHub Actions |
| P0-6 | Policy-owner approval of risk rubric `1.0.0` weights/thresholds, the architecture catalog and the AI evaluation bar | **Recorded PENDING** in the sign-off register ([`signoffs.md`](signoffs.md)) with owner and next step. While pending, the report adds the sample label of every rubric and catalog it relies on, and the console labels the rubric and keeps the sample-catalog banner. An approval needs the decider, date, reference and the sha256 of the exact file (`tools/signoffs.py --check` in CI). **Pending:** policy-owner decisions (owner: policy owner) | Signed-off versions committed; "sample" labels removed by version bump |
| P0-7 | Legal review of licences (LGPL `psycopg`, MPL dev tools, three packages without metadata) | **Recorded PENDING** in the sign-off register (`licence-review`) and in the SBOM report; the acceptances in `licence-policy.json` stay engineering positions. **Pending:** a named legal reviewer's decision (owner: legal reviewer) | Named reviewer's decision recorded in `licence-policy.json` |

## 4. Astra follow-ups

Done on 2026-10-16:
- **Live connectivity.** `tools/astra_smoke.py` gets a validated narrative on its first attempt from gpt-6-astra, gpt-5.4 and gpt-4.1-mini on `dev-agentic`, API `2025-04-01-preview`.
- **AI validation pass for Agents 1–7 (ADR-021).** Built, tested, and run live with `tools/astra_live_run.py` on the `baseline-ok` and `baseline-injection` fixtures.
- **Data approval.** The dev approval ref is a placeholder for synthetic data only (`product-owner-2026-10-16-synthetic-data-only`).
- **A-9 dissent resolution (ADR-022).** Overrule or uphold with a reason, assurance and report revisions, and the UI action.
- **A-3 to A-6 model-call routing (ADR-023).** Usage and latency provenance, per-run token budget, failover with cooldown, and record/replay.
- **A-2 and the generation agents (ADR-024).** Agent 0 scope review as a note, Agent 4 owner questions, and the Agent 8 executive summary with its own review.
- **A-8 labelled evaluation and A-7 explicit proxy (ADR-025).** `tools/eval_labelled.py` on a synthetic set of 24+5 cases met the provisional bar on its third live run (recall 1.0, false dissent 0, 5/5 narratives); all runs are recorded in ADR-025. `AISW_ASTRA_PROXY` is a CONNECT-only, Astra-only proxy.

| # | Item | Notes |
|---|---|---|
| A-1 | Data-handling approval for Astra (open item O3) covering real evidence | **Recorded PENDING** in the sign-off register (`astra-data-approval`). Synthetic data only until then; the configured approval ref covers synthetic data only (owner: product owner with the data protection officer) |

## 5. Rev 3 scope not built (only if the WARDEN plan is adopted, see §2)

- ~~**Rest of the Astra validation pass:** a trigger policy file and an Engine-vs-Astra disagreement queue page.~~ **Done (ADR-036).** **Pending:** policy-owner sign-off of the sample trigger policy (`avp-triggers-1.0.0`).
- ~~**OPA + Rego bundles** for network, storage, logging/encryption, IAM, lifecycle, hardening and K8s RBAC, plus `opa test` in CI.~~ **Done (ADR-031).** Mappings and thresholds await policy-owner review (sign-off `config-baseline-1.0.0`).
- ~~**Framework mappings** (NIST CSF 2.0, CIS v8.1, 800-53r5, ATT&CK) with approval state, and a Control Matrix page.~~ **Done (ADR-032).** **Pending:** a policy owner reviews the 240 proposed mappings in each tenant (owner: policy owner; next step: work through the Control Matrix).
- ~~**Exceptions with expiry** (an expired exception becomes FAIL), plus review actions on findings (confirm, reject, request exception).~~ **Done (ADR-033).**
- ~~**Additional adapters:** Kubernetes (kubescape), firewall exports, LDAP/AD/IAM, NetBox/ServiceNow CMDB APIs, Trivy, Tenable/Qualys/Nessus imports.~~ **Done as file importers (ADR-034).** **Pending:** check each format against an export from the customer's real tool version (owner: platform admin; next step: upload one sanitised export per tool and compare with the fixture), and live API pulls if ever authorised.
- **UI pages:** ~~Asset Explorer~~ (done: `/assets`; an estate map needs relationships, which are not modelled), ~~Coverage Ledger view~~ (done: `/coverage`), ~~Exposure Scenarios chain view, Modernization Roadmap swimlanes~~ (done, ADR-035), ~~Assurance Console, Audit & Provenance with model-call ledger~~ (done, ADR-036: disagreement queue, trigger policy, ledger), ~~Evaluation Lab scorecard~~ (done, ADR-039).
- **Reporting:** ~~PDF/DOCX exports, control-gap matrix, architecture delta~~ **Done (ADR-038).** ~~ITSM draft delivery to Jira/ServiceNow~~ **Built (ADR-037):** renderers, Ticket Outbox page and two-person find-then-create delivery, tested against a loopback fake. **Pending:** sign-off `itsm-delivery` (owner: ITSM owner with the security programme lead; next step: approve a rendered payload, a create-and-search-only service account and the egress rule, then send a first ticket to a sandbox project).
- ~~**Maple Trust fixture estate** (~60 assets) and `scripts/eval_targets.py` scorecard against an answer key.~~ **Done (ADR-039)** as `tools/eval_targets.py`; results in `docs/implementation/eval-targets.md`. **Pending:** an answer key for each owner-supplied target (owner: product owner; next step: supply known issues and known-clean controls per target, §7.1).

## 6. Product and engineering gaps under either plan (P2)

| Area | Gap |
|---|---|
| Live validation (M9) | `example.com` passive smoke, one bounded Nmap on `scanme.nmap.org` (re-check terms), ZAP against your own Juice Shop. Each needs your explicit authorisation and an approved manifest |
| Imports | ~~Upload/import-parameter UI; task dependency ordering~~ (done: review-step file pickers; inventory tasks run first, migration 0019); real tool-version compatibility of the importers |
| Analysis | ~~Real reachability for exposure scoring; graph/attack-path reasoning~~ (done, ADR-041: edges from host-firewall configuration and declared-vantage scans, exposure backed by stored edges, internet-to-asset path scenarios, migration 0022); cloud security-group attachment, rule shadowing and perimeter devices are not modelled; ~~separation of duties for recommendation decisions~~ (done: the run requester may only defer; migration 0018 enforces it) |
| Retention | ~~UI and scheduler~~ (done: Evidence Retention page; daily dry-run check with opt-in, two-sighting auto soft purge, migration 0020); quarantine deletion is manual. **Pending:** sign-off on enabling auto-execute (owner: retention owner; next step: approve `AISW_RETENTION_AUTO_EXECUTE=true` and the confirmation window per tenant) |
| Evidence | ~~Object-lock/WORM storage; externally witnessed audit-chain anchor~~ (done as seams with dev/test emulators: write-once replica, signed and witnessed hourly anchors, migration 0023, ADR-042). **Pending:** sign-offs `evidence-worm-storage` (owner: platform owner; next step: provision an Object Lock bucket in COMPLIANCE mode with a write-only role and agree retention) and `audit-anchor-witness` (owner: security programme lead; next step: choose an RFC 3161 TSA, a transparency log or a separate-account WORM bucket) |
| Events | ~~Silent-stall detection for an open but dead SSE stream (ADR-015)~~ (done: a client watchdog reopens the stream from the cursor after 30 s of silence) |
| Authorisation | ~~Per-project roles~~ (done, ADR-040: additive project grants for operator, approver, reviewer and report reader, migration 0021); tenant-wide lists still need a tenant role |
| URL probe | ~~IPv6-only, HTTP/2-only and proxy behaviour~~ (done on loopback: IPv6 pinning and fallback, HTTP/2-only reported as `HTTP2_ONLY_UNSUPPORTED`, environment proxies ignored by design, ADR-016). **Pending:** a public-CA target, part of live validation (M9) and needing your authorisation |
| Supply chain | ~~Syft/ScanCode SBOM; gitleaks~~ (done, ADR-043: CI cross-checks the lockfile SBOM against Syft image scans and ScanCode licence detection; gitleaks scans the full history; Syft and gitleaks run locally, ScanCode in CI only). **Pending:** the first CI run of the image scan and ScanCode; signing of release artefacts |
| Scale | ~~Multi-node worker soak test~~ (done on one machine, ADR-044: worker processes killed at random; 120 of 120 runs, 28 kills, 9 tasks reclaimed, results in `soak.md`). **Pending:** workers on separate hosts, network partitions, and DoS sizing on the target hardware (owner: platform owner) |
| Accessibility | Manual screen-reader pass (axe WCAG 2.2 AA automated only) |
| Hygiene | ~~Starlette `TestClient`/`httpx` deprecation warning in every test run~~ **Done:** the test client uses `httpx2`, as Starlette now requires |

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
4. ~~GitHub Actions or GitLab CI as the system of record?~~ **Decided: GitHub Actions** (ADR-030).
5. Which targets, and in which windows, are authorised for M9?
