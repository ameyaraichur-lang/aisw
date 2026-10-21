# Pending work plan (post-M8)

Date: 2026-10-19 (first written 2026-10-16). Baseline: branch `feat/astra-llm-config`, [draft PR #1](https://github.com/ameyaraichur-lang/aisw/pull/1) on top of `main` at `956489d` (M0–M8).
Sources: this repository's README "prepared / not prepared" matrix, `status.md`, the threat model's residual risks, ADRs 001–046, the runbooks, the sign-off register, and the WARDEN rev 3 implementation plan kept beside the repository (`../docs/implementation/implementation-plan.md` in the parent workspace).

## 1. Where the project stands

The proof-of-concept pipeline is complete end to end on **synthetic data**: signed scope, tool gateway, durable worker, evidence store, OPA policy evaluation, Agents 0–8 with the advisory Astra validation pass, independent assurance, report with human approval, and the operator console. Since 2026-10-16 the pre-production seams (sign-in, key custody, egress, deployment, CI), the adopted rev 3 scope and the engineering gaps below were built, ADR-020 to ADR-046, migrations up to 0023. On 2026-10-18 the product ran against real targets for the first time ([record](live-validation/2026-10-18-live-runs.md)), and the console gained the Mission Control live view and a HUD theme (ADR-047).

Measured on 2026-10-19: 1553 backend tests, 22 web unit tests and 42 end-to-end tests (with accessibility scans on 29 screens) pass locally and on the [latest GitHub Actions run](https://github.com/ameyaraichur-lang/aisw/actions/runs/39143185443) (commit `ad31c81`), together with ruff, strict mypy, OPA, schema, SBOM, licence, sign-off, secret-scan and gitleaks checks. Results: [`scorecard.md`](scorecard.md).

Contact with reality so far is the product owner's live runs of 2026-10-18, made with Astra on and outside the M9 harness:
- a passive probe of `example.com`, which went through the corporate TLS-inspection proxy, so its certificate controls were not assessed;
- the local portal;
- a bounded Nmap scan of this workstation;
- Trivy scans of the product's own base images.

They found four defects, all fixed, and real critical and high vulnerabilities in both base images. Nothing has touched a real identity provider, a real KMS or a real deployment, and every importer other than Nmap and Trivy has seen synthetic data only. What remains is mostly the rest of that contact with reality, and the human decisions recorded as PENDING in [`signoffs.md`](signoffs.md) (14 entries, each with an owner, a next step and an engineering review that says whether a decision can be made now and what is still open; the reviews are not decisions).

## 2. Which plan governs: decided

**This repository is the base; rev 3 items are adopted one at a time (ADR-046).** Adopted: Astra on the agents (advisory only), OPA, framework mappings, exceptions, the rev 3 importers, the rev 3 pages as routes in the existing console, PDF/DOCX and ITSM reporting, the Maple Trust estate and the Evaluation Lab. Not adopted: the vanilla JS / Socket.IO / APEX rendering model, WARDEN branding, GitLab CI, live API pulls from CMDB and scanner products, and the Estate Map relationship graph. Taking any of those up needs a new ADR. Added since, outside rev 3: the Mission Control live view and the HUD theme (ADR-047), which is decorative and adds no relationship graph.

## 3. Required before any real use (P0)

| # | Item | Why it is open | Done when |
|---|---|---|---|
| P0-1 | Production sign-in (OIDC via BFF cookie, Keycloak or the customer IdP) | **Built (ADR-026)**: generic OIDC, role map, session expiry, revocable logout, RBAC tests on real tokens, all against a loopback mock IdP. **Pending:** register a client at the customer IdP and confirm its claim names, group mapping and logout (owner: platform admin; next step: IdP client registration) | Sign-in, role mapping and logout verified against the real IdP tenant using `docs/runbooks/sign-in.md` |
| P0-2 | Signing-key custody and rotation (OpenBao Transit or HSM) | **Built (ADR-027)**: Transit signer, local verification, revocation list, rotation drill passing on the loopback emulator (`key-rotation-drill.md`); local file keys stay the dev/test default. **Pending:** provision a real Transit key and app/admin tokens, then run the drill against it (owner: platform admin) | Drill passes against the real KMS; old manifests still verify via key ring |
| P0-3 | Egress enforcement at host or network level | **Built (ADR-028)**: scan zones enforced at preflight and dispatch, IdP endpoints bound to allowed hosts, nftables/iptables rules generated per role from settings, `egress_check verify` probe. **Pending:** load the rules on a real host and run `verify` with a deny canary (owner: platform admin) | `verify` passes on the API and worker hosts, with a canary that is reachable without the firewall being refused |
| P0-4 | Deployment: Dockerfiles/compose or native service units, Postgres, worker process | **Built (ADR-029)**: `deploy/` has backend and web images, compose, systemd units and an install runbook; bootstrap, doctor, `/readyz`, worker heartbeat and graceful shutdown. The API and worker are proven as live processes against Postgres, driving a run to REPORT_READY. The images are built and checked in CI (non-root user, security headers, valid compose). **Pending:** the clean-machine install on a host with Docker or systemd (owner: platform admin) | Clean-machine install from the runbook; API, worker and UI up; doctor/health checks green |
| P0-5 | First real CI run | **Built (ADR-030)**: five jobs (backend, web, e2e, deploy images, hygiene), SHA-pinned actions, read-only token, the drill and image checks added; actionlint and zizmor clean locally. **Done 2026-10-18:** all six jobs (a licence scan job was added by ADR-043) green on the [first run](https://github.com/ameyaraichur-lang/aisw/actions/runs/39111965433) from draft PR #1, with no workflow changes | All jobs green on GitHub Actions |
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
| A-1 | Data-handling approval for Astra (open item O3) covering real evidence | **Recorded PENDING** in the sign-off register (`astra-data-approval`; owner: product owner with the data protection officer). Until it is recorded, Astra may see synthetic data plus the redacted findings of the four 2026-10-18 live targets, under the product owner's scoped approval `product-owner-2026-10-18-live-local-targets-and-example-com`. Measured on those runs: 34 calls, 33 schema-valid, median latency 4.9 s; quality not scored ([record](live-validation/2026-10-18-live-runs.md)) |

## 5. Rev 3 scope adopted (ADR-046)

- ~~**Rest of the Astra validation pass:** a trigger policy file and an Engine-vs-Astra disagreement queue page.~~ **Done (ADR-036).** **Pending:** policy-owner sign-off of the sample trigger policy (`avp-triggers-1.0.0`).
- ~~**OPA + Rego bundles** for network, storage, logging/encryption, IAM, lifecycle, hardening and K8s RBAC, plus `opa test` in CI.~~ **Done (ADR-031).** Mappings and thresholds await policy-owner review (sign-off `config-baseline-1.0.0`).
- ~~**Framework mappings** (NIST CSF 2.0, CIS v8.1, 800-53r5, ATT&CK) with approval state, and a Control Matrix page.~~ **Done (ADR-032).** **Pending:** a policy owner reviews the 240 proposed mappings in each tenant (owner: policy owner; next step: work through the Control Matrix).
- ~~**Exceptions with expiry** (an expired exception becomes FAIL), plus review actions on findings (confirm, reject, request exception).~~ **Done (ADR-033).**
- ~~**Additional adapters:** Kubernetes (kubescape), firewall exports, LDAP/AD/IAM, NetBox/ServiceNow CMDB APIs, Trivy, Tenable/Qualys/Nessus imports.~~ **Done as file importers (ADR-034).** **Pending:** check each format against an export from the customer's real tool version (owner: platform admin; next step: upload one sanitised export per tool and compare with the fixture), and live API pulls if ever authorised.
- **UI pages:** ~~Asset Explorer~~ (done: `/assets`; the Estate Map relationship graph is not adopted, ADR-046), ~~Coverage Ledger view~~ (done: `/coverage`), ~~Exposure Scenarios chain view, Modernization Roadmap swimlanes~~ (done, ADR-035), ~~Assurance Console, Audit & Provenance with model-call ledger~~ (done, ADR-036: disagreement queue, trigger policy, ledger), ~~Evaluation Lab scorecard~~ (done, ADR-039).
- **Reporting:** ~~PDF/DOCX exports, control-gap matrix, architecture delta~~ **Done (ADR-038).** ~~ITSM draft delivery to Jira/ServiceNow~~ **Built (ADR-037):** renderers, Ticket Outbox page and two-person find-then-create delivery, tested against a loopback fake. **Pending:** sign-off `itsm-delivery` (owner: ITSM owner with the security programme lead; next step: approve a rendered payload, a create-and-search-only service account and the egress rule, then send a first ticket to a sandbox project).
- ~~**Maple Trust fixture estate** (~60 assets) and `scripts/eval_targets.py` scorecard against an answer key.~~ **Done (ADR-039)** as `tools/eval_targets.py`; results in `docs/implementation/eval-targets.md`. **Pending:** an answer key for each owner-supplied target (owner: product owner; next step: supply known issues and known-clean controls per target, §7.1).

## 6. Product and engineering gaps (P2)

| Area | Gap |
|---|---|
| Live validation (M9) | ~~Harness and authorisation gate~~ (done, ADR-045: the plan in `docs/implementation/live-validation/plan.json` lists `example.com` passive smoke, one bounded Nmap on `scanme.nmap.org` and ZAP against your own Juice Shop; `preflight` refuses any target without an approved, unchanged plan and an in-window authorisation; `evaluate` compares an exported report with the answer key; proven end to end on loopback). ~~First real targets~~ (done outside the harness, 2026-10-18: example.com, the local portal, this workstation and the base images, [record](live-validation/2026-10-18-live-runs.md)). **Pending:** a public-CA chain over a direct connection (example.com was TLS-inspected), and sign-off `live-validation` (owner: you, as the authorising party; next step: fill each target's authorisation block and expectations, re-check the scanme.nmap.org terms, point the Juice Shop selector at your instance, then record the decision with the plan's sha256) |
| Imports | ~~Upload/import-parameter UI; task dependency ordering~~ (done: review-step file pickers; inventory tasks run first, migration 0019); ~~real output for Nmap and Trivy~~ (done 2026-10-18 with Nmap 7.992 and Trivy 0.76.0; real Nmap XML exposed the DOCTYPE defect fixed in `fd4eba9`); real tool-version compatibility of the other importers |
| Analysis | ~~Real reachability for exposure scoring; graph/attack-path reasoning~~ (done, ADR-041: edges from host-firewall configuration and declared-vantage scans, exposure backed by stored edges, internet-to-asset path scenarios, migration 0022); cloud security-group attachment, rule shadowing and perimeter devices are not modelled; ~~separation of duties for recommendation decisions~~ (done: the run requester may only defer; migration 0018 enforces it) |
| Retention | ~~UI and scheduler~~ (done: Evidence Retention page; daily dry-run check with opt-in, two-sighting auto soft purge, migration 0020); quarantine deletion is manual. **Pending:** sign-off on enabling auto-execute (owner: retention owner; next step: approve `AISW_RETENTION_AUTO_EXECUTE=true` and the confirmation window per tenant) |
| Evidence | ~~Object-lock/WORM storage; externally witnessed audit-chain anchor~~ (done as seams with dev/test emulators: write-once replica, signed and witnessed hourly anchors, migration 0023, ADR-042). **Pending:** sign-offs `evidence-worm-storage` (owner: platform owner; next step: provision an Object Lock bucket in COMPLIANCE mode with a write-only role and agree retention) and `audit-anchor-witness` (owner: security programme lead; next step: choose an RFC 3161 TSA, a transparency log or a separate-account WORM bucket) |
| Events | ~~Silent-stall detection for an open but dead SSE stream (ADR-015)~~ (done: a client watchdog reopens the stream from the cursor after 30 s of silence) |
| Authorisation | ~~Per-project roles~~ (done, ADR-040: additive project grants for operator, approver, reviewer and report reader, migration 0021); tenant-wide lists still need a tenant role |
| URL probe | ~~IPv6-only, HTTP/2-only and proxy behaviour~~ (done on loopback: IPv6 pinning and fallback, HTTP/2-only reported as `HTTP2_ONLY_UNSUPPORTED`, environment proxies ignored by design, ADR-016). **Pending:** a public-CA target, part of live validation (M9) and needing your authorisation |
| Supply chain | ~~Syft/ScanCode SBOM; gitleaks~~ (done, ADR-043: CI cross-checks the lockfile SBOM against Syft image scans and ScanCode licence detection; gitleaks scans the full history; Syft and gitleaks run locally, ScanCode in CI only). Both green on the first CI run (2026-10-18). ~~Base images with critical and high vulnerabilities~~ (done 2026-10-19: `python:3.12.15-alpine3.24` and `nginxinc/nginx-unprivileged:1.30.6-alpine`, no critical or high in Trivy; IMG-1 passes, [record](live-validation/2026-10-18-live-runs.md)). **Pending:** the compose Postgres (`16.15-bookworm`) still has 4 critical and 95 high, 25 of them fixable only by a new upstream image (`gosu`); ~~no Trivy scan of the built images in CI~~ (done, ADR-048: fixable critical or high fails the `deploy` job, unfixed ones are reported); the base images' OS packages (38 apk in the backend, 70 apk in the web image, found by Syft) are not in the lockfile SBOM; signing of release artefacts |
| Scale | ~~Multi-node worker soak test~~ (done on one machine, ADR-044: worker processes killed at random; 120 of 120 runs, 28 kills, 9 tasks reclaimed, results in `soak.md`). **Pending:** workers on separate hosts, network partitions, and DoS sizing on the target hardware (owner: platform owner) |
| Accessibility | ~~Structural checks~~ (done: axe best-practice structure rules, heading order, one main landmark, a level-1 heading, content in landmarks, on all 29 scanned screens; two heading-order faults fixed on the run coverage and report tabs). Manual screen-reader pass: **Pending:** sign-off `accessibility-screen-reader` (owner: accessibility lead, ideally a daily screen-reader user; next step: run the 13 tasks in `docs/runbooks/accessibility-screen-reader.md` with VoiceOver and NVDA and record the results) |
| Hygiene | ~~Starlette `TestClient`/`httpx` deprecation warning in every test run~~ **Done:** the test client uses `httpx2`, as Starlette now requires |

## 7. Suggested sequence

1. ~~**Review and merge PR #1**~~ **Done 2026-10-19** (merge commit `48dac5d`; CI green on `main`).
2. **M9b: live validation**, one authorised target at a time (sign-off `live-validation`).
3. **M10: deployability** on real infrastructure (owner: platform admin): P0-1 IdP registration, P0-2 real KMS and rotation drill, P0-3 firewall rules on the hosts, P0-4 clean-machine install, then the write-once bucket and audit witness (§6 Evidence) and a soak across separate hosts (§6 Scale).
4. **M11: governance**: P0-6 rubric, catalog, baselines, AI evaluation bar and trigger policy; the framework mapping review; P0-7 licence review; A-1 Astra data approval; ITSM delivery and retention auto-execute.
5. **Engineering that needs no one else**, in parallel with the above:
   - persist the tool gateway's per-run quotas (concurrency and request budget). Today they are in memory per process, so several workers or a restart do not share them (`aisw/gateway/gateway.py`, `QuotaTracker`);
   - follow the compose Postgres image until its `gosu` and Debian issues are fixed upstream;
   - put the base images' OS packages into the SBOM and run the licence gate over them;
   - sign release artefacts (images and SBOMs);
   - importers for the storage, logging, TLS, hardening and lifecycle facts the Rego pack already has rules for;
   - reachability through cloud security groups, firewall rule shadowing and perimeter devices.

## 8. Open questions for the product owner

1. ~~Which plan governs (§2)?~~ **Decided:** this repository, rev 3 adopted item by item (ADR-046). The model may review agent outcomes, one-way and advisory only (ADR-021).
2. Who approves the Astra data boundary, and does it cover owner-supplied target evidence or synthetic data only? (Sign-off `astra-data-approval`; synthetic only until then.)
3. Which Astra deployments and API version should be the defaults? Today there is no built-in default deployment: enabling Astra requires naming one. The runbook recommends `gpt-6-astra` to write and `gpt-5.4` to review and as the fallback, and the API version defaults to `2025-04-01-preview`.
4. ~~GitHub Actions or GitLab CI as the system of record?~~ **Decided: GitHub Actions** (ADR-030).
5. Which targets, and in which windows, are authorised for M9? (Recorded in `docs/implementation/live-validation/plan.json`, approved through sign-off `live-validation`.)
