# Sign-off register

Generated from `backend/aisw/policy/signoffs.json` by `tools/signoffs.py`; do not edit.

While an item is PENDING, the product keeps the label shown here. A decision needs the
decider, the date, a reference and the sha256 of the exact artefact; changing the artefact
afterwards fails the check until a new decision is recorded.

| Id | Plan | Subject | Owner | Status | Shown while pending | Next step |
|---|---|---|---|---|---|---|
| `risk-rubric-1.0.0` | P0-6 | Risk rubric 1.0.0: severity, criticality and exposure weights and the P0-P2 thresholds (`backend/aisw/policy/rubrics/risk-rubric-1.0.0.json`) | Policy owner (role policy_owner) | PENDING | Risk tiers come from a sample rubric awaiting policy-owner approval; treat them as indicative. | Policy owner reviews the weights and thresholds against a reviewed sample of real findings, then records the decision here or publishes an adjusted rubric version. |
| `architecture-catalog-1.0.0` | P0-6 | Architecture catalog 1.0.0: target patterns used for recommendations (`backend/aisw/policy/catalogs/architecture-catalog-1.0.0.json`) | Policy owner with the customer's enterprise architect | PENDING | Recommendation patterns come from a sample catalog, not the customer's approved reference architecture. | Replace or confirm each pattern against the customer's reference architecture; an approved catalog is published as a new version with status APPROVED. |
| `config-baseline-1.0.0` | P0-6 | Config baseline 1.0.0: Rego domain rules, thresholds and their NIST SP 800-53 / ISO 27001 / CIS v8 mappings (`backend/aisw/policy/packs/config-baseline-1.0.0.json`) | Policy owner with the compliance lead | PENDING | Framework mappings are proposals awaiting review; a mapping is not a statement of compliance. | Compliance lead confirms or corrects each mapping and threshold; approved mappings are marked APPROVED in a new pack version. |
| `image-baseline-1.0.0` | P0-6 | Image baseline 1.0.0: container image vulnerability and base-OS support rules over Trivy reports (`backend/aisw/policy/packs/image-baseline-1.0.0.json`) | Policy owner with the platform security lead | PENDING | Container image thresholds are a synthetic baseline; any critical or high vulnerability fails, with or without a fix. | Platform security lead decides whether unfixed vulnerabilities and which severities fail an image; the agreed thresholds ship as a new pack version marked APPROVED. |
| `ai-evaluation-bar` | P0-6 | Acceptance bar for the AI reviewer and narrator (recall, false-dissent rate, narrative acceptance) (`backend/aisw/llm/evaluation.py`) | Policy owner with the security lead | PENDING | The evaluation bar is provisional; meeting it on the synthetic labelled set is not an approval. | Agree the thresholds and a labelled set drawn from reviewed real findings (needs the data approval below), then record the decision. |
| `avp-triggers-1.0.0` | P0-6 | AI validation pass trigger policy: which agent outcomes the reviewer model checks, and in what budget order (`backend/aisw/llm/policy/triggers-1.0.0.yaml`) | Policy owner with the AI governance lead | PENDING | Sample trigger policy: skipped outcomes are still checked by the deterministic validator, but the review scope has not been approved. | Review the per-agent rules and the 20% scenario sample against measured call volume and cost on owner-supplied targets, then record the decision bound to the file hash. |
| `licence-review` | P0-7 | Licence review: LGPL psycopg/psycopg-binary at runtime, MPL dev tools, three packages without licence metadata (`docs/implementation/sbom/licence-policy.json`) | Named legal reviewer | PENDING | Licence acceptances are engineering positions, not legal advice; no external redistribution until reviewed. | Legal reviewer confirms or changes each acceptance in licence-policy.json, then records the decision here. |
| `astra-data-approval` | A-1 | Data-handling approval for sending redacted real evidence to Astra (open item O3) (`docs/adr/ADR-020-astra-remote-model-provider.md`) | Product owner with the data protection officer | PENDING | Astra may be used on synthetic fixtures, and on redacted findings from the four live targets of 2026-10-18 under the product owner's scoped approval; any other real evidence needs this approval. | Data protection review of what leaves the host (redacted findings, no raw evidence) and of the Azure tenant's retention terms; record the approval reference here and in AISW_ASTRA_DATA_APPROVAL_REF. |
| `itsm-delivery` | R3-ITSM | Ticket delivery to the customer's Jira or ServiceNow: field mapping, service account and egress rule (`docs/adr/ADR-037-itsm-ticket-rendering-and-delivery.md`) | ITSM owner with the security programme lead | PENDING | Delivery is off; tickets are drafts that can be previewed for Jira or ServiceNow. Delivery is tested against a loopback fake only. | ITSM owner approves a rendered payload and a create-and-search-only service account; network owner approves the itsm egress destination; first ticket created in a sandbox project per docs/runbooks/itsm-delivery.md. |
| `retention-auto-execute` | E-Retention | Automatic soft purge by the scheduled retention check: tenants, confirmation window and quarantine handling (`docs/runbooks/evidence-retention.md`) | Retention owner (records management) with the security programme lead | PENDING | Auto-execute is off; the daily check only records the dry-run plan and a retention manager executes a reviewed plan. | Retention owner approves AISW_RETENTION_AUTO_EXECUTE=true per tenant and the AISW_RETENTION_CONFIRM_HOURS window, and names who removes quarantined files and when, per docs/runbooks/evidence-retention.md. |
| `evidence-worm-storage` | E-Evidence | Write-once (Object Lock, COMPLIANCE mode) replica of all evidence and its retention period (`docs/runbooks/evidence-integrity.md`) | Platform owner with the retention owner | PENDING | Evidence has a single mutable copy in production; the write-once replica runs only as a dev/test emulator. | Platform owner provisions an Object Lock bucket in COMPLIANCE mode with a write-only platform role and no governance bypass, agrees the retention period with the retention owner, and implements the ObjectLockBackend, per docs/runbooks/evidence-integrity.md. |
| `audit-anchor-witness` | E-Evidence | External witness for signed audit-chain anchors (`docs/runbooks/evidence-integrity.md`) | Security programme lead | PENDING | The audit chain is verified only against itself in production; anchors run only with the dev/test local-file witness. | Security programme lead chooses the witness (RFC 3161 timestamp authority, transparency log, or object-lock bucket in a separate account), the Witness backend is implemented and aisw-anchor.timer is enabled, per docs/runbooks/evidence-integrity.md. |
| `live-validation` | M9 | Authorisation to validate against the real targets in the M9 plan, with their windows and expected outcomes (`docs/implementation/live-validation/plan.json`) | Product owner (the user) with the security programme lead | PENDING | The harness refuses every target in the M9 plan; real targets have been contacted only by the product owner's live runs of 2026-10-18, outside the harness. | Product owner fills each target's authorisation (who, reference, window), re-checks the scanme.nmap.org terms, replaces the Juice Shop selector with an owned instance, records expected outcomes, then records the decision with the plan's sha256, per docs/adr/ADR-045-live-validation-harness.md. |
| `accessibility-screen-reader` | E-Accessibility | Manual screen-reader pass (VoiceOver and NVDA) over the console's main tasks (`docs/runbooks/accessibility-screen-reader.md`) | Product owner with an accessibility tester | PENDING | Accessibility is checked automatically only (axe WCAG 2.2 AA and structural rules, keyboard and reduced-motion tests). | An accessibility tester runs the 13 tasks in docs/runbooks/accessibility-screen-reader.md with VoiceOver and NVDA, records results in docs/implementation/accessibility-screen-reader-results.md, and the product owner records the decision once every FAIL is fixed or owned. |

## Engineering reviews

Prepared by engineering so each decider can decide quickly. A review is not a decision:
it does not change the status or remove a label, and it goes stale when the artefact
changes. Readiness says whether a decision can be made now, not which way to decide.

### `risk-rubric-1.0.0`: not ready: a prerequisite is missing

The rubric works as designed, but its own description requires calibration on a reviewed sample of real findings before the tiers mean anything, and no such sample exists yet.

Reviewed by Engineering (prepared with an AI coding agent for ameyar) on 2026-10-19; artefact sha256 `759430adc4d00cf4f6431917902610f1da0893d4e713e138c2b137f8f8875aee`.

Evidence:

- Additive weights: severity 0-4, owner-supplied criticality 0-3, exposure 0-2; P0 at 8 or more, P1 at 6, P2 at 4. A business tier is produced only when criticality is known; otherwise the result is NEEDS_POLICY_REVIEW.
- Scoring and the pending label in reports are unit-tested (`tests/unit/test_rubric.py`, `tests/unit/test_signoffs.py`).
- The only real findings so far come from the 2026-10-18 live runs (`docs/implementation/live-validation/2026-10-18-live-runs.md`).

Open before a decision:

- A reviewed sample of real findings with owner-supplied criticality, scored and compared with the tiers the reviewers expect.

### `architecture-catalog-1.0.0`: not ready: a prerequisite is missing

The catalog is a sample of 10 patterns; approving it needs the customer's reference architecture, which engineering does not have.

Reviewed by Engineering (prepared with an AI coding agent for ameyar) on 2026-10-19; artefact sha256 `d55d16974caf8bd100f6ece99bbb49c6faf097e54233dd2ed52db3926eebeb1f`.

Evidence:

- 10 entries, status `SAMPLE_NEEDS_OWNER_REVIEW`.
- Reports and the console show the sample-catalog label while this is pending (`tests/unit/test_signoffs.py`).

Open before a decision:

- The customer's reference architecture, so each pattern can be confirmed, replaced or dropped and a new catalog version published.

### `config-baseline-1.0.0`: ready for a decision, with conditions

The compliance lead can review the rules and mappings now, but several rule families have no importer feeding them real facts yet.

Reviewed by Engineering (prepared with an AI coding agent for ameyar) on 2026-10-19; artefact sha256 `6821c0453f350268c69e2832efce0fac1be54a19a965694c3fca0abefdc3b361`.

Evidence:

- 20 rules across data protection, encryption, host configuration, identity, Kubernetes RBAC, lifecycle, logging and network exposure, with 67 framework mappings in the pack.
- Rules are evaluated by OPA, and `opa test` runs in CI (ADR-031).
- Real input so far is Nmap and Trivy output only; the other importers are tested on synthetic fixtures.

Open before a decision:

- The compliance lead confirms or corrects each of the 67 mappings and each threshold.
- Importers for storage, logging, TLS, hardening and lifecycle facts are not built, so those rules have not seen real data (pending plan, section 7).

### `image-baseline-1.0.0`: ready for a decision, with conditions

Both rules behave correctly on real Trivy reports. The decision left is how to treat vulnerabilities that have no fix: today any critical or high fails, fixed or not.

Reviewed by Engineering (prepared with an AI coding agent for ameyar) on 2026-10-19; artefact sha256 `e0794620d8667224936384cdf0018c30dabf23c74d10ce1964f0c3c563a5287e`.

Evidence:

- IMG-1 failed on the old base images (2026-10-18) and passes on the current ones (2026-10-19); IMG-2 passed on both (`docs/implementation/live-validation/2026-10-18-live-runs.md`).
- On 2026-10-19 `python:3.12.15-slim-trixie` had 44 high vulnerabilities, none with a Debian fix; under this rule it fails although nothing can be patched.

Open before a decision:

- Choose: keep failing on unfixed critical and high (each then needs an owned exception), or fail only when a fix exists and report unfixed ones separately. Ship the choice as a new pack version.

### `ai-evaluation-bar`: not ready: a prerequisite is missing

The provisional bar is met on synthetic cases only. Agreeing it needs a labelled set drawn from reviewed real findings, which in turn needs the Astra data approval.

Reviewed by Engineering (prepared with an AI coding agent for ameyar) on 2026-10-19; artefact sha256 `30fc6800689575d9aa515c128ff570e87127100ff5815bb9efa8a27e54bc936e`.

Evidence:

- Provisional bar in `evaluation.py`: recall at least 0.7, false-dissent rate at most 0.1, unscored at most 0.1.
- Synthetic labelled set of 24 review and 5 narrative cases: recall 1.0, false dissent 0, 5 of 5 narratives accepted on the third live run (ADR-025).
- Live runs of 2026-10-18: 34 model calls, 33 schema-valid; quality not scored.

Open before a decision:

- `astra-data-approval`, then a labelled set drawn from reviewed real findings.

### `avp-triggers-1.0.0`: ready for a decision, with conditions

The policy can only add caution, and every skipped outcome is still checked by the deterministic validator. Its cost has been measured only on four small runs.

Reviewed by Engineering (prepared with an AI coding agent for ameyar) on 2026-10-19; artefact sha256 `2506ddde3f753c08f10336aadd270f4def786f6011354cbcc44a05e6c4d9b183`.

Evidence:

- Agents 0, 6, 7 and 8 are always reviewed; agents 1 to 4 on coverage gaps, failed sources, findings above a severity floor (high, or medium for exposure) and unknown outcomes; agent 5 on P0 and P1 scenarios plus a deterministic 20% sample.
- Every trigger decision is stored per run, and a per-run token budget caps spend (ADR-023, ADR-036).
- Four live runs of 2026-10-18: 34 calls, median latency 4.9 s.

Open before a decision:

- Call volume and cost on an owner-supplied target of realistic size.

### `licence-review`: ready for a decision, with conditions

The application's dependencies are ready for legal review. The container images' operating-system packages are outside the licence gate and need the same review before images are distributed.

Reviewed by Engineering (prepared with an AI coding agent for ameyar) on 2026-10-19; artefact sha256 `c452da2dc0a54527b4461ca113ac9027aca191814415a79c5738dbb3cc91f215`.

Evidence:

- Runtime copyleft: psycopg and psycopg-binary (LGPL-3.0-only), used unmodified as replaceable packages; psycopg-binary bundles libpq.
- MPL-2.0 items (pathspec, certifi, axe-core, @axe-core/playwright, lightningcss) are development, test or build tooling and are not shipped.
- Packages without readable licence metadata: pgserver (development), colorama, tzdata (Windows only) and httpx2-jsfetch (Pyodide only).
- ScanCode in CI reads the licence text of runtime components and denies nothing (ADR-043).

Open before a decision:

- Base-image OS packages: 85 Alpine packages across the two images (Syft, 2026-10-19), including BusyBox (GPL-2.0), are not in the gate.
- Redistribution obligations for the LGPL packages (notices, ability to replace the library) in the packaging.

### `astra-data-approval`: ready for a decision, with conditions

The engineering controls this decision relies on are built and documented. The data protection officer still needs the Azure tenant's terms, and the development key needs rotating.

Reviewed by Engineering (prepared with an AI coding agent for ameyar) on 2026-10-19; artefact sha256 `9bd78b2aef24e701ce80f2fb25554294ea113d6a133ab7580a552de7fe6cfdb7`.

Evidence:

- Only a redacted, whitelisted projection of findings is sent; raw evidence does not leave the host (ADR-020).
- The platform refuses to start with Astra enabled unless `AISW_ASTRA_DATA_APPROVAL_REF` names an approval.
- Every call is recorded with deployment, usage and latency in the model-call ledger, readable by auditors (ADR-023).
- Real use so far: redacted findings of the four 2026-10-18 live targets under the product owner's scoped approval, 34 calls.

Open before a decision:

- Azure tenant retention and abuse-monitoring terms for the deployment, reviewed by the data protection officer.
- Rotate the development API key before real evidence is sent (open since 2026-10-16).

### `itsm-delivery`: ready for a decision

Rendering and delivery are built and tested against a loopback fake. What remains is on the ITSM owner's side: approving a payload, a service account and an egress rule.

Reviewed by Engineering (prepared with an AI coding agent for ameyar) on 2026-10-19; artefact sha256 `e15dce396d943c5e0a37a240bb7372e82c4932de2e055f6e215ec4b15593490f`.

Evidence:

- Jira and ServiceNow renderers, the Ticket Outbox page and two-person find-then-create delivery (ADR-037).
- Delivery is off by default and has only been exercised against a loopback fake.

Open before a decision:

- After approval, a first ticket in a sandbox project per `docs/runbooks/itsm-delivery.md`.

### `retention-auto-execute`: ready for a decision, with conditions

Automatic purge only moves files to quarantine, and only after the same plan has been seen across the confirmation window. The restore path has not been exercised on a live system.

Reviewed by Engineering (prepared with an AI coding agent for ameyar) on 2026-10-19; artefact sha256 `4d349af3d6b14a86733a3ddea6e1822e3c526cdd6254db588015b689292854f3`.

Evidence:

- The platform never deletes: purge moves blobs to quarantine, and final deletion is a manual, ticketed action.
- Each scheduled check records its dry-run plan; any hold, release or newly eligible run changes the plan hash and restarts the window.

Open before a decision:

- Restore from quarantine is marked unverified live in the runbook; rehearse it once before enabling.
- Name who removes quarantined files, and when.

### `evidence-worm-storage`: not ready: a prerequisite is missing

Only the dev/test emulator exists; there is no Object Lock backend to approve yet.

Reviewed by Engineering (prepared with an AI coding agent for ameyar) on 2026-10-19; artefact sha256 `6a2f1cfed4f756cee7dc48e5f2820503f4c6cfe9f668bf3ea8a2853e31d5dbfc`.

Evidence:

- `ObjectLockBackend` is an interface in `aisw/evidence/worm.py`, exercised only with an emulator (ADR-042).

Open before a decision:

- Provision an Object Lock bucket in COMPLIANCE mode with a write-only role, agree the retention period, and implement the backend.

### `audit-anchor-witness`: not ready: a prerequisite is missing

Only the local-file witness exists. The witness can be chosen now; operating it needs an implementation.

Reviewed by Engineering (prepared with an AI coding agent for ameyar) on 2026-10-19; artefact sha256 `6a2f1cfed4f756cee7dc48e5f2820503f4c6cfe9f668bf3ea8a2853e31d5dbfc`.

Evidence:

- `Witness` is an interface in `aisw/core/anchor.py`; the only implementation is `LocalFileWitness`, for dev and test (ADR-042).

Open before a decision:

- Choose an RFC 3161 timestamp authority, a transparency log or a separate-account write-once bucket; then implement it and enable `aisw-anchor.timer`.

### `live-validation`: not ready: a prerequisite is missing

No target in the plan has an authorisation block yet, and the Juice Shop selector is a placeholder.

Reviewed by Engineering (prepared with an AI coding agent for ameyar) on 2026-10-19; artefact sha256 `70c101ee32b111305dfcf07e19d3e1302ea0ac3236bcfb1632a4891a9e34d45b`.

Evidence:

- Three targets: example.com passive smoke, a bounded Nmap of scanme.nmap.org and a ZAP baseline of Juice Shop; each has `authorisation: null`.
- The Juice Shop selector is `http://juice-shop.invalid:3000/`.
- The harness refuses every target until this sign-off approves the plan's exact hash (ADR-045).

Open before a decision:

- Fill each target's authorisation (who, reference, window) and expected outcomes.
- Re-check the scanme.nmap.org terms, and point Juice Shop at an instance you own.

### `accessibility-screen-reader`: not ready: a prerequisite is missing

The manual pass has not been run, so there are no results to decide on.

Reviewed by Engineering (prepared with an AI coding agent for ameyar) on 2026-10-19; artefact sha256 `fbc35ded2a079ff3e52be4b973b292dc5d009056ffff1f8827af6cba85db7ec7`.

Evidence:

- Automated checks pass: axe WCAG 2.2 AA and structural rules on every scanned screen, plus keyboard and reduced-motion tests.
- `docs/implementation/accessibility-screen-reader-results.md` does not exist yet.

Open before a decision:

- An accessibility tester runs the 13 tasks with VoiceOver and NVDA and records the results.
