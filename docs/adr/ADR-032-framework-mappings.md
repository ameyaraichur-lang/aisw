# ADR-032: Curated framework mappings with per-tenant policy-owner review

**Status:** Accepted. Implemented. Every shipped mapping is a proposal (NEEDS_REVIEW) until a tenant's policy owner decides on it.

## Context
Packs name their own controls (`FB-1`, `CB-NET-1`, …). Only `config-baseline` carried mappings to external frameworks; every other pack had none. Nothing recorded whether a mapping had been checked. The rev 3 plan asks for NIST CSF 2.0, CIS v8.1, NIST SP 800-53 Rev. 5 and ATT&CK mappings with an approval state, and a Control Matrix page.

## Decision
- **One catalog**: `backend/aisw/policy/mappings/framework-mappings-1.0.0.json`.
  - Maps every control of every built-in pack to five frameworks: NIST CSF 2.0, CIS Controls v8.1, NIST SP 800-53 Rev. 5, ISO/IEC 27001:2022 Annex A, and MITRE ATT&CK Enterprise (the techniques a control helps mitigate).
  - The entries (227 at first, 240 after ADR-034 added the image-baseline controls) include every mapping that `config-baseline` embeds, so the two sources cannot disagree; a test enforces this.
  - `US-4` ("the endpoint answered") is deliberately unmapped: it is a reachability precondition, not a control.
  - Control titles are short paraphrases kept for display. Each framework's id format is checked when the catalog loads, so typos such as `SC7` or a CSF 1.1 id are refused.
- **Review state per tenant** lives in `framework_mapping_reviews` (migration 0013).
  - The table is append-only, under forced RLS, and a policy owner's change of mind is a new row; the latest row for a mapping wins.
  - The possible decisions are `APPROVED`, `REJECTED` and `NEEDS_REVIEW` (return to review).
  - Each decision needs a reason, which is redacted and capped at 1000 characters, and is written to the audit trail with before and after hashes. Repeating a decision is an idempotent replay.
  - Only `policy:approve`, which belongs to the `policy_owner` role, can decide.
- **Labels, not outcomes.** Approving a mapping changes how it is labelled and nothing else; control outcomes come only from policy evaluation. Even an approved mapping is not a statement of compliance, and both the catalog notice and the UI say so.
- **API.**
  - `GET /api/v1/control-matrix?run_id=…|policy_version=…` returns, for each pack control, its rules, its outcome in the run (absent when no run is given or it has not finished, never guessed), and its mappings with effective state. It also returns a summary count and whether the caller may review.
  - `POST /api/v1/framework-mappings/reviews` records a decision.
  - The finding detail response gains `framework_mappings` for the finding's control.
- **UI.** `/controls` becomes the Control Matrix.
  - Rows are controls; there is an outcome column when a run is selected, plus one column per framework.
  - Each mapping shows its state as icon plus label, never colour alone.
  - Policy owners get a review dialog that requires a reason; other roles see the state read-only.
  - The finding detail page lists the reviewed mappings for its control.
- A dev identity `paula` (policy owner) is added to the stub so the flow can be exercised locally.

## Consequences
- Review state is scoped to one catalog version. A new catalog version starts every mapping at NEEDS_REVIEW again, because the old decisions were about different text.
- Reports still carry the pack's own mappings and the `config-baseline-1.0.0` pending sign-off label. Report-level control-gap matrices are a later item (w3).

## Tests
- `tests/unit/test_framework_mappings.py`:
  - all five frameworks are present;
  - every pack control is mapped, except the documented exception;
  - the pack's embedded mappings appear in the catalog;
  - every title is used;
  - framework id formats are enforced;
  - duplicates and unknown controls are refused.
- `tests/integration/test_control_matrix.py`:
  - run outcomes are joined with mappings;
  - a pack can be browsed without a run;
  - only the policy owner can decide;
  - idempotent replay, 409 on an empty reset, and the latest decision wins;
  - the finding detail reflects decisions, and outcomes do not change;
  - decisions are audited;
  - rows are append-only and tenant-isolated;
  - validation and redaction;
  - an unfinished run shows no outcomes.
- `web/e2e/controls.spec.ts`: a policy owner approves or rejects a mapping through the dialog (a reason is required); a report reader sees the result read-only; axe finds no WCAG 2.2 AA violations on the page or the dialog.
