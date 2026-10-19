# ADR-022: Human resolution of AI validator dissents via assurance and report revisions

**Status:** Accepted (post-M8). Completes ADR-021, whose `DISSENT` effect holds an item "until a human resolves it". Decided by the product owner on 2026-10-16 as part of "go with all items".

## Context
Under ADR-021 a `DISSENT` turns an accepted item into `NEEDS_REVIEW` and keeps it out of the report. Until now nothing could release the hold, so one wrong dissent removed a correct finding from the report for good. Assurance results and reports are append-only (ADR-019), so releasing a hold cannot mean editing the stored verdict or the stored report.

## Decision
1. **Who decides.** `POST /api/v1/assessments/{run_id}/ai-validations/resolutions` with `{target_ref, decision, reason}`. It requires `report:approve`. The run's requester cannot resolve its dissents, which is the same separation of duties as report approval. The reason is required; it is redacted and capped at 1000 characters.
2. **When.** Only a `DISSENT` can be resolved. It must be resolved while the run is `REPORT_READY` or `PARTIAL` and its latest report is `PENDING`. After approval the report is final, so any further resolution returns 409.
3. **Decisions.**
   - `UPHOLD` records agreement with the reviewer. The item stays held and the report does not change.
   - `OVERRULE` removes this dissent from assurance input. It increments `assessment_runs.assurance_revision` and returns the run to `ASSURANCE`. The worker then re-runs assurance at the new revision. The model is not called again. The item becomes `ACCEPT` only if its evidence still holds, because overruling a dissent never accepts an item directly.
4. **Revisions, not rewrites.**
   - `assurance_results` is keyed by `(run_id, item_ref, revision)`, and every read uses the run's current revision.
   - Each re-run writes a new report revision, `rep-{run}-r{n}`, which records the report it `supersedes`.
   - The previous `PENDING` report is marked `SUPERSEDED`, which is the only change made to it. It can no longer be approved, and it stays readable as history.
   - Each report's limitations and HTML banner disclose the revision and the number of dissents overruled and upheld.
5. **Record.**
   - `ai_validation_resolutions` is append-only, has forced RLS, and has one row per dissent. A replay of the identical decision is idempotent; a different decision returns 409.
   - Every decision writes an audit event: `ai_validation.overrule` or `ai_validation.uphold`.
   - An overrule also appends a `phase.changed` event with reason `AI_DISSENT_OVERRULED`.

## Consequences
- A wrong dissent costs one human decision and one deterministic re-run, not a lost finding.
- Report approval can now race only against a newer revision. Approving the superseded report fails because it is no longer `PENDING`. While the run is reassessing, approval fails because the run is not awaiting approval.
- Migration `0008` reverses cleanly; its downgrade deletes the revision > 1 rows.

## Tests
- `tests/integration/test_dissent_resolution.py` covers:
  - overrule, then a new revision that supersedes the old report and can be approved;
  - uphold, which leaves the report unchanged;
  - idempotent replay, and 409 on a conflicting decision;
  - RBAC and separation of duties;
  - 409 for a non-dissent target or an approved report;
  - redaction of the reason;
  - append-only rows and tenant isolation.
- `tests/integration/test_migrations.py` covers the 0008 downgrade.
- `web/e2e/dissent.spec.ts` drives the UI end to end against a local scripted reviewer and includes an axe check of the decision dialog.
