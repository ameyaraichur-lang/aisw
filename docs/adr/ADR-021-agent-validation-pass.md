# ADR-021: AI validation pass over agent outcomes (one-way, advisory)

**Status:** Accepted (post-M8). Amends ADR-018 ("a model only explains"): a model may now also *review* agent outcomes, under the rules below. Decided by the product owner on 2026-10-16 ("Astra should work on the agents, live integration").

## Context
ADR-018 limits the model to explaining scenarios and recommendations. The WARDEN rev 3 plan asks for an "Astra validation pass" in which a model reviews what each agent produced. A reviewer that can approve, re-score or add findings would make the model a decision maker and undo the evidence-first design, so the pass must be built so that it can only add caution.

## Decision
1. **What is reviewed.** After narratives are written in `ARCHITECTURE_ANALYSIS`, the worker builds review packets for Agents 1 to 7 and sends them to the model outside the run-row lock:
   - Agent 1: coverage ledgers.
   - Agents 2, 3 and 4: findings, assigned to an agent via evidence artifact, then task, then adapter.
   - Agent 5: scenarios.
   - Agent 6: recommendations.
   - Agent 7: the narratives that passed grounding.

   Agent 0 (scope gate) and Agent 8 (report) are not reviewed yet.
2. **What the model sees.** Each target carries deterministic fields plus, for findings, the observed and expected values of that finding's own rule. The rule is linked through the deterministic finding id, never through the shared evidence ref. Values are truncated to 300 characters and the whole packet is redacted. Evidence refs are shown as short ids (`E1`, `E2`, …) and mapped back before grounding, both in cited refs and in the prose a human reads. Raw evidence blobs are never sent.
3. **What the model may say.** Each target gets exactly one verdict: `CONCUR`, `CONCERN`, `DISSENT` or `INSUFFICIENT_EVIDENCE`. A verdict can carry at most 6 issues, with codes from a fixed list of 17, at most 3 human questions, and a confidence level. The schema forbids unknown fields, so a reply that tries to approve, re-score or call a tool fails validation.
4. **Deterministic grounding (any defect invalidates the whole reply).** A reply is rejected if it contains any of the following:
   - unknown or duplicate target refs;
   - `CONCERN` or `DISSENT` without an issue;
   - evidence refs not given for that target;
   - hidden or control characters;
   - commands (`PROHIBITED_ACTION`);
   - compliance claims;
   - any CVE, control, IP, URL, port or tier that is not in the packet.

   A rejected reply is stored as `VALIDATOR_INVALID`. Malformed or unreachable replies get one retry and then become `UNAVAILABLE`.
5. **Effects are code, one-way, and enforced twice.**
   - `DISSENT` → `HOLD_FOR_REVIEW`: an `ACCEPT` becomes `NEEDS_REVIEW` with the defect `AI_VALIDATOR_DISSENT`. This applies to findings, scenarios, recommendations and narratives.
   - `CONCERN` and `INSUFFICIENT_EVIDENCE` → `REVIEW_ITEM`: shown to reviewers; no change to any verdict.
   - `CONCUR` → `ANNOTATION`: no change.
   - `VALIDATOR_INVALID`, `UNAVAILABLE` and `NO_VERDICT` → no effect.

   No path moves anything toward `ACCEPT`. A database `CHECK` ties `DISSENT` to `HOLD_FOR_REVIEW` and forces the effect `NONE` for non-verdicts. A property test runs every assurance verdict against every reviewer verdict.
6. **Storage and provenance.** The `ai_validations` table (migration 0007) holds one row per target. It is append-only, uses forced row-level security per tenant, and the app role can only `SELECT` and `INSERT`. Each row records the model, prompt version (`agent-validation-1.0.0`), input and output hashes, and defects together with any injection flags. Every packet also writes an `llm_calls` row with purpose `validation:agent-N`.
7. **Separate reviewer deployment.** `AISW_ASTRA_VALIDATION_DEPLOYMENT`, for example `gpt-5.4`, sets the deployment that reviews; otherwise the generation deployment reviews its own work. The pass runs only when AI is enabled, the run was launched with `ai_assist`, and `AISW_AI_VALIDATION_ENABLED` is true (the default when AI is on). Tuning settings: `AISW_AI_VALIDATION_BATCH_SIZE` (12), `AISW_AI_VALIDATION_MAX_ITEMS_PER_AGENT` (60) and `AISW_AI_VALIDATION_CONCURRENCY` (4).
8. **Disclosure.** Validation is surfaced in several places:
   - The API endpoint `GET /api/v1/assessments/{run_id}/ai-validations` requires `finding:read` and labels every item `ai_generated`.
   - `GET /api/v1/agents` reports `ai_validated` per agent, plus `ai.validation_enabled` and `ai.validation_model`.
   - The run's Analysis tab has a panel, filtered to items needing attention by default.
   - The report gets a `ai.validation` summary, an HTML section, `model_versions`, and limitations stating how many items were held and how many could not be reviewed.

## Consequences
- With the pass off, unavailable or invalid, reports are identical to the deterministic ones (integration tests compare report shape).
- A model can now delay an item reaching the report until a human resolves it. That is the intended cost: false dissents create review work, never false acceptance.
- First live runs on 2026-10-16 (synthetic `baseline-ok` and `baseline-injection` fixtures, gpt-6-astra generating, gpt-5.4 reviewing):
  - **`baseline-ok`:** 9 targets in about 35 s, no dissents and no invalid replies once evidence aliases and per-rule observations were in place.
  - **`baseline-injection`:** the injected observation was held for review. The reviewer did not follow the planted instruction.
  - **Defects found in our own packets:** a shared-evidence observation mix-up and mistyped long evidence URIs, both fixed before this ADR. The reviewer also found an ambiguous Agent 6 `current_state` template, reworded to "requirement not met".
- Residual: a reviewer that CONCURs with everything adds nothing. Its value must be measured on a labelled set (pending plan A-8).

## Alternatives considered
- Letting the reviewer downgrade severity or close findings: makes the model a decision maker; rejected.
- Free-text review without issue codes: cannot be grounded or counted; rejected.
- Reviewing inside the locked transaction: blocks the run row on network calls; rejected, as in ADR-018.

> **Update (ADR-036):** which outcomes are reviewed is now decided by a versioned trigger policy rather than "every outcome up to the cap"; the cap still applies to what the policy selects.
