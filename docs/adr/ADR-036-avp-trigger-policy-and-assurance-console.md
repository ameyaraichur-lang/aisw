# ADR-036: AVP trigger policy and the Assurance Console

**Status:** Accepted. Implemented. The shipped policy is a sample awaiting policy-owner sign-off.

## Context
The AI validation pass (ADR-021) reviewed every outcome of every agent, up to a per-agent cap. The rev 3 plan (§3.3) asks for a versioned per-agent trigger policy ("validate if necessary"), configuration rather than code, with every trigger decision audited and the budget spent in priority order (A0 > A7 > A8 > A5 > A6 > the rest). It also asks for an Assurance Console with an engine-versus-AI disagreement queue, and for the model-call ledger to appear under Audit & Provenance.

## Decision
- **Policy file.** `backend/aisw/llm/policy/triggers-<version>.yaml`, selected by `AISW_AI_VALIDATION_TRIGGER_VERSION` (default `1.0.0`). It is validated strictly on load:
  - each rule has exactly one condition;
  - the policy covers agents 0–8 exactly once;
  - its sha256 is recorded with every decision.

  Conditions are `always`, `coverage_below`, `zero_asset_anomaly`, `source_failed`, `has_gaps`, `severity_at_least`, `outcome_in`, `tier_in` and `sample_rate`. Sampling hashes the policy version with the target reference, so a run always samples the same items.
- **Shipped rules (1.0.0):**
  - A0, A6, A7 and A8: always.
  - A1: coverage below 95%, a zero-asset anomaly, a failed source, or recorded gaps.
  - A2 and A3: high or worse, plus every not-applicable, unknown or error outcome.
  - A4: medium or worse.
  - A5: P0 and P1, plus a 20% sample of the rest.
- **Decisions are records.** Every outcome considered, triggered or skipped, is written to the append-only, RLS-forced `ai_validation_triggers` table (migration 0016) with its rule, policy version and hash. Decisions for A0–A6 are written in the locked transaction that builds the packets; decisions for A7–A8 are written with the results. Packets are sent in policy priority order.
- **Skipping never weakens assurance.** A skipped outcome is still checked by the deterministic validator (Agent 7). The AI reviewer can only add caution, so a narrower trigger can only mean fewer holds, never a weaker gate.
- **Assurance Console** (`/assurance`, needs `finding:read`):
  - `GET /api/v1/assurance/overview`: current deterministic verdicts per item kind, the top defect codes, AI verdict counts, open dissents, and triggered/skipped counts per agent.
  - `GET /api/v1/assurance/disagreements?state=open|resolved|notes|all`: each AI disagreement beside the current engine verdict. Only an unresolved DISSENT is resolvable, through the existing per-run resolution endpoint, so the existing separation and re-assessment rules (ADR-022) apply unchanged. Concerns and insufficient-evidence items are review notes.
  - `GET /api/v1/assurance/trigger-policy[?run_id]`: the active policy, its sign-off state, and a run's decisions.
- **Model-call ledger** (`/audit/model-calls`, needs `audit:read`): `GET /api/v1/model-calls` lists calls tenant-wide with filters and totals. It returns hashes, tokens, latency and outcomes, never prompts or replies.
- **Sign-off.** The policy is registered as `avp-triggers-1.0.0` (PENDING, P0-6, owner: policy owner with the AI governance lead) and labelled as a sample in the console until it is approved.

## Consequences
- AI validation on a clean fixture run now reviews fewer items (for example, a medium host finding and full coverage are skipped). Tests that need every kind reviewed pass an explicit "always" policy to the worker.
- Call volume and cost under the policy are still to be measured on owner-supplied targets before the sign-off.
- Tests:
  - `tests/unit/test_trigger_policy.py`
  - `tests/integration/test_ai_validation_pipeline.py`
  - `tests/integration/test_assurance_console.py`
  - `tests/integration/test_migrations.py`
  - `web/e2e/assurance.spec.ts`
