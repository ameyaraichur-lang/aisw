# ADR-023: Model-call routing: usage provenance, run budgets, failover, record/replay

**Status:** Accepted (post-M8). Extends ADR-018, ADR-020 and ADR-021. Decided by the product owner on 2026-10-16 as part of "go with all items".

## Context
Live Astra runs (ADR-020 and ADR-021) showed three gaps:
- Nothing recorded what a run cost or which deployment answered.
- One busy deployment failed every call in a run.
- Reproducing a live run, for evaluation or for a bug report, meant calling the model again.

A remote, metered model also needs a hard cap per run.

## Decision
All of the following are `ModelClient` wrappers, in `aisw/llm/routing.py`. None of them changes a prompt, adds a tool, or relaxes grounding.
1. **Usage provenance.**
   - Astra reports `usage.input_tokens` and `usage.output_tokens`; Ollama reports `prompt_eval_count` and `eval_count`. Bogus values are treated as unknown.
   - A `CallMeter` in each gateway sums tokens and latency over every attempt of a call. It records the deployment that served the call, which becomes `model_id`.
   - `llm_calls` gains the columns `input_tokens`, `output_tokens`, `latency_ms` and `replayed` (migration 0009).
   - `GET /assessments/{run_id}/model-calls` serves the ledger and its totals. It returns hashes only, never prompts or replies. The report carries `ai.usage`.
2. **Run budget.**
   - One `TokenBudget` per run is shared by narration and validation, and is thread-safe.
   - It starts from the live tokens the run has already recorded, so a repeated step cannot overspend.
   - A call is made only if its estimated prompt size, at about 4 characters per token rounded up, fits the remaining budget. A call that does not fit raises `MODEL_BUDGET_EXHAUSTED`; this is never retried and the item keeps its deterministic result.
   - Successful calls are charged their reported tokens, or a high estimate when the provider does not report usage. Failed calls are refunded. Replays are free.
   - The report states how many calls were refused.
3. **Failover.**
   - `AISW_ASTRA_FALLBACK_DEPLOYMENTS` forms a chain behind the primary deployment.
   - Only transient failures move to the next deployment: unreachable, 429, timeout and incomplete. A deployment that failed is skipped for a cooldown period, unless every deployment is cooling down.
   - Authentication failures, refusals, tool calls and unreadable replies are request-level failures and are final.
   - The validation chain excludes the generating deployment, so the reviewer never reviews its own output.
4. **Record and replay** (dev and test only; refused when `env=prod`).
   - `record` writes each successful reply under a SHA-256 of the exact request. Files are mode 0600 and contain the reply, never the prompt.
   - Per-run UUIDs are numbered by first appearance in the key, so the same fixture replays across runs.
   - `replay` answers only from the store and never constructs a network client, so it needs no key, endpoint or data approval. A miss is `REPLAY_MISS` and is not retried.
   - Replayed replies go through the full grounding of the current run, and the report states how many were replayed.

## Consequences
- The cost and the serving deployment of every AI-assisted run are auditable.
- A runaway run is bounded.
- One deployment outage degrades a run instead of disabling AI for it.
- Recorded live runs become deterministic regression fixtures, which feeds the labelled-set evaluation.
- Record mode keeps model replies on local disk. That is why it is unavailable in prod.

## Tests
- `tests/unit/test_model_routing.py` covers:
  - usage parsing for both providers, including bogus values;
  - meter totals;
  - failover rules, cooldown and the factory chain, including the reviewer exclusion;
  - record/replay: permissions, no prompts stored, keying and misses;
  - budget: refusal, charging, refunds, free replays and thread safety;
  - unsafe settings.
- `tests/integration/test_model_usage_pipeline.py` covers stored usage and the ledger, a half budget, a zero budget, and a recorded run replayed with an identical report.
