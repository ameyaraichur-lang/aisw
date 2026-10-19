# Enabling and disabling AI

AI is **off by default** and is not needed for any decision. A model writes optional explanations of scenarios and recommendations and, when enabled, reviews agent outcomes; it can only hold items for human review ([ADR-021](../adr/ADR-021-agent-validation-pass.md)). Deterministic checks decide what is shown. **No model weights are bundled or downloaded by this repository.** Astra has been run live on synthetic fixtures (2026-10-16), and on the redacted findings of four real targets under a scoped product-owner approval (2026-10-18, [record](../implementation/live-validation/2026-10-18-live-runs.md)); no local model has been run.

Two providers exist (`AISW_MODEL_PROVIDER`): `ollama`, a local runtime on loopback (default), and `astra`, the Astra / Azure OpenAI Responses API (remote, [ADR-020](../adr/ADR-020-astra-remote-model-provider.md)).

## Local model (`ollama`)

### Before enabling (all required)
1. A model whose **weights licence** you have reviewed (record the SPDX id). The runtime's licence (e.g. Ollama) is separate.
2. A local runtime listening on loopback only. The platform refuses any other endpoint.
3. A person accepts that output quality and latency are **unverified** until you run the evaluation checks below on your model.

### Enable
Set `AISW_AI_ENABLED=true`, `AISW_MODEL_ID`, `AISW_MODEL_LICENSE`, optionally `AISW_MODEL_ENDPOINT` (default `http://127.0.0.1:11434`) and the two feature flags `AISW_AI_NARRATIVE_ENABLED` / `AISW_AI_ARCHITECTURE_ENABLED`. Startup fails if the model id or licence is missing. A run uses AI only when the launch request sets `ai_assist: true`.

## Astra (`astra`)

Redacted, whitelisted findings (titles, categories, severities, asset ids, evidence refs, control ids and deterministic text; never raw evidence) are sent to Azure. Treat this as data leaving the host.

### Before enabling (all required)
1. A recorded **data-handling approval** for sending that projection to the Astra resource (synthetic data only until the approval covers real evidence).
2. An Astra deployment name and the resource endpoint, which must be an `https` origin on `*.openai.azure.com`, `*.cognitiveservices.azure.com` or `*.services.ai.azure.com` (no path, port 443).
3. The API key in your secret provider, injected as an environment variable. Never put it in `.env.example`, a commit, a ticket or a chat.
4. Outbound https to that host, either direct or through one explicit proxy (`AISW_ASTRA_PROXY=http://<proxy>:<port>`, ADR-025). The client ignores `HTTPS_PROXY`/`HTTP_PROXY` and never follows redirects. With a proxy, it opens a CONNECT tunnel to the Azure host, so TLS is end to end and the proxy never sees the key or the prompt. Proxy credentials, paths and link-local addresses are refused. Allow only that proxy in the egress rules.

### Enable
```bash
AISW_AI_ENABLED=true
AISW_MODEL_PROVIDER=astra
AISW_MODEL_ID=<deployment name>
AISW_ASTRA_ENDPOINT=https://<resource>.openai.azure.com
AISW_ASTRA_API_VERSION=2025-04-01-preview      # default; must match a Responses API version on your resource
AISW_ASTRA_API_KEY=<from the secret provider>
AISW_ASTRA_DATA_APPROVAL_REF=<approval id>
# optional: AISW_ASTRA_MAX_OUTPUT_TOKENS=2048, AISW_MODEL_TIMEOUT_SECONDS=60
```
Startup fails if any required value is missing, the approval reference is blank, or the endpoint is not an Azure OpenAI origin. `GET /api/v1/agents` then reports `ai.provider = "astra"` and `endpoint_local_only = false`, and the Architecture workbench says that findings leave the host.

### Failure codes recorded in `llm_calls.defects`
`MODEL_AUTH_FAILED` (401/403, not retried: fix the key or role), `MODEL_RATE_LIMITED` (429, retried once), `MODEL_UNREACHABLE`, `MODEL_TIMEOUT`, `MODEL_REFUSED`, `MODEL_RESPONSE_INCOMPLETE` (raise `AISW_ASTRA_MAX_OUTPUT_TOKENS`), `MODEL_RESPONSE_UNREADABLE`, `MODEL_RESPONSE_TOO_LARGE`, `MODEL_TOOL_CALL_REFUSED`. In every case the deterministic report is unchanged.

## Agent validation pass (ADR-021)
On by default when AI is enabled (`AISW_AI_VALIDATION_ENABLED=false` turns it off). It runs only for runs launched with `ai_assist: true`. Set `AISW_ASTRA_VALIDATION_DEPLOYMENT` to have a different deployment review than the one that writes (recommended: `gpt-5.4` reviewing `gpt-6-astra`).

Verdicts and what they do:

| Verdict | Effect |
|---|---|
| `DISSENT` | The item is held for review: an accepted item becomes `NEEDS_REVIEW` (defect `AI_VALIDATOR_DISSENT`) and leaves the report until a human resolves it |
| `CONCERN`, `INSUFFICIENT_EVIDENCE` | A review note; nothing changes |
| `CONCUR` | An annotation; nothing changes |
| `VALIDATOR_INVALID` (the reply failed grounding), `UNAVAILABLE` | No effect; the report limitations count them |

Read the results on the run's Analysis tab, from `GET /api/v1/assessments/{run_id}/ai-validations`, or in the `ai_validations` and `llm_calls` tables (`purpose LIKE 'validation:%'`). Many dissents on findings that are clearly correct mean the reviewer is not usable for this estate; turn it off and record why.

### Cost, failover and replay (ADR-023)

- **Usage.** Every model call records:
  - the deployment that served it;
  - the input and output tokens the provider reported;
  - the latency summed over all attempts;
  - whether it was replayed.

  Read this from `GET /api/v1/assessments/{run_id}/model-calls`. It returns hashes and costs only, never prompts or replies. The report's `ai.usage` block carries the same totals.
- **Trigger policy.** `AISW_AI_VALIDATION_TRIGGER_VERSION` (default `1.0.0`) selects `backend/aisw/llm/policy/triggers-<version>.yaml`, which decides which agent outcomes the reviewer checks and the order packets are sent in under a budget. Every decision, including skips, is stored in `ai_validation_triggers` and shown on the Assurance Console (ADR-036). The shipped policy is a sample awaiting policy-owner sign-off.
- **Budget.** `AISW_AI_RUN_TOKEN_BUDGET` (default 200000; 0 means no limit) caps the live tokens one run may spend. Narration and validation share the budget, including calls made concurrently.
  - A call whose prompt would not fit is not made. It is recorded with the defect `MODEL_BUDGET_EXHAUSTED` and is not retried. That item keeps its deterministic result.
  - The report states how many calls were refused.
  - Tokens already spent by an earlier attempt of the same step still count against the budget.
- **Failover.** `AISW_ASTRA_FALLBACK_DEPLOYMENTS` lists deployments to try, in order, when a call fails transiently (unreachable, 429, timeout, incomplete).
  - A deployment that failed is skipped for `AISW_ASTRA_FAILOVER_COOLDOWN_SECONDS`.
  - Authentication failures, refusals and unreadable replies never fail over.
  - The reviewer never fails over to the generating deployment (`AISW_MODEL_ID`).
- **Record and replay** (dev and test only).
  - `AISW_AI_REPLAY_MODE=record` stores each reply in `AISW_AI_REPLAY_DIR`, as mode-0600 files keyed by a hash of the request. Prompts are not stored.
  - `replay` answers only from that store and never builds a network client, so it needs no key or data approval. A miss is `REPLAY_MISS`.
  - Per-run ids are normalised in the key, so the same fixture replays across runs. Every replayed reply still passes full grounding.
  - The report states how many replies were replayed.

**Resolving a dissent (ADR-022).** A reviewer with `report:approve` who did not request the run opens the run's Analysis tab and chooses **Overrule** or **Uphold** on a dissent row, giving a reason. The API equivalent is `POST /api/v1/assessments/{run_id}/ai-validations/resolutions`.
- **Uphold** keeps the item held and leaves the report unchanged.
- **Overrule** re-runs assurance without that dissent and issues a new report revision (`rep-{run}-r2`, …). The old pending report becomes `SUPERSEDED`. Approve the newest revision.

Both decisions are final and audited. Resolve every dissent before approving, because an approved report cannot be revised.

### Agents 0, 4 and 8 (ADR-024)
- **Scope review (Agent 0).** The reviewer reads the signed scope against what actually ran. A dissent on `scope:…` is a review note. It never holds the report, and overruling it records the decision without a new revision. Treat a `SCOPE_TOO_BROAD` or `SCOPE_INCONSISTENT` note as input to the next manifest, not to this report.
- **Owner questions (Agent 4).** Accepted nmap, URL-smoke and ZAP findings (at most 10) carry one to three AI-written questions for the asset owner, listed under "Questions for asset owners (AI-written)". Nothing was tested to produce them. Turn them off with `AISW_AI_VERIFICATION_QUESTIONS_ENABLED=false`.
- **Executive summary (Agent 8).** The summary is shown only if every finding it cites was accepted and the reviewer did not dissent. Otherwise it is held and the report has no summary. Turn it off with `AISW_AI_EXECUTIVE_SUMMARY_ENABLED=false`.

### Measuring the reviewer and the narrator (ADR-025)
Before relying on a deployment, and after any prompt or deployment change, run the labelled evaluation from `backend/`:
```bash
uv run python ../tools/eval_labelled.py --env-file ../.env.astra --timeout 120 \
    --json ../docs/implementation/evaluation/labelled-1.0.0-<reviewer>.json --markdown ../docs/implementation/evaluation.md
```
The set is synthetic (`aisw/llm/eval_data/labelled-1.0.0.json`, 24 reviewer cases across Agents 0–8 and 5 narration subjects). Each case goes through the production gateways.
- The exit code is 0 for `USABLE`, 1 for `NOT_USABLE` and 3 for `INCONCLUSIVE`.
- The provisional bar is: recall of planted defects of at least 0.7, a false-dissent rate on clean cases of at most 0.1, and at most 10% unscored.
- Results vary between runs. Run it more than once, and record every run, not only the best one.
- When a case misses, read its `explanations` in the JSON. Fix the input or the prompt. Never loosen the grounding validator to make a number pass.

### Live check on synthetic data
From `backend/`, with the key in a gitignored env file (here `../.env.astra`):
```bash
uv run python ../tools/astra_smoke.py --env-file ../.env.astra                 # one narrative call
AISW_E2E_ENV_FILE=../.env.astra AISW_E2E_PORT=8199 uv run python e2e/server.py  # dev server on Astra
uv run python ../tools/astra_live_run.py --base http://127.0.0.1:8199 --fixture-set baseline-ok
uv run python ../tools/astra_live_run.py --base http://127.0.0.1:8199 --fixture-set baseline-injection
```
Expected: `REPORT_READY` (or `PARTIAL` for the injection fixture). On `baseline-ok` there should be no `DISSENT` and no `VALIDATOR_INVALID`. On `baseline-injection` the injected finding should be held for review. Neither script prints the key.

## Evaluate before relying on it
Run `uv run pytest -m evaluation`. These use a scripted stub and an in-memory Astra transport: they prove the **controls** (hallucinated CVE/control/IP/URL/port/tier rejected, tool calls impossible, secrets redacted, outage leaves the report identical), not your model's quality. Then run a few assessments and read the `llm_calls` provenance (`model_id`, `prompt_version`, hashes, `defects`) and the rejection rate. A high rejection rate means the model is not usable for this.

## Disable / incident
Unset `AISW_AI_ENABLED` and restart. Existing reports keep their already-validated narratives, labelled with model and prompt version. If a bad narrative ever reached a report, treat it as a defect in the grounding validator: keep the report hash, add a test, fix, regenerate. If the Astra key may have leaked, rotate it in Azure first, then update the secret provider and restart.
