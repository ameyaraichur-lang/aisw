# Enabling and disabling AI

AI is **off by default** and is not needed for any decision. A model writes optional explanations of scenarios and recommendations and, when enabled, reviews agent outcomes; it can only hold items for human review ([ADR-021](../adr/ADR-021-agent-validation-pass.md)). Deterministic checks decide what is shown. **No model weights are bundled or downloaded by this repository.** Astra has been run live on synthetic fixtures only (2026-10-16); no local model has been run.

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
4. Outbound https to that host. The client ignores `HTTPS_PROXY`/`HTTP_PROXY` and never follows redirects, so a proxy-only network cannot reach Astra.

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

**Resolving a dissent (ADR-022).** A reviewer with `report:approve` who did not request the run opens the run's Analysis tab and chooses **Overrule** or **Uphold** on a dissent row, giving a reason. The API equivalent is `POST /api/v1/assessments/{run_id}/ai-validations/resolutions`.
- **Uphold** keeps the item held and leaves the report unchanged.
- **Overrule** re-runs assurance without that dissent and issues a new report revision (`rep-{run}-r2`, …). The old pending report becomes `SUPERSEDED`. Approve the newest revision.

Both decisions are final and audited. Resolve every dissent before approving, because an approved report cannot be revised.

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
