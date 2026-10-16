# ADR-020: Astra (Azure OpenAI) as an opt-in remote model provider

**Status:** Accepted (post-M8), amends ADR-009 for the Astra provider only

## Context
ADR-009 allows only a local, loopback model, and ADR-018 builds the bounded LLM gateway on that assumption. The product owner asked for Astra, the Azure OpenAI Responses API deployment the team already uses, to be configurable as the narrative model. Astra is a hosted service: the redacted, whitelisted projection of findings that the gateway sends would leave the host. That conflicts with the blueprint's open-source/local-only boundary, so it needs its own decision and must not weaken anything else.

## Decision
1. **A second provider, off unless chosen.** `AISW_MODEL_PROVIDER` is `ollama` (default, unchanged) or `astra`. AI stays off by default (`AISW_AI_ENABLED=false`); selecting `astra` alone does nothing.
2. **Complete configuration or startup fails.** With `ai_enabled=true` and `model_provider=astra`, settings require `AISW_MODEL_ID` (the Astra deployment name), `AISW_ASTRA_ENDPOINT`, `AISW_ASTRA_API_KEY` and `AISW_ASTRA_DATA_APPROVAL_REF`. The weights-licence field is not required for a hosted model; the data-handling approval reference replaces it as the human gate.
3. **The data boundary is a recorded human decision.** `AISW_ASTRA_DATA_APPROVAL_REF` names the approval (ticket or decision id) for sending redacted findings to Azure. Without it the platform refuses to start with Astra enabled. Synthetic data only until that approval covers real evidence (open item O3 in the WARDEN plan).
4. **The endpoint cannot become generic egress.** `AISW_ASTRA_ENDPOINT` must be an `https` origin on port 443 with no credentials, path, query or fragment, whose host ends in `.openai.azure.com`, `.cognitiveservices.azure.com` or `.services.ai.azure.com`. The same check runs in settings (even while AI is off) and again in the client. The client refuses redirects, ignores proxy environment variables and caps responses at 256 KB, like the Ollama client.
5. **The key is a secret, not a setting value.** `AISW_ASTRA_API_KEY` is a `SecretStr` injected by the secret provider through the environment. It is sent only in the `api-key` header, never appears in settings output, client `repr`, exceptions or provenance, and HTTP error bodies are not chained into exceptions.
6. **Same contract as the local model.** The client implements `ModelClient.complete` (text plus a JSON schema, no tools). The Responses API request carries `instructions`, `input`, `store: false`, `max_output_tokens` and a `json_schema` text format, and never a `tools` key. Any output item other than `message` or `reasoning` (function, web-search, MCP and other tool calls) is refused as `MODEL_TOOL_CALL_REFUSED`. Refusals, incomplete responses and unreadable bodies become `ModelUnavailable` codes. Authentication failures (`MODEL_AUTH_FAILED`) are not retried; rate limits and transport errors get the gateway's single retry.
7. **Validation is unchanged and remains the control.** The schema is sent with `strict: false` because the narrative schema uses optional fields and length limits that Azure's strict mode rejects. Pydantic validation, the grounding validator and Agent 7 decide what is accepted, exactly as for a local model.
8. **Provenance.** `llm_calls.model_id` records the Astra deployment name. `GET /api/v1/agents` reports `ai.provider` and sets `endpoint_local_only` to `false` for Astra, and the workbench says that redacted findings leave the host.

## Consequences
- The deterministic workflow is unaffected: with Astra off, unavailable, rejected or slow, reports are identical (existing ADR-018 tests).
- A hosted model is no longer impossible by configuration, so its use depends on the data-handling approval and on operators keeping the key in the secret provider.
- Tier routing with failover, per-run token budgets, response record/replay and the "Astra validation pass" for every agent from the WARDEN rev 3 plan are **not** built; this ADR covers the provider and its configuration only.

## Alternatives considered
- Pointing the existing loopback `model_endpoint` at a local proxy to Azure: hides the remote hop from settings, provenance and the threat model.
- A generic "any OpenAI-compatible URL" setting: turns the model endpoint into general egress.
