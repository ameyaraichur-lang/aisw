# Enabling and disabling AI

AI is **off by default** and is not needed for any decision. A model only writes optional explanations of scenarios and recommendations; deterministic checks decide what is shown. **No model weights are bundled or downloaded by this repository, and none has been run against it.**

## Before enabling (all required)
1. A model whose **weights licence** you have reviewed (record the SPDX id). The runtime's licence (e.g. Ollama) is separate.
2. A local runtime listening on loopback only. The platform refuses any other endpoint.
3. A person accepts that output quality and latency are **unverified** until you run the evaluation checks below on your model.

## Enable
Set `AISW_AI_ENABLED=true`, `AISW_MODEL_ID`, `AISW_MODEL_LICENSE`, optionally `AISW_MODEL_ENDPOINT` (default `http://127.0.0.1:11434`) and the two feature flags `AISW_AI_NARRATIVE_ENABLED` / `AISW_AI_ARCHITECTURE_ENABLED`. Startup fails if the model id or licence is missing. A run uses AI only when the launch request sets `ai_assist: true`.

## Evaluate before relying on it
Run `uv run pytest -m evaluation`. These use a scripted stub: they prove the **controls** (hallucinated CVE/control/IP/URL/port/tier rejected, tool calls impossible, secrets redacted, outage leaves the report identical), not your model's quality. Then run a few assessments and read the `llm_calls` provenance (`prompt_version`, hashes, `defects`) and the rejection rate. A high rejection rate means the model is not usable for this.

## Disable / incident
Unset `AISW_AI_ENABLED` and restart. Existing reports keep their already-validated narratives, labelled with model and prompt version. If a bad narrative ever reached a report, treat it as a defect in the grounding validator: keep the report hash, add a test, fix, regenerate.
