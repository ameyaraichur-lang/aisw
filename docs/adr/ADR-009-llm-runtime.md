# ADR-009: LLM runtime

**Status:** Accepted (M0, approved with development plan)

## Decision
Ollama or vLLM, local only, disabled by default (AISW_AI_ENABLED=false). Enabling requires a recorded approved model id; weights licence reviewed separately from runtime licence.

## Context
Blueprint 5/11/J.1: no hosted model APIs; disable AI if no approved open-source weights.

## Consequences
Deterministic workflow must be complete without AI. Config validation already forbids ai_enabled without model_id.

## Alternatives considered
Hosted model API (violates open-source-only boundary).
