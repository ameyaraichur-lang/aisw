# ADR-003: Policy engine

**Status:** Accepted (M0). Delivered by ADR-031: OPA 1.21.2 runs the packaged Rego; the Python evaluator remains the default and must agree with it.

## Decision
OPA (Rego bundles, pinned version/digest) behind a PolicyEvaluator interface; a Python rule evaluator is the interim implementation until the opa binary is installed.

## Context
Blueprint requires deterministic, versioned, auditable policy decisions with rule ID, policy version and evidence refs.

## Consequences
Same test suite must pass for both implementations. OPA binary download (Apache-2.0) is approved but not yet performed.

## Alternatives considered
Python-only rules (less auditable/standard).
