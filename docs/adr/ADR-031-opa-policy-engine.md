# ADR-031: OPA policy engine with packaged Rego, held equivalent to the Python evaluator

**Status:** Accepted. Implemented and tested against a real OPA 1.21.2 server on loopback. ADR-003 is now delivered; the Python evaluator stays as the default and as the reference implementation.

## Context
ADR-003 chose OPA behind the `PolicyEvaluator` interface, but the binary had never been installed, so every decision came from the interim Python evaluator. The rev 3 scope also needs domain policies (network, storage, logging and encryption, IAM, lifecycle, hardening, Kubernetes RBAC) that are better expressed as Rego over normalised facts than as single-value checks.

## Decision
- **Packaged Rego** in `backend/aisw/policy/rego/`:
  - `policy.rego` (package `aisw.policy`) gives `decision` and `applicable`, with the same semantics as the Python evaluator:
    - missing evidence is UNKNOWN;
    - a check that cannot run on its value is ERROR;
    - a rule applies only when the asset proves every attribute it is conditioned on;
    - equality is JSON equality (`true` is not `1`).
  - `domains/*.rego` (packages `aisw.domains.<domain>`) hold 20 rules that read `input.value` and return PASS, FAIL or NOT_APPLICABLE. Facts they cannot judge leave the rule undefined, which becomes UNKNOWN. Thresholds come from pack parameters with documented defaults.
  - `lifecycle` compares the end-of-life date with the evidence date, never the clock.
- **A new check op** `rego` with value `{"rule": "<domain>.<rule>", "params": {...}}`, validated at load time. The other ops now type-check their values when a pack loads: numbers for `gte`/`lte`, lists for `in`/`disjoint`.
- **Python stays strict.** The Python evaluator cannot run `rego` rules and returns ERROR rather than guessing. A launch whose pack needs Rego is refused with `POLICY_ENGINE_OPA_REQUIRED` unless OPA is the engine.
- **`OpaEvaluator`:**
  - Talks to an OPA server (`AISW_POLICY_ENGINE=opa`, `AISW_OPA_URL`) through `safe_http`: no proxies, no redirects, a size cap.
  - Before first use it hashes the policy sources the server reports and compares them with the packaged Rego (tests excluded). On a mismatch it refuses to start.
  - An unreachable server raises, so the task retries instead of recording outcomes nobody evaluated.
  - Only the rule id, applicability and check are sent, never titles or mappings. Asset attributes are stringified exactly as the Python evaluator does.
- **The URL** may use http only on loopback or with a single-label service name on an internal network; anything else must be https. OPA is added to both roles' egress destinations.
- **Pack `config-baseline:1.0.0`** has 20 Rego rules, each mapped to NIST SP 800-53 Rev. 5, ISO/IEC 27001:2022 Annex A and CIS Controls v8. Every mapping is `NEEDS_REVIEW` and the pack is a PENDING sign-off (`config-baseline-1.0.0`), so reports carry the "proposal" label.
- **Deployment.**
  - An `opa` compose service (pinned image, read-only policy mount, internal `policy` network, non-root).
  - An `aisw-opa.service` unit on loopback with `IPAddressDeny=any`.
  - A doctor check `policy_engine`: WARN in prod on the Python engine, FAIL if OPA serves different policy.
- **CI.**
  - Installs the pinned OPA binary and verifies its sha256.
  - Runs `opa check --strict`, `opa fmt --list --fail` and `opa test` with a 95% coverage threshold.
  - Sets `AISW_REQUIRE_OPA=1`, so the equivalence tests cannot silently skip.

## Consequences
- Two engines must agree. The shared suite and a seeded differential test of 400 generated checks enforce it; the first divergences found (bool versus number equality) were fixed in Python.
- Changing any Rego file changes the bundle hash. A deployment must run the OPA policy shipped with the same build, or the services refuse to start.
- Domain rules have no adapter feeding them until the rev 3 configuration imports land (w2). Until then they are exercised through tests only.

## Tests
- `opa test aisw/policy/rego`: 15 Rego tests, 99.7% coverage.
- `tests/unit/test_policy_engine.py`: the existing suite, parametrised over both engines.
- `tests/unit/test_opa.py`:
  - the differential test;
  - a server with a tampered policy is refused;
  - packaged sources exclude tests and match the server;
  - failing closed when unreachable;
  - NaN becomes ERROR;
  - domain rules through the pack, with the Python engine giving ERROR and an inapplicable resource type giving no outcome;
  - every pack rule resolves to a domain rule with three framework mappings;
  - URL validation;
  - the egress destination;
  - a minimal payload is sent to OPA.
- `tests/integration/test_opa_pipeline.py`: the worker gives identical observations, controls, findings and run state with either engine on the `baseline-ok` and `baseline-partial` fixtures; a Rego pack is refused at launch without OPA.
