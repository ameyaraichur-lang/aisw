# ADR-008: Agent execution model

**Status:** Accepted (M0, approved with development plan)

## Decision
Agents are typed task handlers registered with the orchestrator. No agent-to-agent calls. LLM client is importable only from agents 5, 6 and 8-narrative, behind feature flags.

## Context
Appendix D/G: not every task needs an LLM; orchestrator owns state, dispatch and permissions.

## Consequences
Import-boundary test in CI to enforce the LLM-client restriction.

## Alternatives considered
Free-roaming agents / swarm (explicitly deferred).
