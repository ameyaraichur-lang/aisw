# ADR-035: Modernization roadmap waves and the scenario chain view

**Status:** Accepted. Implemented.

## Context
The rev 3 plan asks for a Modernization Roadmap with remediation-wave swimlanes and a dependency graph, and for an Exposure Scenarios chain view. Recommendations already carry a rubric tier (or none, when criticality is unknown) and free-text prerequisites from the sample architecture catalog. Nothing in the data orders one recommendation before another, so any ordering the platform shows must come from a rule that the evidence supports, or it would be an invented priority.

## Decision
- **Waves are computed on the server** by `aisw/agents/roadmap.py` and served at `GET /api/v1/assessments/{run}/roadmap` (needs `finding:read`).
  - Only recommendations accepted by independent assurance are placed; the count of the others is shown.
  - The wave comes from the rubric tier only: P0 and P1 go to wave 1, P2 to wave 2, P3 to wave 3.
  - A recommendation without a tier is **not scheduled**. It sits in a "Needs owner input" lane with the reason, because placing it would invent a priority.
  - Rejected and implemented-pending-validation recommendations are listed in their own lanes, not scheduled.
  - Effort stays unknown until the owner estimates it.
- **The only dependency edge** is `OWNER_UNKNOWN`: a recommendation on assets whose owner is unknown *now* (read from the reconciled assets) follows the asset-governance recommendation (`AC-GOV-*`) that covers those assets, one wave later. A wave-3 prerequisite opens a fourth wave. If the governance recommendation itself is unscheduled, the dependent card says it is waiting for it. Catalog prerequisites remain owner checks, not ordering.
- **The scenario chain** is drawn as asset → finding → finding, each link labelled with its basis. The scenarios API now adds each finding's title, severity and category to its chain link, so the view does not depend on a paginated finding list. Recorded links are drawn solid; inferred links (none exist yet; reachability analysis will add them) are drawn dashed and labelled as needing validation.

## Consequences
- Without owner-supplied criticality, the roadmap is honestly empty of waves. That is the expected state for the fixture estate and is tested end to end.
- When the catalog gains real inter-pattern dependencies, they become a second edge basis; the view already renders an edge list with its reason.
- Tests: `tests/unit/test_roadmap.py`, `tests/integration/test_roadmap_api.py`, `web/e2e/roadmap.spec.ts`, `web/e2e/analysis.spec.ts`.
