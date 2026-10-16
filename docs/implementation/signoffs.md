# Sign-off register

Generated from `backend/aisw/policy/signoffs.json` by `tools/signoffs.py`; do not edit.

While an item is PENDING, the product keeps the label shown here. A decision needs the
decider, the date, a reference and the sha256 of the exact artefact; changing the artefact
afterwards fails the check until a new decision is recorded.

| Id | Plan | Subject | Owner | Status | Shown while pending | Next step |
|---|---|---|---|---|---|---|
| `risk-rubric-1.0.0` | P0-6 | Risk rubric 1.0.0: severity, criticality and exposure weights and the P0-P2 thresholds (`backend/aisw/policy/rubrics/risk-rubric-1.0.0.json`) | Policy owner (role policy_owner) | PENDING | Risk tiers come from a sample rubric awaiting policy-owner approval; treat them as indicative. | Policy owner reviews the weights and thresholds against a reviewed sample of real findings, then records the decision here or publishes an adjusted rubric version. |
| `architecture-catalog-1.0.0` | P0-6 | Architecture catalog 1.0.0: target patterns used for recommendations (`backend/aisw/policy/catalogs/architecture-catalog-1.0.0.json`) | Policy owner with the customer's enterprise architect | PENDING | Recommendation patterns come from a sample catalog, not the customer's approved reference architecture. | Replace or confirm each pattern against the customer's reference architecture; an approved catalog is published as a new version with status APPROVED. |
| `ai-evaluation-bar` | P0-6 | Acceptance bar for the AI reviewer and narrator (recall, false-dissent rate, narrative acceptance) (`backend/aisw/llm/evaluation.py`) | Policy owner with the security lead | PENDING | The evaluation bar is provisional; meeting it on the synthetic labelled set is not an approval. | Agree the thresholds and a labelled set drawn from reviewed real findings (needs the data approval below), then record the decision. |
| `licence-review` | P0-7 | Licence review: LGPL psycopg/psycopg-binary at runtime, MPL dev tools, three packages without licence metadata (`docs/implementation/sbom/licence-policy.json`) | Named legal reviewer | PENDING | Licence acceptances are engineering positions, not legal advice; no external redistribution until reviewed. | Legal reviewer confirms or changes each acceptance in licence-policy.json, then records the decision here. |
| `astra-data-approval` | A-1 | Data-handling approval for sending redacted real evidence to Astra (open item O3) (`docs/adr/ADR-020-astra-remote-model-provider.md`) | Product owner with the data protection officer | PENDING | Astra may be used on synthetic fixtures only; the configured approval reference covers synthetic data only. | Data protection review of what leaves the host (redacted findings, no raw evidence) and of the Azure tenant's retention terms; record the approval reference here and in AISW_ASTRA_DATA_APPROVAL_REF. |
