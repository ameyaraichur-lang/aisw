# ADR-046: Plan of record: this repository as the base, rev 3 adopted item by item

**Status:** Accepted (2026-10-18, product owner). Closes open question 1 of the pending plan. An item listed below as not adopted can be taken up later, with its own ADR.

## Context
Two plans describe the product. This repository was built to the open-source blueprint v2.1 (`development-plan.md`, M0–M8). The WARDEN rev 3 plan in the parent workspace (`../docs/implementation/implementation-plan.md`) asks for Astra on every agent, OPA policy bundles, framework mappings, more importers, a new UI of 13 pages with the APEX look and feel, and WARDEN branding. The pending plan (§2) recommended keeping this repository as the base and adopting rev 3 items one at a time. Since then the product owner decided Astra on the agents (ADR-021, 2026-10-16), GitHub Actions (ADR-030), and asked for all remaining items to be built (2026-10-17). They were built here, each with its own ADR.

## Decision
1. **This repository is the base and the plan of record.** Its architecture stays: FastAPI with Postgres row-level security, the durable worker, signed scope manifests, the evidence store, independent assurance, and the React console with server-sent events. `pending-plan.md` tracks the remaining work.
2. **Adopted from rev 3**, each recorded in its ADR:
   - Astra on the agents, one-way and advisory only. A model may hold an item for human review, never approve, re-score or add a finding (ADR-020 to ADR-025, ADR-036).
   - OPA and Rego policy bundles (ADR-031), framework mappings with per-tenant review (ADR-032), exceptions with expiry and finding review (ADR-033), file importers for the rev 3 tools (ADR-034).
   - The rev 3 pages, as routes in the existing console (below), reporting with PDF/DOCX and ITSM drafts (ADR-037, ADR-038), and the Maple Trust estate with the Evaluation Lab (ADR-039).
3. **Not adopted:**
   - *Vanilla JS without a build step, Socket.IO and the APEX visual language.* The React/TypeScript console is built, typed against the API contracts, and covered by 40 end-to-end tests with accessibility scans on 28 screens. Rewriting it would add risk and no capability.
   - *WARDEN branding and a `branding.json` white-label file.* The product stays generic ("AISW Security Warden").
   - *GitLab CI.* GitHub Actions is the system of record (ADR-030).
   - *Live API pulls from CMDB and scanner products.* Only file imports exist; a live pull would be a new egress destination and needs its own authorisation.
   - *The Estate Map relationship graph.* The Asset Explorer, the architecture view and the reachability edges (ADR-041) exist; a zone-grouped graph of asset relationships is not built.

| Rev 3 page | Where it is |
|---|---|
| Command Deck | `/` (Command Center) |
| Scope Studio | `/projects` and the New Assessment wizard (`/assessments/new`); manifests are signed on `/approvals` |
| Run Theatre | `/assessments/:runId/timeline` |
| Estate Map | Partly: `/assets`, `/architecture`; no relationship graph |
| Coverage Ledger | `/coverage` and the run's coverage tab |
| Findings & Evidence | `/findings` and the finding page |
| Exposure Scenarios | The run's analysis tab (ADR-035, ADR-041) |
| Control Matrix | `/controls` |
| Modernization Roadmap | `/roadmap` |
| Assurance Console | `/assurance` |
| Approvals & Reports | `/approvals`, `/reports` and the run's report tab |
| Audit & Provenance | `/audit`, `/audit/model-calls` |
| Evaluation Lab | `/evaluation` |

The console also has pages rev 3 does not list: `/integrations`, `/exceptions`, `/retention` and `/tickets`.

## Consequences
- The pending plan no longer has a "decision needed first" section; §5 lists the rev 3 scope as adopted, with what is still pending on each item.
- A rev 3 item not adopted here is not a gap. Taking one up needs a new ADR stating why.
- Every rev 3 item that was adopted still runs on synthetic data only, and every human decision it needs is a PENDING sign-off in `signoffs.md`.
