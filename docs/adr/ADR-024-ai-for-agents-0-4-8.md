# ADR-024: AI review of Agent 0, Agent 4 owner questions, Agent 8 executive summary

**Status:** Accepted (post-M8). Extends ADR-018 (narratives) and ADR-021 (agent validation pass). Decided by the product owner on 2026-10-16 as part of "go with all items".

## Context
Before this ADR, the agent validation pass reviewed Agents 1–7, and only Agents 5 and 6 asked the model for prose. Agent 0 (scope and authorisation) went unreviewed, even though a too-broad or inconsistent scope is the most expensive mistake a run can make. Asset owners had no prompt for what to confirm about an exposure finding. Leadership had only the findings table.

## Decision
1. **Agent 0 is reviewed, but it cannot hold anything.**
   - The validator receives one `scope:{manifest_id}` packet. It contains the signed targets, exclusions, domains, adapters, profiles and expiry, the expected asset count, whether the approver differs from the author, the permit's task types and the tasks that actually ran.
   - New issue codes are `SCOPE_TOO_BROAD` and `SCOPE_INCONSISTENT`.
   - The scope gate is enforced in code before any tool call, so a scope dissent is a **review note** (`REVIEW_ITEM`), never `HOLD_FOR_REVIEW`. `effect_for(kind, verdict)` maps the effect, and migration `0010` relaxes the 0007 check for `scope:` rows only.
   - A reviewer may overrule or uphold a scope dissent. The decision is recorded and audited, but there is no reassessment and no new report revision (`reassessing: false`).
2. **Agent 4 drafts questions for asset owners.**
   - Narrative purpose `verification` covers up to 10 accepted Agent 4 findings (nmap, URL smoke, ZAP), most severe first.
   - The subject is the finding plus its observed and expected values, each clipped to 200 characters.
   - The output must contain one to three questions, and each must end with "?". The validator rejects anything else with `NO_VERIFICATION_QUESTIONS` or `VERIFICATION_NOT_A_QUESTION`.
   - Grounding still applies: a question may not mention a port, CVE or host that is absent from the facts.
   - Questions appear in the report only for findings that assurance accepted, under "Questions for asset owners (AI-written)".
3. **Agent 8 writes an executive summary.**
   - Narrative purpose `executive` (subject `executive`) covers the 12 most severe findings, a severity tally and per-segment coverage.
   - Its assurance parent is `ACCEPT` only if every finding it cites is accepted; otherwise it is `NEEDS_REVIEW` and is not shown.
   - Agent 8 reviews it in its own validation packet, and a `DISSENT` holds it.
   - The report states that the findings table is authoritative.
4. **Switches.** `AISW_AI_VERIFICATION_QUESTIONS_ENABLED` and `AISW_AI_EXECUTIVE_SUMMARY_ENABLED` both default to on, and both still require AI assist on the run. Prompt versions are `narrative-1.2.0` and `agent-validation-1.2.0`.
5. **Replay alignment.** Recorded replies now store per-run UUIDs as the prompt's `<idN>` placeholders and restore them for the replaying run. Without this, a replayed `scope:{uuid}` verdict would name the recorded run's manifest.

## Consequences
- With every agent reviewed, `held_for_review` counts only `HOLD_FOR_REVIEW` effects, so scope notes never inflate it.
- A run now makes up to 11 more model calls: 10 verification calls and 1 executive call. The per-run token budget (ADR-023) still caps them.
- Migration `0010` reverses cleanly. Its downgrade removes `verification` and `executive` narratives and any `scope:` validations and resolutions, with the append-only triggers disabled for that step only.

## Tests
- `tests/unit/test_generation_agents.py` covers effects, subjects, question checks, the scope packet and replay alignment.
- `tests/integration/test_generation_agents.py` covers:
  - a scope dissent as a note, with no reassessment;
  - the scope packet contents;
  - the executive summary shown, held by a dissent, held when it cites a held finding, and switched off;
  - Agent 4 questions on accepted nmap findings, with an instruction rejected.
- `tests/integration/test_migrations.py` covers the 0010 downgrade.
- `web/e2e/ai-sections.spec.ts` checks the labelled executive summary, including an axe check.
