# ADR-033: Finding review actions and time-boxed exceptions

**Status:** Accepted. Implemented.

## Context
Findings had a lifecycle column (`NEW`, `TRIAGED`, …) but nothing could move it, and the console showed review actions as "planned". The rev 3 plan asks for review actions on findings (confirm, reject, request exception) and for exceptions with an expiry, where an expired exception turns back into a FAIL. Accepting a risk is a decision with consequences, so it needs a second person, a reason, an end date and an audit trail.

## Decision
- **Review actions** live at `POST /api/v1/assessments/{run}/findings/{fid}/review`. They need `finding:triage`, held by the assessment operator and reviewer roles.

  | Action | From | To |
  |---|---|---|
  | `CONFIRM` | `NEW`, `REOPENED` | `TRIAGED` (shown as "Confirmed") |
  | `REJECT` (false positive) | any open state | `FALSE_POSITIVE` |
  | `REOPEN` | `FALSE_POSITIVE` | `REOPENED` |
  | `REQUEST_EXCEPTION` | any open state | `EXCEPTION_PENDING` |

  - The open states are `NEW`, `TRIAGED` and `REOPENED`.
  - Every action needs a reason, which is redacted and capped at 1000 characters.
  - Each action is appended to `finding_reviews` and audited as `finding.<action>`.
  - An identical repeat is an idempotent replay.
  - Actions are refused (409) on a run that has not finished, and on a finding that assurance rejected.
- **Exceptions** (`finding_exceptions`, migration 0014):
  - **Scope.** An exception is scoped to a project, a stable dedupe key, a pack rule and an asset.
  - **Requests.** A request needs an explicit time-zone-aware expiry, later than now and no more than `exception_max_days` away (default 365, at most 1095). Only one pending or active exception may exist per finding key; an advisory lock serialises requests.
  - **Decisions.** `exception:approve` belongs to the approver role only. The decider must differ from the requester, and this is enforced twice:
    - in the API, through `require_separation_of_duties`;
    - by a database CHECK constraint.

    Approving after the requested expiry has already passed is refused. Approval moves the source finding to `ACCEPTED`; rejection moves it back to `TRIAGED`.
  - **Revocation.** An active exception can be revoked with a reason; the finding moves to `REOPENED`.
  - **Database guarantees.** A trigger allows only `REQUESTED→APPROVED|REJECTED` and `APPROVED→REVOKED`. It also refuses deletes and refuses rewriting a recorded decision. The app role may update only the decision and revoke columns.
- **Effect on later runs.**
  - The worker loads the project's approved and revoked grants. For each FAIL, it judges the grant at the time the evidence was observed:
    - **Applied:** the grant was approved, not yet expired and not revoked at that time. The control outcome becomes `EXCEPTION` and no finding is raised. The observation itself stays FAIL, so the evidence is never rewritten.
    - **Expired:** the expiry had passed. The finding is raised again with an assumption that names the exception and its expiry.
  - Either effect is recorded in `exception_applications` (append-only, one row per run and exception). The report then lists it in an "Exceptions" section and a limitation line. The section appears only when there is something to list, so existing golden reports are unchanged.
  - An exception never applies retroactively to the run it was requested from.
- **UI.**
  - The finding page has a review panel with:
    - the lifecycle;
    - the actions the caller may take;
    - a reason dialog, plus an end-of-day UTC expiry date for exception requests;
    - the current exception;
    - the history.
  - `/exceptions` lists exceptions by state (awaiting approval, in force, expired, rejected, revoked) with days left. Approvers get approve, reject and revoke dialogs.
  - The Command Center gains an exceptions card (pending, in force, expiring within 30 days, expired). Its open critical/high count excludes false positives and accepted risks.

## Consequences
- Accepting a risk is visible end to end: who asked, who approved, why, until when, and which runs it covered.
- Expiry is judged against the observation time, not the wall clock at report time. A late re-run of old evidence therefore cannot be hidden by an exception approved afterwards, and a run near the boundary is deterministic.
- Exceptions do not carry across projects or rule changes. A new pack rule id or asset needs a new request.

## Tests
- `tests/unit/test_exception_rules.py`: the effect and state functions at every boundary (approval, expiry, revocation before and after expiry).
- `tests/integration/test_exceptions.py`:
  - review transitions, history and replay;
  - request validation (expiry window, time zone, duplicates);
  - an approved exception covers later runs until it expires, then the finding is reported again and renewal is allowed;
  - rejection and revocation;
  - database separation of duties and transition guards;
  - a late approval is refused;
  - tenant isolation and permission checks.
- `web/e2e/exceptions.spec.ts`:
  - a reviewer confirms a finding and requests an exception;
  - a different approver approves it;
  - the finding shows "Risk accepted";
  - the requester has no decision controls;
  - axe finds no WCAG 2.2 AA violations on the panel, the dialog or the exceptions page.
