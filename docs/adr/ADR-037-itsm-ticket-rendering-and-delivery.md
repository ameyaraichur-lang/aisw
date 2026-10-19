# ADR-037: Ticket rendering for Jira and ServiceNow, and two-person delivery

**Status:** Accepted. Implemented and tested against a loopback fake ITSM only. Delivery to a real Jira or ServiceNow instance is pending the owner step recorded as `itsm-delivery` in the sign-off register.

## Context
Ticket drafts (M7) were outbox rows that could never be sent: the database allowed only `status = 'DRAFT'`. The rev 3 plan asks for Jira and ServiceNow payloads and for delivery, without giving up the read-only posture: AISW must never change an assessed system, and a ticket must not be created twice when a call times out after the ticket was already made.

## Decision
- **Rendering is pure and always available.** `aisw/itsm/render.py` turns a stored draft into:
  - **Jira REST v3:** project, issue type, summary (255 characters at most) and an Atlassian Document Format description built from plain-text paragraphs only, so no markup can be injected. No Jira priority is set, because priority schemes differ per site.
  - **ServiceNow Table API:** short description (160 characters at most), description, category `security`. Urgency and impact come from the rubric tier only (P0 = 1/1, P1 = 2/1, P2 = 2/2, P3 = 3/3). An untiered draft gets neither.

  Both carry the correlation key `aisw-<outbox_id>`: as a Jira label, or as the ServiceNow `correlation_id`. `GET /api/v1/tickets/drafts/{id}/render?target=jira|servicenow` returns the exact payload (needs `finding:read`).
- **Delivery is off by default.** `AISW_ENABLE_ITSM_TICKET_DELIVERY` requires ticket creation to be on and requires `AISW_ITSM_TARGET`, `AISW_ITSM_BASE_URL`, `AISW_ITSM_USERNAME` and `AISW_ITSM_TOKEN`. The base URL must be an https origin with no credentials; plain http is allowed only on loopback outside prod. When delivery is on, the egress allow-list gains one destination for the API process only (ADR-028).
- **Two people.** `POST /api/v1/tickets/drafts/{id}/send` needs `recommendation:decide` from someone other than the draft's author. This is enforced in the API and by a CHECK constraint (`sent_by <> created_by`). A dev approver `vic` is seeded so the flow can be exercised locally.
- **Find, then create.** Each attempt:
  1. claims the row (DRAFT or FAILED becomes SENDING, `attempts + 1`) in its own transaction;
  2. calls the ITSM outside any transaction, first searching for the correlation key and creating the ticket only if none exists;
  3. records SENT (with external reference and sender) or FAILED (with an error code only, never a response body).

  A timed-out create is therefore found on the next attempt, not duplicated. An in-flight claim blocks other senders until it is stale (twice the timeout plus 30 seconds). There are at most 5 attempts.
- **The database keeps it honest.** Migration 0017:
  - allows only DRAFT|FAILED|SENDING → SENDING (with `attempts + 1`) and SENDING → SENT|FAILED;
  - makes SENT final;
  - fixes the target after the first attempt;
  - grants UPDATE on the delivery columns only, so the payload stays immutable and rows are never deleted.

  The migration is reversible only while nothing has been sent.
- **Calls are bounded.** They use the control-plane HTTP helper: no proxy, no redirects, a size cap and a timeout (`AISW_ITSM_TIMEOUT_SECONDS`, default 10). Errors are classified as unreachable (retryable), 429 or 5xx (retryable), 401 or 403 (refused), or other 4xx (rejected). AISW never updates, transitions or closes a ticket.
- **Audit.** Every attempt appends a `ticket.send` audit event (SUCCESS or FAILURE) with a hash of the target and the reference or error code.
- **UI.** `/tickets` (Ticket Outbox, needs `finding:read`) lists drafts with their delivery state and the exact payload for either system. Approvers other than the author get a confirmed **Send** action; the author is told another approver sends it.

## Consequences
- Real delivery needs the human step in `itsm-delivery`: the ITSM owner approves the field mapping and a least-privilege service account; the token goes into the secret provider; the egress rule is approved; and a first ticket is created in a sandbox project. Until then delivery stays off and the outbox is labelled draft-only.
- Jira search uses `/rest/api/3/search/jql`. On a Jira Data Center site the path may differ, which will be checked during the owner step.
- Tests:
  - `tests/unit/test_itsm.py`: renderers, the client against the fake (late reply, error classes, unreachable) and the settings that must fail closed.
  - `tests/integration/test_ticket_delivery.py`: two-person rule, retry without duplicate, replay, database finality, ServiceNow refusals and stale claims.
  - `tests/integration/test_migrations.py`.
  - `web/e2e/tickets.spec.ts`.
