# Turning on ticket delivery (Jira or ServiceNow)

Delivery is off by default. Drafts can always be previewed for either system on the **Ticket Outbox** page (`/tickets`). Turn delivery on only after every step below is recorded against `itsm-delivery` in `backend/aisw/policy/signoffs.json` (ADR-037).

## 1. Owner approvals
- **Field mapping:** the ITSM owner reviews a rendered payload (Ticket Outbox, then **Ticket payload**), including the ServiceNow urgency and impact derived from the rubric tier, and the Jira project and issue type.
- **Service account:** create one account that can create tickets in a single project or table and search them. It must not edit, transition or delete tickets.
- **Egress:** with delivery on, the egress `plan` (see `egress.md` and `deploy/egress/README.md`) lists one `itsm` destination for the API process. The network owner approves it before the rules are rendered and loaded.

## 2. Configuration
```
AISW_ENABLE_ITSM_TICKET_CREATION=true
AISW_ENABLE_ITSM_TICKET_DELIVERY=true
AISW_ITSM_TARGET=jira                    # or servicenow
AISW_ITSM_BASE_URL=https://<site>        # an origin only, no path or credentials
AISW_ITSM_USERNAME=<service account>
AISW_ITSM_TOKEN=<from the secret provider; never in a file in the repository>
AISW_ITSM_JIRA_PROJECT_KEY=SEC           # Jira only
AISW_ITSM_JIRA_ISSUE_TYPE=Task           # Jira only
AISW_ITSM_SERVICENOW_TABLE=incident      # ServiceNow only
AISW_ITSM_TIMEOUT_SECONDS=10
```
Startup refuses any of the following:
- a missing value;
- a non-https URL (http is allowed only on loopback outside prod);
- a URL with credentials or a path;
- delivery enabled without ticket creation.

## 3. First ticket
1. Point the configuration at a sandbox project.
2. Approver A creates a draft from an accepted recommendation.
3. Approver B sends it from the Ticket Outbox.
4. Confirm that the ticket exists once, carries the label or `correlation_id` `aisw-<outbox id>`, and that the audit log shows `ticket.send` SUCCESS.
5. Record the decision in the sign-off register and regenerate `docs/implementation/signoffs.md` (`python tools/signoffs.py`).

## Failures
- **"did not answer in time" (`ITSM_UNREACHABLE`):** send again. The retry searches for the correlation key first, so a ticket created by the timed-out call is reused, not duplicated.
- **`ITSM_REFUSED_401` or `ITSM_REFUSED_403`:** the credentials or the account's rights are wrong. Fix them in the secret provider; retrying does not help.
- **"attempt limit reached":** five attempts were used. Investigate before doing anything else; the draft cannot be sent from AISW again.
- **To stop delivery:** set `AISW_ENABLE_ITSM_TICKET_DELIVERY=false` and restart the API. Drafts and sent records stay.
