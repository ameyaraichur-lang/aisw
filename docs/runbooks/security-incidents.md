# Security incidents

First, preserve: do not edit or delete rows, evidence or quarantine files. Place a retention hold on affected runs.

| Suspicion | Do |
|---|---|
| Audit tampering | `GET /api/v1/audit/verify` (auditor). `ok:false` names the broken sequence. The chain is not externally witnessed: compare with any backup |
| Cross-tenant exposure | Stop the API. RLS is forced and fail-closed; check `current_setting('app.tenant_id')` handling in the failing path; reproduce as a test before fixing |
| Secret found in evidence/report | Redaction is pattern-based. Rotate the secret, add the pattern + a regression test, then (after review) plan a purge of that run's evidence; the report hash and audit stay |
| Unexpected outbound connection | The gateway is the only egress path and every dispatch is audited. Check `gateway` audit rows for the run; confirm the egress firewall exists at the host (it is **not** enforced by this software) |
| Scope violation claimed | Fetch the signed manifest and permits for the run; confirm the manifest hash and the audit `gateway.dispatch` decisions; a denied dispatch has zero tool calls by design |
| Key compromise | See [permits-and-keys](permits-and-keys.md) (procedure is design only) |
| Model produced something harmful | Disable AI ([ai-enablement](ai-enablement.md)). The model has no tools; check `llm_calls` and `narratives` for what was stored |
