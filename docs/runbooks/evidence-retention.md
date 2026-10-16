# Evidence retention, legal holds and purge

Principles: nothing is deleted by the platform. Purge **moves** blobs to `<evidence_dir>/.quarantine/<tenant>/`; a person removes quarantined files later under their own change control. Every action is an append-only row (`retention_actions`) plus an audit event.

Eligible = run finished (`CLOSED`/`FAILED`/`CANCELLED`/`EXPIRED`) **and** the manifest's `evidence_retention_days` elapsed since the run last changed **and** no active hold. A blob also shared with anything still retained (another run's evidence, an import in use) is kept. Uploaded imports are eligible when every run that used them is, or, if unused, after `AISW_EVIDENCE_RETENTION_DAYS` (default 365).

1. **Place a hold if anyone might need the run** (legal, audit, dispute): `POST /api/v1/assessments/{run}/retention-hold {"reason": "..."}` (role `project_admin`). Release: `.../retention-hold/release`.
2. **Dry run:** `GET /api/v1/retention/plan`. Review items, bytes, `kept_shared`, `held_runs`. Nothing changes.
3. **Execute:** `POST /api/v1/retention/execute {"plan_hash": "<hash you reviewed>", "reason": "..."}`. If anything changed since (a hold, a new run) the hash differs and you get 409: fetch the plan again.
4. **Verify:** `GET /api/v1/retention/actions` (auditor). Reports and findings stay; their evidence shows as purged.
5. **Restore** (mistake found within your quarantine window): move the file back from `.quarantine/<tenant>/<hash>` to `<tenant>/<first two hex>/<hash>`; assurance will verify the hash on next read **(unverified live)**.
6. **Final deletion** of quarantined files is a manual, ticketed action by a person. The platform has no delete.

Not built: scheduled purge, per-project retention overrides, UI for any of this (API only).
