# Write-once evidence replica and audit anchors

What exists today (ADR-042) is the seam plus dev/test emulators. Production needs the two sign-offs below; until then `python -m aisw.doctor` shows WARN for `evidence_worm` and `audit_witness`, and the Audit page says the chain is not anchored.

## Write-once evidence replica

`AISW_EVIDENCE_WORM_BACKEND=emulator` (dev/test only; refused in prod) wraps the evidence store: every blob is written to the live store **and** to an Object Lock replica in COMPLIANCE mode for `AISW_EVIDENCE_WORM_RETAIN_DAYS` (default 30) from the write. If the replica refuses the object the write fails, so evidence is never recorded with only one copy. The replica never shortens retention and refuses different bytes under an existing key; deletion before the retain-until date is refused.

- **Verify:** a blob verifies only when the live copy and the replica both match its hash.
- **Restore** a missing or damaged live copy: `WormEvidenceStore.restore(tenant, hash)` rewrites it from the replica after checking the replica's hash. There is no API or CLI for this yet; run it from a maintenance shell **(unverified live)**.
- **Purged evidence stays purged.** A blob moved to quarantine by retention (`evidence-retention.md`) is never restored from the replica. Replica retention must be no longer than the shortest manifest `evidence_retention_days` you intend to honour, or the replica outlives the purge; agree this with the retention owner.

Sign-off `evidence-worm-storage` (owner: platform owner): provision a bucket with Object Lock in COMPLIANCE mode, a write-only role for the platform (no delete, no governance bypass), the retention period agreed with the retention owner, and implement the matching `ObjectLockBackend`.

## Audit anchors

The audit chain is hash-linked inside Postgres, so someone with database owner access could rewrite it consistently. `python -m aisw.core.anchor` (hourly via `aisw-anchor.timer`, or `--tenant` by hand) signs the current chain head with the manifest signer and records the statement with an external witness, then stores the anchor (`audit_anchors`, append-only) and an `audit.anchor` audit event. It does nothing when the only new event is its own previous record.

- **Check:** `GET /api/v1/audit/verify` returns `anchors` alongside the chain result; the Audit page shows it. Problems: `ANCHORED_EVENT_CHANGED` (an anchored event was altered), `STATEMENT_MISMATCH`, `SIGNATURE_NOT_VERIFIED` (key not in the trusted key ring, e.g. after rotation without keeping the old public key), `WITNESS_UNAVAILABLE`, `WITNESS_MISMATCH`.
- **Any problem is an incident:** follow `security-incidents.md`; do not re-anchor over it.
- `AISW_AUDIT_WITNESS=local_file` is an append-only, hash-chained log emulator for dev and test only (refused in prod).

Sign-off `audit-anchor-witness` (owner: security programme lead): choose the witness (an RFC 3161 timestamp authority, a transparency log, or an object-lock bucket in a separate account the platform cannot administer), implement its `Witness`, then enable `aisw-anchor.timer`.
