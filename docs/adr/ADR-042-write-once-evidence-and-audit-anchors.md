# ADR-042: Write-once evidence replica and externally witnessed audit anchors

**Status:** Accepted (seams and dev/test emulators; production backends pending sign-off)

## Context
Evidence lives in one content-addressed directory: re-hashing on read detects damage but cannot recover from it, and a host administrator can delete it (threat T13). The audit trail is hash-chained in Postgres, so a database owner can rewrite the whole chain consistently and the verifier still passes (T14, ADR-005 deferred anchoring).

## Decision
1. **Write-once evidence replica** (`aisw/evidence/worm.py`). `WormEvidenceStore` wraps the evidence store and writes each blob to an `ObjectLockBackend` as well, under the key `tenant/sha256`, in COMPLIANCE mode for `AISW_EVIDENCE_WORM_RETAIN_DAYS` from the write:
   - the write fails if the replica refuses it, so no evidence is recorded with one copy;
   - the same key with different bytes is refused; rewriting identical bytes may extend retention, never shorten it; deletion before retain-until is refused;
   - a blob verifies only when both copies match its hash; `restore` rewrites a missing or damaged live copy from a hash-checked replica copy;
   - **a blob moved to quarantine by retention is never restored** from the replica, so the replica cannot undo a purge (ADR-019).
2. **Signed, witnessed audit anchors** (`aisw/core/anchor.py`, migration 0023). An hourly job signs a statement over the tenant, head sequence, head hash and time (domain `aisw-audit-anchor-v1`) with the manifest signer, records it with an external `Witness`, and stores the anchor in `audit_anchors` (append-only, forced RLS, `SELECT, INSERT` only) with an `audit.anchor` event. It skips when the only new event is its own previous record, and serialises per tenant with an advisory lock.
3. **Verification** joins each anchor with the current event at that sequence: `ANCHORED_EVENT_CHANGED`, `STATEMENT_MISMATCH`, `SIGNATURE_NOT_VERIFIED`, `WITNESS_UNAVAILABLE`, `WITNESS_MISMATCH`. `GET /audit/verify` returns the result as `anchors`, with `witness_configured`; the Audit page shows not anchored, no anchors yet, verified, or the problems.
4. **Emulators only, refused in prod.** `LocalObjectLockEmulator` (files plus a lock sidecar) and `LocalFileWitness` (hash-chained JSON lines; confirmation re-verifies the whole log) exist so the seams are tested end to end. Settings refuse both when `AISW_ENV=prod`; the doctor reports WARN while either is absent or emulated.

## Consequences
- Rewriting an anchored audit event, or the chain behind it, is detectable as long as the witness is outside the platform's control. Events after the latest anchor are protected only by the chain until the next anchor (at most an hour with the timer).
- Replica retention must not outlast the retention the manifests promise, or the replica keeps evidence the platform claims to have purged; the retention owner agrees the period in the sign-off.
- Rotating the signing key must keep old public keys in the key ring, or older anchors report `SIGNATURE_NOT_VERIFIED`.
- Not built: an S3/Object Lock backend, an RFC 3161 or transparency-log witness, an API or CLI for restore, and replica checks during assurance. These need the `evidence-worm-storage` and `audit-anchor-witness` sign-offs (PENDING).

## Tests
`tests/security/test_worm_and_anchor.py` (lock semantics, dual-copy verify and restore, quarantine not resurrected, full run mirrored to the replica, anchors signed and witnessed and skipped when nothing is new, rewrite and witness tampering detected, prod refusal), the migration up/down test, `tests/unit/test_deploy_packaging.py` (anchor unit and timer) and `web/e2e/audit-anchor.spec.ts`.
