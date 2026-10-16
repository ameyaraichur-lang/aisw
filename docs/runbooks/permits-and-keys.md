# Permits, manifests and signing keys

**Permits** authorise one run for 15 minutes. While a run is still dispatching, the worker renews a permit that is within 5 minutes of expiry, but only if the *full launch policy* still passes (manifest approved, signature valid, unexpired, hash unchanged, inventory unchanged, connector health). Renewal is capped at 8 renewals and 2 hours per run and never outlives the manifest. A **revoked** or **lapsed** permit is never renewed: launch again.

Revoke a run's authority: `ScopeService.revoke_permit` (operator, `assessment:cancel`) revokes **every** permit of the run. Revoke a manifest to stop all future launches and renewals (`MANIFEST_NOT_APPROVED`).

Audit: `permit.renew`, `permit.revoke`, `manifest.revoke`, `assessment.authorize` are in the hash-chained audit trail (`GET /api/v1/audit/events`, `GET /api/v1/audit/verify`).

**Signing keys (weakest area).** Manifests are signed with Ed25519. Today the private key is a local file (`AISW_SIGNING_KEY_PATH`, created on first use in dev/test only; the app refuses to create one in prod) and the key ring holds public keys. There is **no tested rotation or revocation procedure and no HSM/OpenBao custody**. Until that exists, treat key compromise as: stop the platform, revoke all approved manifests, rotate by deploying a new key id and re-approving manifests **(unverified; design only)**.
