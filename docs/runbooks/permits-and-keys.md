# Permits, manifests and signing keys

**Permits** authorise one run for 15 minutes. While a run is still dispatching, the worker renews a permit that is within 5 minutes of expiry, but only if the *full launch policy* still passes (manifest approved, signature valid, unexpired, hash unchanged, inventory unchanged, connector health). Renewal is capped at 8 renewals and 2 hours per run and never outlives the manifest. A **revoked** or **lapsed** permit is never renewed: launch again.

Revoke a run's authority: `ScopeService.revoke_permit` (operator, `assessment:cancel`) revokes **every** permit of the run. Revoke a manifest to stop all future launches and renewals (`MANIFEST_NOT_APPROVED`).

Audit: `permit.renew`, `permit.revoke`, `manifest.revoke`, `assessment.authorize` are in the hash-chained audit trail (`GET /api/v1/audit/events`, `GET /api/v1/audit/verify`).

**Signing keys (ADR-027).** Manifests are signed with Ed25519. Two custody options:

- `AISW_SIGNING_BACKEND=local_file` (the default; dev/test only). The private key is a local file at `AISW_SIGNING_KEY_PATH`, created with mode 0600 on first use; the app refuses to create one in prod. There is no rotation for this backend: to rotate, deploy a new key id and re-approve manifests.
- `AISW_SIGNING_BACKEND=transit`. A Transit-compatible KMS (OpenBao or Vault Transit) holds the key, and the private key never leaves it. Configure:
  - `AISW_KMS_ADDR` (https);
  - `AISW_KMS_KEY` (an `ed25519` key, `exportable=false`, `deletion_allowed=false`);
  - `AISW_KMS_MOUNT` (default `transit`);
  - `AISW_KMS_NAMESPACE` (optional);
  - `AISW_KMS_TOKEN_FILE`: a 0600 file written by the secret provider, holding a token whose policy allows only `read` on `transit/keys/<key>` and `update` on `transit/sign/<key>`, and never rotate or config.

  Key ids are recorded on each manifest as `transit.<key>.v<n>`. Verification is local, against the public keys the KMS publishes, so approved manifests keep launching during a KMS outage. A new approval during an outage gets `503 signer_unavailable` and changes nothing.

**Rotation.** An operator rotates with an admin token; the app token cannot. Run the drill first. It is the same procedure, with every step checked:
```
cd backend && uv run python ../tools/key_rotation_drill.py --addr https://kms:8200 --key aisw-manifests \
    --token-file /run/secrets/kms-admin-token --rotate --markdown /tmp/drill.md
```
It checks custody (not exportable, deletion disallowed), signs and verifies a probe under its own domain, and rotates. It then confirms that new signatures use the new version, old signatures still verify, and the retired version cannot sign. The running API picks up the new version on its next signature; no restart is needed. **Never trim** (`min_decryption_version`) a version that an approved, unexpired manifest still references: its signature would stop verifying.

**Compromise.** Add the compromised key id to `AISW_SIGNING_REVOKED_KEY_IDS` (comma-separated) and restart. Manifests signed with that id then fail with `BAD_SIGNATURE` at launch and in the tool gateway, and the signer refuses to use it. Rotate at the KMS, then re-approve the affected manifests.

The drill has been run only against the loopback emulator (`docs/implementation/key-rotation-drill.md`). **Running it against a real KMS is pending (unverified):** the owner is the platform admin, and the next step is to provision the Transit key and the two tokens.
