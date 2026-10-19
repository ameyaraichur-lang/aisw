# Signing-key rotation drill

Target: local Transit emulator (loopback). Key: `aisw-manifests`. Rotated: yes. Result: **PASS**.

| Step | Result | Detail |
|---|---|---|
| `kms_reachable` | PASS | key aisw-manifests type ed25519 |
| `key_not_exportable` | PASS | exportable=False |
| `key_deletion_disallowed` | PASS | deletion_allowed=False |
| `signs_with_latest_version` | PASS | transit.aisw-manifests.v1 |
| `signature_verifies_locally` | PASS | verified with the published public key |
| `tampered_payload_fails` | PASS | one changed byte is rejected |
| `revoked_key_fails_closed` | PASS | transit.aisw-manifests.v1 listed as revoked does not verify |
| `rotated` | PASS | v1 -> v2 |
| `new_signatures_use_new_version` | PASS | transit.aisw-manifests.v2 |
| `old_signature_still_verifies` | PASS | transit.aisw-manifests.v1 still trusted after rotation |
| `new_signature_verifies` | PASS | transit.aisw-manifests.v2 |
| `retired_old_versions` | PASS | min_encryption_version=2 |
| `retired_version_cannot_sign` | PASS | v1 refused: kms POST sign: answered 400 |
| `old_signature_verifies_after_retirement` | PASS | retirement does not invalidate existing manifests |
