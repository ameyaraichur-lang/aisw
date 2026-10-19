# ADR-027: Manifest signing through a Transit-compatible KMS, with a rotation drill

**Status:** Accepted. Implemented and drilled against a loopback Transit emulator; no real KMS is connected yet. Local file keys remain the dev/test default, by the product owner's decision.

## Context
Manifest signatures were made by an Ed25519 key in a local file. There was no rotation, no revocation and no production custody (pending-plan P0-2, threat T20). In prod the app refused to create a signer at all, so nothing could be approved there.

## Decision
- **The signer returns `Signed(key_id, signature)` together.** The scope service records the key id that actually made the signature, so a rotation between two reads cannot mismatch them.
- **`signing_backend=transit`** uses the OpenBao/Vault Transit HTTP API:
  - `sign/<key>` signs, using the latest version;
  - `keys/<key>` publishes one Ed25519 public key per version.
  - The private key is never exported.
  - Key ids are `transit.<key>.v<n>`, which fit the manifest's `key_id` contract unchanged; key names are capped at 48 characters.
  - The KMS token is read from a 0600 file. It never appears in settings, logs or reprs.
  - Calls use the shared control-plane transport (`aisw.core.safe_http`): proxy variables are ignored, redirects refused, responses size-capped, and every call has a timeout. The address must be an https origin; http is accepted only on loopback outside prod.
- **Verification is local.** `KeyRing` loads the KMS's public keys. An unknown key id triggers at most one reload every 30 s. That picks up a rotation without a restart, and garbage key ids cannot flood the KMS. A KMS that is down at startup just means nothing verifies until it is back: the ring fails closed.
- **Every KMS signature is checked locally before it is stored.** A signature from an unknown, revoked or tampered key version is refused.
- **Revocation:** `AISW_SIGNING_REVOKED_KEY_IDS` lists key ids that never verify and never sign. The tool gateway and launch authorisation both use the same ring.
- **Retirement:** set `min_encryption_version` at the KMS. Retired versions cannot sign but still verify. Trimming a version destroys it and is documented as forbidden while manifests reference it.
- **Outage handling:** `SigningError` on approval becomes `503 signer_unavailable` inside the approval transaction, so the manifest state does not change.
- **Least privilege:** the app token can `read` and `sign`. Rotate and config need a separate operator token. The emulator enforces per-token capabilities, so this is tested.
- **Drill:** `aisw.authz.drill` with the CLI `tools/key_rotation_drill.py`. It checks custody (not exportable, deletion disallowed), the probe signature, tamper detection, revocation, rotation, new-version signing, old-version verification and retirement. Probes are signed under their own domain (`aisw-key-drill-v1`), never the manifest domain.

## Consequences
- Prod can now sign manifests, once a Transit key and tokens are provisioned.
- The rotation procedure is executable and its result recorded (`docs/implementation/key-rotation-drill.md`, from the emulator).
- Not yet verified against a real OpenBao, Vault or HSM-backed Transit. The emulator follows the documented API and semantics, but a real run is the remaining step (P0-2), owned by the platform admin.
- An HSM is supported indirectly: Transit can be backed by an HSM (managed keys or seal), with nothing for AISW to change.

## Tests
- `tests/unit/test_transit.py`:
  - sign and verify;
  - least privilege;
  - rotation pickup;
  - retirement;
  - revocation;
  - a tampered KMS signature;
  - outages, both after startup and at a cold start;
  - the refresh throttle;
  - malformed key descriptions and signatures;
  - unsafe addresses and names;
  - token-file permissions;
  - settings wiring;
  - the full, read-only and failing drill variants.
- `tests/integration/test_key_rotation.py`, using real Postgres manifests:
  - a manifest approved under v1 still launches after rotation to v2 and retirement of v1;
  - a revoked v1 blocks launch with `BAD_SIGNATURE`;
  - a KMS outage refuses approval without changing state, while launches continue;
  - the container wires the Transit signer, and the API answers 503 then 200 once the KMS is back.
