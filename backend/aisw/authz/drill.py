"""Key custody drill for the Transit signer (ADR-027): checks custody properties and, with
``rotate=True``, rotates the key and proves the rotation is safe.

Probes are signed under their own domain, so a drill signature can never be mistaken for a
manifest signature. ``rotate=True`` changes the KMS key (new version, older versions retired for
signing) and must be run by an operator holding an admin token, never by the application.
"""

from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass
from typing import Any

from aisw.authz.signing import KeyRing, SigningError
from aisw.authz.transit import TransitClient, TransitSigner, transit_key_id
from aisw.contracts.base import canonical_json

PROBE_DOMAIN = "aisw-key-drill-v1"


@dataclass(frozen=True)
class Step:
    name: str
    passed: bool
    detail: str


def _probe(label: str) -> bytes:
    return canonical_json({"domain": PROBE_DOMAIN, "probe": label, "nonce": secrets.token_hex(8)})


def _ring(client: TransitClient, revoked: tuple[str, ...] = ()) -> KeyRing:
    return KeyRing(revoked=revoked, loader=client.public_keys)


def run_drill(client: TransitClient, *, rotate: bool) -> list[Step]:
    steps: list[Step] = []

    def check(name: str, ok: bool, detail: str) -> bool:
        steps.append(Step(name, ok, detail))
        return ok

    try:
        desc = client.describe()
    except SigningError as exc:
        check("kms_reachable", False, str(exc))
        return steps
    check("kms_reachable", True, f"key {client.key} type {desc['type']}")
    check("key_not_exportable", desc.get("exportable") is False,
          f"exportable={desc.get('exportable')!r}")  # fmt: skip
    check("key_deletion_disallowed", desc.get("deletion_allowed") is not True,
          f"deletion_allowed={desc.get('deletion_allowed')!r}")  # fmt: skip

    before = int(desc["latest_version"])
    ring = _ring(client)
    signer = TransitSigner(client, ring)
    old_payload = _probe("before-rotation")
    old = signer.sign_detached(old_payload)
    check("signs_with_latest_version", old.key_id == transit_key_id(client.key, before), old.key_id)
    check("signature_verifies_locally", ring.verify(old.key_id, old_payload, old.signature),
          "verified with the published public key")  # fmt: skip
    check("tampered_payload_fails", not ring.verify(old.key_id, old_payload + b" ", old.signature),
          "one changed byte is rejected")  # fmt: skip
    check("revoked_key_fails_closed",
          not _ring(client, (old.key_id,)).verify(old.key_id, old_payload, old.signature),
          f"{old.key_id} listed as revoked does not verify")  # fmt: skip
    if not rotate:
        return steps

    try:
        after = client.rotate()
    except SigningError as exc:
        check("rotated", False, str(exc))
        return steps
    check("rotated", after == before + 1, f"v{before} -> v{after}")
    new_payload = _probe("after-rotation")
    new = signer.sign_detached(new_payload)  # the running signer picks up the new version
    check("new_signatures_use_new_version", new.key_id == transit_key_id(client.key, after),
          new.key_id)  # fmt: skip
    fresh = _ring(client)  # as after a restart: only what the KMS publishes
    check("old_signature_still_verifies", fresh.verify(old.key_id, old_payload, old.signature),
          f"{old.key_id} still trusted after rotation")  # fmt: skip
    check(
        "new_signature_verifies", fresh.verify(new.key_id, new_payload, new.signature), new.key_id
    )

    try:
        client.retire_below(after)
    except SigningError as exc:
        check("retired_old_versions", False, str(exc))
        return steps
    check("retired_old_versions", True, f"min_encryption_version={after}")
    try:
        client.sign(_probe("retired"), version=before)
        refused, detail = False, f"v{before} still signs"
    except SigningError as exc:
        refused, detail = True, f"v{before} refused: {exc}"
    check("retired_version_cannot_sign", refused, detail)
    check("old_signature_verifies_after_retirement",
          _ring(client).verify(old.key_id, old_payload, old.signature),
          "retirement does not invalidate existing manifests")  # fmt: skip
    return steps


def passed(steps: list[Step]) -> bool:
    return bool(steps) and all(s.passed for s in steps)


def report(steps: list[Step], **context: Any) -> dict[str, Any]:
    return {**context, "passed": passed(steps), "steps": [asdict(s) for s in steps]}


def render_markdown(rep: dict[str, Any]) -> str:
    lines = [
        "# Signing-key rotation drill", "",
        f"Target: {rep.get('target', 'unknown')}. Key: `{rep.get('key')}`. "
        f"Rotated: {'yes' if rep.get('rotate') else 'no'}. Result: "
        f"**{'PASS' if rep['passed'] else 'FAIL'}**.", "",
        "| Step | Result | Detail |", "|---|---|---|",
    ]  # fmt: skip
    for s in rep["steps"]:
        detail = str(s["detail"]).replace("|", "\\|")
        lines.append(f"| `{s['name']}` | {'PASS' if s['passed'] else 'FAIL'} | {detail} |")
    return "\n".join(lines) + "\n"
