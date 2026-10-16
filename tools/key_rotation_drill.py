"""Run the signing-key custody and rotation drill against a Transit-compatible KMS (ADR-027).

Usage (from backend/):
  # against the local emulator (no external access; what CI and the docs use)
  uv run python ../tools/key_rotation_drill.py --emulator --rotate \
      [--json ../docs/implementation/key-rotation-drill.json] [--markdown ...md]
  # against a real KMS, by an operator with an admin token file (0600)
  uv run python ../tools/key_rotation_drill.py --addr https://kms.example:8200 --key aisw-manifests \
      --token-file /run/secrets/kms-admin-token [--mount transit] [--namespace ns] [--rotate]

Without --rotate only read-only custody checks and a probe signature run. Prints no token.
Exit code: 0 all steps passed, 1 a step failed, 2 misconfigured.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aisw.authz.drill import render_markdown, report, run_drill
from aisw.authz.signing import SigningError
from aisw.authz.transit import TransitClient, read_token_file
from aisw.core.config import Environment

BACKEND = Path(__file__).resolve().parents[1] / "backend"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--emulator", action="store_true", help="run against a loopback emulator")
    ap.add_argument("--addr")
    ap.add_argument("--key", default="aisw-manifests")
    ap.add_argument("--mount", default="transit")
    ap.add_argument("--namespace")
    ap.add_argument("--token-file", type=Path)
    ap.add_argument("--rotate", action="store_true", help="rotate and retire (changes the KMS key)")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--markdown", type=Path)
    args = ap.parse_args()

    emu = None
    try:
        if args.emulator:
            sys.path.insert(0, str(BACKEND))
            from tests.kms_emulator import TransitEmulator  # noqa: PLC0415 - test-only module

            emu = TransitEmulator(mount=args.mount).start()
            emu.create(args.key)
            client = TransitClient(emu.addr, args.key, emu.admin_token, mount=args.mount,
                                   env=Environment.TEST)  # fmt: skip
            target = "local Transit emulator (loopback)"
        else:
            if not (args.addr and args.token_file):
                print("--addr and --token-file are required without --emulator", file=sys.stderr)
                return 2
            client = TransitClient(
                args.addr, args.key, read_token_file(args.token_file), mount=args.mount,
                namespace=args.namespace,
            )  # fmt: skip
            target = args.addr
    except SigningError as exc:
        print(f"misconfigured: {exc}", file=sys.stderr)
        return 2
    try:
        steps = run_drill(client, rotate=args.rotate)
    finally:
        if emu is not None:
            emu.close()
    rep = report(steps, target=target, key=args.key, rotate=args.rotate)
    for s in steps:
        print(f"{'PASS' if s.passed else 'FAIL'}  {s.name}: {s.detail}")
    if args.json:
        args.json.write_text(json.dumps(rep, indent=2) + "\n")
    if args.markdown:
        args.markdown.write_text(render_markdown(rep))
    return 0 if rep["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
