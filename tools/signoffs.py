"""Render and check the sign-off register (P0-6, P0-7, A-1).

Usage (from the repo root or backend/):
  python tools/signoffs.py           # write docs/implementation/signoffs.md
  python tools/signoffs.py --check   # fail on drift, missing artefacts or stale approvals
  python tools/signoffs.py --hash backend/aisw/policy/rubrics/risk-rubric-1.0.0.json
                                     # sha256 to record with a decision
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aisw.policy.signoffs import builtin, problems, render_markdown, sha256_file

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "implementation" / "signoffs.md"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--hash", type=Path, metavar="ARTEFACT")
    args = ap.parse_args()
    if args.hash:
        print(sha256_file(args.hash))
        return 0
    register = builtin()
    issues = problems(register, ROOT)
    for issue in issues:
        print(f"sign-off: {issue}", file=sys.stderr)
    text = render_markdown(register)
    if args.check:
        if not OUT.is_file() or OUT.read_text() != text:
            print(f"{OUT.relative_to(ROOT)} is stale; run python tools/signoffs.py", file=sys.stderr)
            return 1
        return 1 if issues else 0
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
