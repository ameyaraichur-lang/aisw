"""Egress allow-list: print it, render host-firewall rules, or verify it from the host (ADR-028).

Usage (from backend/):
  uv run python ../tools/egress_check.py plan   [--env-file F]
  uv run python ../tools/egress_check.py render [--env-file F] --role worker --format nftables \
      [--user aisw] [--resolve] [--out FILE]
  uv run python ../tools/egress_check.py verify [--env-file F] --role worker \
      [--deny HOST:PORT ...] [--json FILE]

``render`` resolves hostnames only with --resolve (otherwise they are left out: fails closed).
``verify`` TCP-connects to each control-plane destination for the role (expect success) and to each
--deny canary (expect failure); choose canaries that are reachable when no firewall is present.
Prints no secrets. Exit code: 0 ok, 1 a probe failed, 2 misconfigured.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aisw.core import egress
from aisw.core.config import Settings


def _target(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        raise argparse.ArgumentTypeError(f"expected HOST:PORT, got {text!r}")
    return host.strip("[]"), int(port)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["plan", "render", "verify"])
    ap.add_argument("--env-file")
    ap.add_argument("--role", choices=egress.ROLES, default="worker")
    ap.add_argument("--format", choices=["nftables", "iptables", "ip6tables"], default="nftables")
    ap.add_argument("--user", default="aisw")
    ap.add_argument("--resolve", action="store_true")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--deny", type=_target, action="append", default=[])
    ap.add_argument("--json", type=Path)
    args = ap.parse_args(argv)
    try:
        settings = Settings(_env_file=args.env_file)  # type: ignore[call-arg]
    except ValueError as exc:
        print(f"misconfigured: {exc}", file=sys.stderr)
        return 2
    dests = egress.destinations(settings)
    if args.command == "plan":
        print(json.dumps(egress.plan(settings), indent=2))
        return 0
    if args.command == "render":
        text = egress.render(dests, args.format, role=args.role, user=args.user,
                             resolver=egress.system_resolver if args.resolve else None)  # fmt: skip
        if args.out:
            args.out.write_text(text)
        else:
            print(text, end="")
        return 0
    allowed = [(d.host, p) for d in egress.for_role(dests, args.role) if not d.is_network
               and d.proto == "tcp" for p in d.ports]  # fmt: skip
    results = egress.probe(allowed, args.deny)
    for r in results:
        print(f"{'PASS' if r.passed else 'FAIL'}  {r.expect:5}  {r.target}: {r.observed}")
    if not args.deny:
        print("note: no --deny canary given, so denial was not tested", file=sys.stderr)
    if args.json:
        args.json.write_text(json.dumps([r.__dict__ for r in results], indent=2) + "\n")
    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
