"""Live validation harness (M9, ADR-045): authorisation gate and report checks for real targets.

The harness never contacts a target. A run is launched, approved (two people) and executed through
the console as usual; this module decides whether a target may be run at all, and checks the
exported report against what the plan expects.

  python -m aisw.validation.live preflight [--plan PATH] [--target ID]
      exit 0 only when every selected target is authorised now
  python -m aisw.validation.live evaluate --target ID --report REPORT.json [--plan PATH]
      [--results OUT.md]

A non-loopback target is authorised only when the `live-validation` sign-off is APPROVED for the
exact plan file (its sha256) and the target's own authorisation names who authorised it, a
reference, and a window that contains now. Loopback targets need no sign-off.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import AwareDatetime, Field, model_validator

from aisw.contracts.base import NonEmpty, StrictModel
from aisw.policy.signoffs import Register, builtin, sha256_file

SIGNOFF_ID = "live-validation"
REPO = Path(__file__).resolve().parents[3]
DEFAULT_PLAN = REPO / "docs" / "implementation" / "live-validation" / "plan.json"
Outcome = Literal["PASS", "FAIL", "NOT_APPLICABLE", "NOT_ASSESSED", "UNKNOWN", "ERROR"]


class Authorisation(StrictModel):
    by: NonEmpty
    reference: NonEmpty
    window_start: AwareDatetime
    window_end: AwareDatetime

    @model_validator(mode="after")
    def _ordered(self) -> Authorisation:
        if self.window_end <= self.window_start:
            raise ValueError("authorisation window must end after it starts")
        return self


class Target(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    kind: Literal["url", "host"]
    selector: NonEmpty
    method: Literal["platform", "operator_import"]
    adapter: NonEmpty
    policy_version: NonEmpty
    allowed_ports: list[int] = Field(default_factory=list)
    operator_command: str | None = None  # what the operator runs by hand for an import target
    authorisation: Authorisation | None = None
    expect: dict[str, Outcome] = Field(default_factory=dict)  # control id -> outcome on the target
    note: str = ""

    @property
    def host(self) -> str:
        return (urlsplit(self.selector).hostname or "") if self.kind == "url" else self.selector

    @property
    def loopback(self) -> bool:
        try:
            return ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            return self.host == "localhost"


class Plan(StrictModel):
    version: NonEmpty
    note: str = ""
    targets: list[Target]

    @model_validator(mode="after")
    def _unique(self) -> Plan:
        ids = [t.id for t in self.targets]
        if len(ids) != len(set(ids)):
            raise ValueError("target ids must be unique")
        return self

    def target(self, target_id: str) -> Target:
        for t in self.targets:
            if t.id == target_id:
                return t
        raise KeyError(f"no target {target_id!r} in the plan")


def load_plan(path: Path) -> Plan:
    return Plan.model_validate(json.loads(path.read_text(encoding="utf-8")))


def authorise(target: Target, plan_path: Path, register: Register, now: datetime) -> list[str]:
    """Reasons the target may NOT be run now; empty means authorised."""
    if target.loopback:
        return []
    problems = []
    s = register.get(SIGNOFF_ID)
    if s is None or s.status != "APPROVED" or s.decision is None:
        problems.append(f"SIGNOFF_NOT_APPROVED:{SIGNOFF_ID}")
    elif s.decision.sha256 != sha256_file(plan_path):
        problems.append("PLAN_CHANGED_SINCE_APPROVAL")
    a = target.authorisation
    if a is None:
        problems.append("TARGET_NOT_AUTHORISED")
    elif not a.window_start <= now <= a.window_end:
        problems.append("OUTSIDE_AUTHORISED_WINDOW")
    return problems


def control_outcomes(report: dict[str, Any]) -> dict[str, str]:
    """{control id: worst outcome across assets} from a report body."""
    rank = {"FAIL": 5, "ERROR": 4, "UNKNOWN": 3, "NOT_ASSESSED": 2, "PASS": 1, "NOT_APPLICABLE": 0}
    out: dict[str, str] = {}
    for c in report.get("controls", []):
        cid, outcome = c.get("control_id"), c.get("outcome")
        if cid and outcome and rank.get(outcome, 6) >= rank.get(out.get(cid, ""), -1):
            out[cid] = outcome
    return out


def evaluate(target: Target, report: dict[str, Any]) -> tuple[bool, list[str]]:
    """(all expectations met, one line per expectation and per unexpected control)."""
    got = control_outcomes(report)
    lines, ok = [], True
    for cid, want in sorted(target.expect.items()):
        have = got.get(cid, "ABSENT")
        ok &= have == want
        lines.append(
            f"{cid}: expected {want}, got {have}" + ("" if have == want else "  <-- MISMATCH")
        )
    for cid in sorted(set(got) - set(target.expect)):
        lines.append(f"{cid}: {got[cid]} (no expectation recorded)")
    if not target.expect:
        ok = False
        lines.append("no expectations recorded for this target: observations only, not a pass")
    return ok, lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aisw.validation.live")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pre = sub.add_parser("preflight")
    pre.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    pre.add_argument("--target", action="append")
    ev = sub.add_parser("evaluate")
    ev.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    ev.add_argument("--target", required=True)
    ev.add_argument("--report", type=Path, required=True)
    ev.add_argument("--results", type=Path)
    args = ap.parse_args(argv)
    plan = load_plan(args.plan)
    now = datetime.now(UTC)
    if args.cmd == "preflight":
        targets = [plan.target(t) for t in args.target] if args.target else plan.targets
        refused = 0
        for t in targets:
            reasons = authorise(t, args.plan, builtin(), now)
            refused += bool(reasons)
            print(f"{t.id}: {'AUTHORISED' if not reasons else 'REFUSED ' + ', '.join(reasons)}")
        return 1 if refused else 0
    target = plan.target(args.target)
    reasons = authorise(target, args.plan, builtin(), now)
    if reasons:
        print(f"{target.id}: REFUSED {', '.join(reasons)}", file=sys.stderr)
        return 2
    report = json.loads(args.report.read_text(encoding="utf-8"))
    ok, lines = evaluate(target, report)
    text = "\n".join([f"### {target.id} ({now:%Y-%m-%d}): {'MET' if ok else 'NOT MET'}",
                      f"run {report.get('run_id')}", *(f"- {x}" for x in lines)]) + "\n"  # fmt: skip
    print(text, end="")
    if args.results:
        with args.results.open("a", encoding="utf-8") as fh:
            fh.write(text)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
