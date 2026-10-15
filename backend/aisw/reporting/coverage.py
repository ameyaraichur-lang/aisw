"""Coverage ledger construction (blueprint 2.1). Completeness is derived, never asserted.

Expected assets come from the inventory snapshot taken when the run was queued (the CMDB side);
discovered assets come from the tool. Anything expected-but-missing, unreachable, unsupported or
unexpected stays visible as a count and as a named reason. Missing evidence is never PASS.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from aisw.contracts.domain import CoverageLedger
from aisw.contracts.enums import PolicyOutcome


def build_ledger(
    *,
    tenant_id: str,
    run_id: str,
    segment: str,
    expected: list[str],
    statuses: Mapping[
        str, tuple[str, str | None]
    ],  # asset_id -> (SCANNED|UNREACHABLE|UNSUPPORTED, reason)
    asset_outcomes: Mapping[str, PolicyOutcome],
    source_ok: bool,
    source_reasons: list[str],
    last_success_at: datetime | None,
) -> CoverageLedger:
    expected_set, found = set(expected), set(statuses)
    absent = sorted(expected_set - found)
    unexpected = sorted(found - expected_set)
    unreachable = sorted(a for a, (s, _) in statuses.items() if s == "UNREACHABLE")
    unsupported = sorted(a for a, (s, _) in statuses.items() if s == "UNSUPPORTED")

    reasons = list(source_reasons)
    if not statuses:
        reasons.append("ZERO_ASSETS_RETURNED")  # tool said "success" but saw nothing: anomaly
        source_ok = False
    reasons += [f"EXPECTED_ASSET_ABSENT:{a}" for a in absent]
    reasons += [f"ASSET_UNREACHABLE:{a}:{statuses[a][1] or 'no reason'}" for a in unreachable]
    reasons += [f"ASSET_UNSUPPORTED:{a}:{statuses[a][1] or 'no reason'}" for a in unsupported]
    reasons += [f"UNEXPECTED_ASSET:{a}" for a in unexpected]  # unmatched queue; owner unknown

    by_outcome: dict[PolicyOutcome, int] = {}
    for asset in sorted(expected_set | found):
        status = statuses.get(asset, ("ABSENT", None))[0]
        if status == "SCANNED":
            outcome = asset_outcomes.get(asset, PolicyOutcome.NOT_ASSESSED)
        elif status == "UNREACHABLE":
            outcome = PolicyOutcome.UNKNOWN
        else:  # unsupported or absent
            outcome = PolicyOutcome.NOT_ASSESSED
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1

    return CoverageLedger(
        tenant_id=tenant_id, run_id=run_id, segment=segment,
        expected_count=len(expected_set), discovered_count=len(found),
        reconciled_count=len(expected_set & found), excluded_count=0,
        unsupported_count=len(unsupported), unknown_count=len(absent) + len(unreachable),
        assessed_by_outcome=by_outcome, source_ok=source_ok, last_success_at=last_success_at,
        reasons=reasons if (reasons or not source_ok) else [],
    )  # fmt: skip
