"""Builders for analysis-layer unit tests (synthetic data only)."""

from __future__ import annotations

from datetime import UTC, datetime

from aisw.contracts.analysis import RiskFactors
from aisw.contracts.domain import Finding
from aisw.contracts.enums import Confidence, PolicyOutcome, Severity

T0 = datetime(2026, 10, 1, tzinfo=UTC)


def finding(
    fid: str,
    *,
    asset: str = "asset-a",
    category: str = "host_configuration",
    severity: Severity = Severity.HIGH,
    title: str | None = None,
) -> Finding:
    return Finding(
        finding_id=fid, stable_dedupe_key=f"dk-{fid}", tenant_id="ten-1", project_id="prj-1",
        run_id="run-1", title=title or f"Synthetic weakness {fid}", category=category,
        severity=severity, severity_source="fixture", confidence=Confidence.MEDIUM,
        outcome=PolicyOutcome.FAIL, affected_assets=[asset], evidence_refs=[f"ev-{fid}"],
        policy_version="p-1", first_observed=T0, last_observed=T0,
    )  # fmt: skip


def factors(
    severity: str = "HIGH", criticality: str | None = "high", exposure: str = "VERIFIED",
    fresh: bool = True, sources: int = 1,
) -> RiskFactors:  # fmt: skip
    return RiskFactors(
        severity=severity, criticality=criticality, exposure=exposure,
        evidence_fresh=fresh, corroborating_sources=sources,
    )  # fmt: skip
