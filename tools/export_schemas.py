"""Export every public contract as JSON Schema into /schemas (UI types are generated from these).

Usage: python tools/export_schemas.py [--check]   (--check fails if checked-in schemas drifted)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import BaseModel

from aisw.contracts import analysis, assurance, domain, envelope, manifest
from aisw.contracts.audit import AuditEventRecord
from aisw.llm.schema import NarrativeOutput

MODELS: list[type[BaseModel]] = [
    envelope.TaskEnvelope,
    manifest.ScopeManifestBody,
    manifest.ScopeManifest,
    manifest.AuthorizationDecision,
    manifest.ExecutionPermit,
    AuditEventRecord,
    domain.EvidenceArtifact,
    domain.Asset,
    domain.Relationship,
    domain.Observation,
    domain.Finding,
    domain.ControlAssessment,
    domain.Recommendation,
    domain.Validation,
    domain.RiskException,
    domain.CoverageLedger,
    analysis.RiskAssessment,
    analysis.CorrelationScenario,
    assurance.AssuranceResult,
    assurance.ReportBundle,
    NarrativeOutput,
]
OUT = Path(__file__).resolve().parents[1] / "schemas"


def render() -> dict[str, str]:
    return {
        f"{m.__name__}.schema.json": json.dumps(m.model_json_schema(), indent=2, sort_keys=True)
        + "\n"
        for m in MODELS
    }


def main() -> int:
    rendered = render()
    if "--check" in sys.argv:
        drift = [
            n
            for n, text in rendered.items()
            if not (OUT / n).exists() or (OUT / n).read_text() != text
        ]
        extra = {p.name for p in OUT.glob("*.schema.json")} - set(rendered)
        for n in [*drift, *sorted(extra)]:
            print(f"schema drift: {n}")  # noqa: T201
        return 1 if drift or extra else 0
    OUT.mkdir(exist_ok=True)
    for n, text in rendered.items():
        (OUT / n).write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
