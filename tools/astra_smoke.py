"""Live Astra smoke test: one narrative on a synthetic subject through the real gateway path.

Usage (from backend/): uv run python ../tools/astra_smoke.py [--env-file ../.env.astra] [--deployment NAME]

Sends only the fixed synthetic subject below. Prints status, defects, latency and the validated
output; never prints the API key.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from aisw.core.config import ModelProvider, Settings
from aisw.llm.client import AstraClient
from aisw.llm.factory import build_model_client
from aisw.llm.gateway import LlmGateway
from aisw.llm.schema import Fact, NarrativeSubject

SUBJECT = NarrativeSubject(
    purpose="scenario",
    subject_ref="smoke-sc-1",
    title="Two weaknesses on synthetic host smoke-a",
    tier="P2",
    facts=[
        Fact(
            finding_id="smoke-f1",
            title="SSH root login permitted",
            severity="HIGH",
            category="host_configuration",
            asset_ids=["smoke-a"],
            evidence_refs=["ev-smoke-f1"],
            control_ids=["CIS 5.2.10"],
        ),
        Fact(
            finding_id="smoke-f2",
            title="Telnet service reachable on port 23",
            severity="HIGH",
            category="network_exposure",
            asset_ids=["smoke-a"],
            evidence_refs=["ev-smoke-f2"],
        ),
    ],
    context=["Synthetic fixture data. Exploitability was not tested."],
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env-file", default=str(Path(__file__).resolve().parents[1] / ".env.astra"))
    ap.add_argument("--deployment", help="override AISW_MODEL_ID for this run")
    args = ap.parse_args()
    overrides = {"model_id": args.deployment} if args.deployment else {}
    settings = Settings(_env_file=args.env_file, **overrides)  # type: ignore[call-arg]
    if settings.model_provider is not ModelProvider.ASTRA or not settings.ai_enabled:
        print("env file does not enable the astra provider", file=sys.stderr)  # noqa: T201
        return 2
    client = build_model_client(settings)
    assert isinstance(client, AstraClient)
    started = time.monotonic()
    res = LlmGateway(client, timeout=settings.model_timeout_seconds).narrate(SUBJECT)
    report = {
        "deployment": res.model_id,
        "status": res.status,
        "defects": res.defects,
        "attempts": res.attempts,
        "latency_s": round(time.monotonic() - started, 2),
        "output": res.output.model_dump() if res.output else None,
    }
    print(json.dumps(report, indent=2))  # noqa: T201
    return 0 if res.status == "VALIDATED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
