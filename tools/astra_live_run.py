"""Drive one synthetic assessment with AI assist through a running AISW server, then summarise
what the model did: narratives shown, agent validation verdicts, and what was held for review.

Start the server against Astra first (from backend/):
    AISW_E2E_ENV_FILE=../.env.astra AISW_E2E_PORT=8199 uv run python e2e/server.py
Then:
    uv run python ../tools/astra_live_run.py --base http://127.0.0.1:8199 [--fixture-set baseline-ok]

Uses the dev identity stub (alice requests, bob approves, carol reads). Synthetic fixture data only.
Prints no secrets: the server holds the key; this script never sees it.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

GROUP = "fixture-group-1"
EXPECTED = ["host-1", "host-2", "host-3"]
TERMINAL = {"REPORT_READY", "PARTIAL", "FAILED", "CANCELLED", "EXPIRED", "CLOSED"}


class Api:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/") + "/api/v1"

    def __call__(self, method: str, path: str, user: str, body: Any = None) -> Any:
        headers = {"Authorization": f"Bearer dev-{user}", "Idempotency-Key": uuid.uuid4().hex}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urlopen(req, timeout=60) as r:  # noqa: S310 - loopback test server
                return json.loads(r.read() or b"null")
        except HTTPError as e:
            raise SystemExit(f"{method} {path} -> {e.code}: {e.read()[:500]!r}") from None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8199")
    ap.add_argument("--fixture-set", default="baseline-ok")
    ap.add_argument("--timeout", type=float, default=900.0)
    args = ap.parse_args()
    api = Api(args.base)

    agents = api("GET", "/agents", "carol")["ai"]
    if not (agents["enabled"] and agents["validation_enabled"]):
        raise SystemExit(f"server AI not enabled for validation: {agents}")

    pid = api("POST", "/projects", "alice", {"name": f"live-{uuid.uuid4().hex[:6]}",
                                             "environment": "test"})["project_id"]  # fmt: skip
    api("POST", "/inventory", "alice", {"project_id": pid, "kind": "asset_group",
                                        "selector": GROUP, "expected_assets": EXPECTED})  # fmt: skip
    m = api("POST", "/scope-manifests", "alice", {
        "project_id": pid, "targets": [{"kind": "asset_group", "selector": GROUP}],
        "domains": ["host"], "allowed_adapters": ["fixture"],
        "profiles": {"fixture": {"profile_id": "FIXTURE_BASELINE", "profile_class": "READ_ONLY"}},
        "evidence_retention_days": 30, "policy_version": "fixture-baseline:1.0.0",
        "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
    })["manifest"]  # fmt: skip
    api("POST", f"/scope-manifests/{m['manifest_id']}/preflight", "alice")
    m = api("POST", f"/scope-manifests/{m['manifest_id']}/approve", "bob", {})
    run_id = api("POST", "/assessments", "alice", {
        "project_id": pid, "scope_manifest_id": m["manifest_id"],
        "scope_manifest_hash": m["canonical_hash"], "assessment_profile": "baseline-readonly-v1",
        "adapter_params": {"fixture": {"fixture_set": args.fixture_set}}, "ai_assist": True,
    })["run_id"]  # fmt: skip
    print(f"run {run_id} launched ({args.fixture_set})", file=sys.stderr)

    started, state = time.monotonic(), ""
    while time.monotonic() - started < args.timeout:
        new = api("GET", f"/assessments/{run_id}", "alice")["state"]
        if new != state:
            print(f"  {time.monotonic() - started:6.1f}s  {new}", file=sys.stderr)
            state = new
        if state in TERMINAL:
            break
        time.sleep(1.0)
    elapsed = round(time.monotonic() - started, 1)

    val = api("GET", f"/assessments/{run_id}/ai-validations", "carol")
    reports = api("GET", f"/assessments/{run_id}/reports", "carol")
    rep = api("GET", f"/reports/{reports[0]['report_id']}", "carol") if reports else {}
    print(json.dumps({
        "run_id": run_id, "state": state, "elapsed_s": elapsed,
        "validation_summary": val["summary"],
        "attention": [
            {k: i[k] for k in ("agent_id", "target_ref", "verdict", "effect", "issues",
                               "human_questions", "validator_confidence", "defects")}
            for i in val["items"] if i["verdict"] != "CONCUR"
        ],
        "report": {
            "ai": rep.get("ai"), "model_versions": rep.get("model_versions"),
            "findings_accepted": len(rep.get("findings", [])),
            "pending_review": [f["finding_id"] for f in rep.get("pending_review", [])],
            "scenarios": len(rep.get("scenarios", [])),
            "recommendations": len(rep.get("recommendations", [])),
            "limitations": rep.get("limitations"),
        },
    }, indent=2))  # fmt: skip
    return 0 if state in {"REPORT_READY", "PARTIAL"} and val["summary"]["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
