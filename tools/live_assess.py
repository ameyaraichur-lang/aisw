"""Run real assessments against a running dev stack (tools/dev_stack.py) through its public API.

Each scenario is a project with inventory, a scope manifest that alice drafts and preflights and
bob approves, optional scanner imports, and a launch. The script then waits for the run and prints
what the platform concluded. Only targets the product owner authorised are defined here:

  example-com       passive URL probe of https://example.com/ (port 443 only)
  local-portal      passive URL probe of this stack's console and API on loopback
  workstation       an Nmap import of this machine, run with the approved bounded profile
  base-images       a Trivy import of the product's own container base images

Run from backend/ with its virtualenv:  .venv/bin/python ../tools/live_assess.py [names...] [--ai]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCANS = ROOT / "data" / "dev-stack" / "scans"
TERMINAL = {"REPORT_READY", "HUMAN_REVIEW", "CLOSED", "PARTIAL", "FAILED", "CANCELLED", "EXPIRED"}
URL_PROFILE = {"url_smoke": {"profile_id": "PASSIVE_HTTP_SMOKE", "profile_class": "READ_ONLY"}}


def nmap_root(scan: Path) -> Any:
    import xml.etree.ElementTree as ET  # noqa: S405 - our own scanner output, parsed again by the API

    return ET.parse(scan).getroot()  # noqa: S314


# Expected asset ids must be derived exactly as the adapters derive them, or nothing reconciles.
def _h(key: str, n: int) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:n]


def expected_urls(selector: str) -> list[str]:
    u = urllib.parse.urlsplit(selector)
    port = u.port or (443 if u.scheme == "https" else 80)
    return ["url-" + _h(f"{u.scheme}://{u.hostname}:{port}", 12)]


def expected_hosts(pattern: str) -> list[str]:
    root = nmap_root(sorted(SCANS.glob(pattern))[0])
    ips = [a.get("addr") for h in root.iter("host") for a in h.iter("address")
           if a.get("addrtype") in {"ipv4", "ipv6"}]  # fmt: skip
    return sorted("ip-" + _h(ip, 12) for ip in ips if ip)


def expected_images(pattern: str) -> list[str]:
    ids = []
    for f in sorted(SCANS.glob(pattern)):
        r = json.loads(f.read_text())
        meta = r.get("Metadata") or {}
        digest = (meta.get("RepoDigests") or [""])[0] or meta.get("ImageID", "")
        ids.append("img-" + _h(f"{r['ArtifactName']}|{digest}", 14))
    return sorted(ids)


SCENARIOS: dict[str, dict[str, Any]] = {
    "example-com": {
        "name": "example.com public site",
        "environment": "external",
        "inventory": [("url", "https://example.com/")],
        "manifest": {
            "domains": ["url"],
            "allowed_adapters": ["url_smoke"],
            "profiles": URL_PROFILE,
            "allowed_ports": [443],
            "policy_version": "url-smoke-baseline:1.0.0",
        },  # fmt: skip
        "params": {"url_smoke": {}},
    },
    "local-portal": {
        "name": "AISW local portal",
        "environment": "dev",
        "inventory": [("url", "http://127.0.0.1:5173/"), ("url", "http://127.0.0.1:8000/healthz")],
        "manifest": {
            "domains": ["url"],
            "allowed_adapters": ["url_smoke"],
            "profiles": URL_PROFILE,
            "allowed_ports": [5173, 8000],
            "internal_range_authorization": ["127.0.0.1/32"],
            "policy_version": "url-smoke-baseline:1.0.0",
        },  # fmt: skip
        "params": {"url_smoke": {}},
    },
    "workstation": {
        "name": "This workstation",
        "environment": "dev",
        "inventory": [("asset_group", "this-workstation")],
        "manifest": {
            "domains": ["network"],
            "allowed_adapters": ["nmap_import"],
            "profiles": {
                "nmap_import": {"profile_id": "NMAP_BOUNDED_IMPORT", "profile_class": "READ_ONLY"}
            },
            "policy_version": "import-baseline:1.0.0",
        },  # fmt: skip
        "imports": {"nmap_import": ("nmap_xml", "nmap-workstation.xml")},
        "params": {"nmap_import": {"vantage": "internal"}},
    },
    "base-images": {
        "name": "AISW container base images",
        "environment": "dev",
        "inventory": [("asset_group", "aisw-base-images")],
        "manifest": {
            "domains": ["container"],
            "allowed_adapters": ["trivy_import"],
            "profiles": {
                "trivy_import": {
                    "profile_id": "TRIVY_IMAGE_REPORT_IMPORT",
                    "profile_class": "READ_ONLY",
                }
            },
            "policy_version": "image-baseline:1.0.0",
        },  # fmt: skip
        "imports": {"trivy_import": ("trivy_json", "trivy-*.json")},
        "params": {"trivy_import": {}},
    },
}


class Api:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")

    def call(self, method: str, path: str, user: str = "alice", ok: tuple[int, ...] = (200, 201, 202),
             idem: bool = False, json_body: Any = None, params: dict[str, Any] | None = None) -> Any:  # fmt: skip
        headers = {"Authorization": f"Bearer dev-{user}", "Content-Type": "application/json"}
        if idem:
            headers["Idempotency-Key"] = uuid.uuid4().hex
        url = self.base + path + (f"?{urllib.parse.urlencode(params)}" if params else "")
        data = None if json_body is None else json.dumps(json_body).encode()
        req = urllib.request.Request(url, data=data, headers=headers, method=method)  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 - loopback dev API
                status, raw = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        if status not in ok:
            raise SystemExit(
                f"{method} {path} as {user}: HTTP {status}: {raw[:600].decode(errors='replace')}"
            )
        return json.loads(raw) if raw else None


def import_content(kind: str, pattern: str) -> tuple[str, str]:
    files = sorted(SCANS.glob(pattern))
    if not files:
        raise SystemExit(f"no scan output matching {SCANS / pattern}; run the scans first")
    if kind == "nmap_xml":
        print(f"    nmap arguments: {nmap_root(files[0]).get('args', '')}")
        return files[0].name, files[0].read_text()
    reports = [json.loads(f.read_text()) for f in files]
    return "trivy-images.json", json.dumps(reports if len(reports) > 1 else reports[0])


def project_id(api: Api, name: str, environment: str) -> str:
    listing = api.call("GET", "/api/v1/projects")
    rows = listing["items"] if isinstance(listing, dict) else listing
    for p in rows:
        if p["name"] == name:
            return str(p["project_id"])
    made = api.call("POST", "/api/v1/projects", idem=True,
                    json_body={"name": name, "environment": environment, "owner": "alice"})  # fmt: skip
    return str(made["project_id"])


def run(api: Api, key: str, ai: bool, timeout: float) -> str:
    s = SCENARIOS[key]
    print(f"\n=== {s['name']} ({key})")
    pid = project_id(api, s["name"], s["environment"])
    targets = []
    for kind, selector in s["inventory"]:
        if kind == "url":
            expected = expected_urls(selector)
        else:
            adapter, (import_kind, pattern) = next(iter(s["imports"].items()))
            expected = (expected_hosts if import_kind == "nmap_xml" else expected_images)(pattern)
            # Inventory entries cannot be edited, so a changed scan set gets its own selector.
            selector = f"{selector}-{_h('|'.join(expected), 6)}"
        api.call("POST", "/api/v1/inventory", ok=(201, 409),
                 json_body={"project_id": pid, "kind": kind, "selector": selector,
                            "expected_assets": expected})  # fmt: skip
        targets.append({"kind": kind, "selector": selector})
        print(f"    inventory {kind} {selector}: expects {expected}")
    body = {
        "project_id": pid, "targets": targets,
        "evidence_retention_days": 30,
        "expires_at": (datetime.now(UTC) + timedelta(days=7)).isoformat(), **s["manifest"],
    }  # fmt: skip
    m = api.call("POST", "/api/v1/scope-manifests", json_body=body)["manifest"]
    pf = api.call("POST", f"/api/v1/scope-manifests/{m['manifest_id']}/preflight")
    issues = [i["code"] for i in (pf.get("issues") or [])]
    print(f"    scope {m['manifest_id']} preflight: {pf.get('decision', {}).get('decision', '?')}"
          + (f" {issues}" if issues else ""))  # fmt: skip
    m = api.call("POST", f"/api/v1/scope-manifests/{m['manifest_id']}/approve", "bob", json_body={})
    params = json.loads(json.dumps(s["params"]))
    for adapter, (kind, pattern) in s.get("imports", {}).items():
        filename, content = import_content(kind, pattern)
        imp = api.call("POST", "/api/v1/imports",
                       json_body={"project_id": pid, "kind": kind, "filename": filename, "content": content})  # fmt: skip
        params[adapter]["import_id"] = imp["import_id"]
        print(f"    uploaded {filename} as {imp['import_id']} ({len(content):,} bytes)")
    launched = api.call("POST", "/api/v1/assessments", idem=True, json_body={
        "project_id": pid, "scope_manifest_id": m["manifest_id"],
        "scope_manifest_hash": m["canonical_hash"], "assessment_profile": "baseline-readonly-v1",
        "adapter_params": params, "ai_assist": ai,
    })  # fmt: skip
    run_id = str(launched["run_id"])
    deadline = time.monotonic() + timeout
    while (st := api.call("GET", f"/api/v1/assessments/{run_id}"))["state"] not in TERMINAL:
        if time.monotonic() > deadline:
            print(f"    run {run_id} still {st['state']} after {timeout:.0f}s")
            return run_id
        time.sleep(2)
    summarize(api, run_id, st, ai)
    return run_id


def wait_for_ai(api: Api, run_id: str, settle: float = 8, limit: float = 180) -> Any:
    """Narratives are written after the report is ready; wait until the call count stops moving."""
    deadline, seen, calls = time.monotonic() + limit, -1, None
    while time.monotonic() < deadline:
        calls = api.call("GET", f"/api/v1/assessments/{run_id}/model-calls")
        if calls["totals"]["calls"] and calls["totals"]["calls"] == seen:
            break
        seen = calls["totals"]["calls"]
        time.sleep(settle)
    return calls


def summarize(api: Api, run_id: str, st: dict[str, Any], ai: bool) -> None:
    print(f"    run {run_id}: {st['state']}  tasks {st.get('tasks')}")
    for ev in api.call("GET", f"/api/v1/assessments/{run_id}/events", params={"limit": 500})[
        "events"
    ]:
        p = ev["payload"]
        codes = p.get("error_codes", []) + p.get("warning_codes", [])
        if ev["type"] in {"task.failed", "task.partial", "task.completed"} and codes:
            print(f"    {ev['type']}: {codes}")
    controls = api.call("GET", f"/api/v1/assessments/{run_id}/controls")
    print("    controls: " + ", ".join(f"{c['control_id']}={c['outcome']}" for c in controls))
    items = api.call("GET", f"/api/v1/assessments/{run_id}/findings")["items"]
    sev = Counter(i["severity"] for i in items)
    print(f"    findings ({len(items)}): {dict(sev)}")
    for i in items:
        print(f"      [{i['severity']}] {i['title']}")
    calls = wait_for_ai(api, run_id) if ai else {"totals": {"calls": 0}}
    if calls["totals"]["calls"]:
        status = Counter(c["status"] for c in calls["items"])
        print(f"    AI narratives: {calls['totals']['calls']} calls {dict(status)}")
        v = api.call("GET", f"/api/v1/assessments/{run_id}/ai-validations")["summary"]
        print(f"    AI validation: {v['by_verdict']}  held for review: {v['held_for_review']}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("scenarios", nargs="*", metavar="|".join(SCENARIOS))
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument(
        "--ai", action="store_true", help="request AI assist (the stack must run with --ai)"
    )
    ap.add_argument("--timeout", type=float, default=300)
    a = ap.parse_args()
    if unknown := sorted(set(a.scenarios) - set(SCENARIOS)):
        ap.error(f"unknown scenario(s): {', '.join(unknown)}")
    api = Api(a.api)
    ids = {k: run(api, k, a.ai, a.timeout) for k in (a.scenarios or SCENARIOS)}
    print("\nruns:", json.dumps(ids, indent=2))


if __name__ == "__main__":
    sys.exit(main())
