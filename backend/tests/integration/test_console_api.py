"""Read models and the SSE stream that back the operator console."""

from __future__ import annotations

import json
from typing import Any

import pytest

from aisw.orchestrator.stream import format_sse, stream_events
from tests.slice import Slice

EXPECTED = ["host-1", "host-2", "host-3"]


def parse_sse(raw: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for block in raw.split("\n\n"):
        if not block.strip() or block.startswith(":"):
            continue
        item: dict[str, Any] = {}
        for line in block.split("\n"):
            k, _, v = line.partition(": ")
            item[k] = v
        out.append(item)
    return out


def test_identity_and_auth_mode(sl: Slice) -> None:
    assert sl.client.get("/api/v1/auth/mode").json()["mode"] == "dev_stub"
    users = sl.client.get("/api/v1/auth/mode").json()["users"]
    assert {"alice", "bob", "carol", "dave"} <= {u["name"] for u in users}
    assert "token" not in json.dumps(users).lower()  # names and roles only
    assert sl.client.get("/api/v1/me").status_code == 401
    me = sl.call("GET", "/api/v1/me", "bob").json()
    assert me["roles"] == ["approver"] and "manifest:approve" in me["permissions"]
    assert "assessment:launch" not in me["permissions"]


def test_connectors_and_policy_packs(sl: Slice) -> None:
    c = sl.call("GET", "/api/v1/connectors", "carol").json()
    assert [x["adapter_id"] for x in c] == ["fixture"] and c[0]["read_only"] is True
    assert c[0]["profiles"] == [{"profile_id": "FIXTURE_BASELINE", "profile_class": "READ_ONLY"}]
    packs = sl.call("GET", "/api/v1/policy-packs", "carol").json()
    assert packs[0]["key"] == "fixture-baseline:1.0.0" and packs[0]["rules"] == 3


def test_lists_tasks_controls_and_overview_follow_the_run(sl: Slice) -> None:
    pid, m, run_id = sl.full_run(EXPECTED)
    ov = sl.call("GET", "/api/v1/overview", "alice").json()
    assert ov["runs"]["by_state"].get("AUTHORIZED", 0) >= 1
    assert any(r["run_id"] == run_id for r in ov["active_runs"])
    sl.drain()
    runs = sl.call("GET", f"/api/v1/assessments?project_id={pid}", "carol").json()
    assert runs["total"] == 1 and runs["items"][0]["state"] == "REPORT_READY"
    assert runs["items"][0]["tasks_total"] == 1 and runs["items"][0]["tasks_open"] == 0
    tasks = sl.call("GET", f"/api/v1/assessments/{run_id}/tasks", "alice").json()
    assert tasks[0]["status"] == "SUCCEEDED" and tasks[0]["agent_id"] == "fixture"
    assert tasks[0]["output_refs"] and tasks[0]["contract_version"] == "1.1"
    ctrls = sl.call("GET", f"/api/v1/assessments/{run_id}/controls", "carol").json()
    assert {c["control_id"]: c["outcome"] for c in ctrls} == {
        "FB-1": "FAIL",
        "FB-2": "FAIL",
        "FB-3": "PASS",
    }
    assert all(c["final"] for c in ctrls)
    ov = sl.call("GET", "/api/v1/overview", "alice").json()
    assert (
        ov["coverage"]["runs_considered"] >= 1
        and ov["coverage"]["basis"] == "latest finished run per project"
    )
    assert ov["findings"]["open_critical_high_authoritative"] >= 1 and ov["as_of"]
    manifests = sl.call(
        "GET", f"/api/v1/scope-manifests?project_id={pid}&status=APPROVED", "bob"
    ).json()
    assert [x["manifest_id"] for x in manifests] == [m["manifest_id"]]
    assert manifests[0]["targets"] == ["fixture-group-1"] and manifests[0]["active_profiles"] == []
    inv = sl.call("GET", f"/api/v1/inventory?project_id={pid}", "carol").json()
    assert inv[0]["expected_assets"] == EXPECTED


def test_overview_never_counts_incomplete_coverage_as_complete(sl: Slice) -> None:
    sl.full_run(["host-1", "host-2", "host-3", "host-4"], fixture_set="baseline-partial")
    sl.drain()
    ov = sl.call("GET", "/api/v1/overview", "alice").json()
    cov = ov["coverage"]
    assert cov["segments_incomplete"] >= 1 and cov["unknown"] >= 2 and cov["unsupported"] >= 1
    assert cov["reconciled"] < cov["expected"] or cov["unknown"] > 0
    assert ov["partial_runs"]


def test_finding_detail_links_evidence_observation_and_assurance(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    items = sl.call("GET", f"/api/v1/assessments/{run_id}/findings", "alice").json()["items"]
    root = next(i for i in items if "root login" in i["title"])
    d = sl.call(
        "GET", f"/api/v1/assessments/{run_id}/findings/{root['finding_id']}", "alice"
    ).json()
    assert d["authoritative"] is True and d["assurance"]["verdict"] == "ACCEPT"
    ev = d["evidence"][0]
    assert ev["content_hash"].startswith("sha256:") and ev["source"] == "fixture"
    assert ev["tool_version"] == "fixture-scanner@1.0.0" and ev["collected_at"]
    # observed vs expected is matched to THIS finding's rule, not another failing rule on the host
    assert d["observation"]["rule_id"] == "ssh.permit_root_login"
    assert (d["observation"]["observed_value"], d["observation"]["expected_value"]) == ("yes", "no")
    other = next(i for i in items if "password length" in i["title"])
    d2 = sl.call(
        "GET", f"/api/v1/assessments/{run_id}/findings/{other['finding_id']}", "alice"
    ).json()
    assert d2["observation"]["rule_id"] == "password.min_length"
    assert (d2["observation"]["observed_value"], d2["observation"]["expected_value"]) == (8, 12)
    risk = d["risk_explanation"]
    assert (
        risk["business_risk"] is None
        and risk["ai_narrative"] is None
        and risk["inferred_links"] == []
    )
    assert risk["deterministic"]["severity_source"] == "policy:fixture-baseline:1.0.0"
    assert any(m["mapping_status"] == "NEEDS_REVIEW" for m in d["finding"]["control_mappings"])


def test_finding_detail_access_rules(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    fid = sl.call("GET", f"/api/v1/assessments/{run_id}/findings", "alice").json()["items"][0][
        "finding_id"
    ]
    assert sl.call("GET", f"/api/v1/assessments/{run_id}/findings/{fid}", "dave").status_code in (
        403,
        404,
    )
    assert sl.call("GET", f"/api/v1/assessments/{run_id}/findings/nope", "alice").status_code == 404
    assert sl.client.get(f"/api/v1/assessments/{run_id}/findings/{fid}").status_code == 401


def test_tenant_wide_findings_filters_and_pagination(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    r = sl.call("GET", f"/api/v1/findings?run_id={run_id}&severity=HIGH", "alice").json()
    assert (
        r["total"] == 1 and r["items"][0]["severity"] == "HIGH" and r["items"][0]["authoritative"]
    )
    both = sl.call("GET", f"/api/v1/findings?run_id={run_id}&limit=1&offset=0", "alice").json()
    nxt = sl.call("GET", f"/api/v1/findings?run_id={run_id}&limit=1&offset=1", "alice").json()
    assert (
        both["total"] == nxt["total"] == 2 and both["items"][0]["severity"] == "HIGH"
    )  # ordered by severity
    assert both["items"][0]["finding_id"] != nxt["items"][0]["finding_id"]
    assert (
        sl.call("GET", "/api/v1/findings?verdict=REJECT", "erin").status_code == 422
    )  # not exposed here
    assert (
        sl.call("GET", f"/api/v1/findings?run_id={run_id}", "dave").status_code == 403
    )  # no finding:read
    assert sl.call("GET", "/api/v1/findings", "bob").status_code == 200  # approver has finding:read


def test_audit_events_are_for_auditors(sl: Slice) -> None:
    sl.full_run(EXPECTED)
    assert sl.call("GET", "/api/v1/audit/events", "alice").status_code == 403
    r = sl.call("GET", "/api/v1/audit/events?limit=5", "erin").json()
    assert r["total"] > 5 and len(r["items"]) == 5 and r["items"][0]["seq"] > r["items"][-1]["seq"]
    assert {"actor", "action", "resource", "result"} <= set(r["items"][0])
    assert sl.call("GET", "/api/v1/audit/events?result=DENIED", "erin").status_code == 200
    assert sl.call("GET", "/api/v1/audit/events?result=BAD", "erin").status_code == 422


# ---- SSE ------------------------------------------------------------------------------------
def test_stream_delivers_log_in_order_then_ends(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    with sl.client.stream("GET", f"/api/v1/assessments/{run_id}/events/stream",
                          headers={"Authorization": "Bearer dev-alice"}) as r:  # fmt: skip
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
        assert r.headers["cache-control"] == "no-store"
        body = "".join(r.iter_text())
    msgs = parse_sse(body)
    ids = [int(m["id"]) for m in msgs if "id" in m]
    persisted = [e["seq"] for e in sl.events(run_id)]
    assert ids == persisted and msgs[-1]["event"] == "end"
    assert json.loads(msgs[-1]["data"])["state"] == "REPORT_READY"


def test_stream_resumes_after_last_event_id_without_gaps_or_repeats(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    sl.drain()
    persisted = [e["seq"] for e in sl.events(run_id)]
    cut = persisted[3]
    with sl.client.stream("GET", f"/api/v1/assessments/{run_id}/events/stream",
                          headers={"Authorization": "Bearer dev-alice", "Last-Event-ID": str(cut)}) as r:  # fmt: skip
        msgs = parse_sse("".join(r.iter_text()))
    assert [int(m["id"]) for m in msgs if "id" in m] == [s for s in persisted if s > cut]
    with sl.client.stream("GET", f"/api/v1/assessments/{run_id}/events/stream?cursor={persisted[-1]}",
                          headers={"Authorization": "Bearer dev-alice"}) as r2:  # fmt: skip
        only_end = parse_sse("".join(r2.iter_text()))
    assert [m["event"] for m in only_end] == ["end"]  # nothing missed, nothing replayed


def test_stream_is_authorised_and_tenant_scoped(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    url = f"/api/v1/assessments/{run_id}/events/stream"
    assert sl.client.get(url).status_code == 401
    assert sl.call("GET", url, "dave").status_code == 404
    assert sl.call("GET", "/api/v1/assessments/nope/events/stream", "alice").status_code == 404


def test_stream_generator_waits_heartbeats_and_ends_when_run_finishes(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    clock = {"t": 0.0}
    sleeps: list[float] = []

    def sleep(s: float) -> None:  # a fake clock: finish the run while the stream is waiting
        sleeps.append(s)
        clock["t"] += 6.0
        if len(sleeps) == 3:
            sl.drain()

    def mono() -> float:
        return clock["t"]

    gen = stream_events(sl.app_engine, tenant_id="tenant-a", run_id=run_id, cursor=0,
                        poll_seconds=0.5, heartbeat_seconds=10.0, sleep=sleep, monotonic=mono)  # fmt: skip
    out: list[str] = []
    for chunk in gen:
        out.append(chunk)
        if len(out) > 200:
            break
    assert any(c.startswith(": heartbeat") for c in out)  # idle connection stays alive
    assert out[-1].startswith("id") is False and "event: end" in out[-1]
    assert any("report.ready" in c for c in out)


def test_stream_generator_rotates_long_connections(sl: Slice) -> None:
    _, _, run_id = sl.full_run(EXPECTED)
    clock = {"t": 0.0}

    def sleep(s: float) -> None:
        clock["t"] += 100.0

    chunks = list(stream_events(sl.app_engine, tenant_id="tenant-a", run_id=run_id, cursor=0,
                                max_seconds=250, sleep=sleep, monotonic=lambda: clock["t"]))  # fmt: skip
    last = parse_sse(chunks[-1])[0]
    seqs = [e["seq"] for e in sl.events(run_id)]
    assert last["event"] == "reconnect" and json.loads(last["data"])["cursor"] == seqs[-1]
    delivered = [c for c in chunks if c.startswith("id: ")]
    assert len(delivered) == len(
        seqs
    )  # every event delivered exactly once, then the rotation notice


@pytest.mark.parametrize("data", [{"a": 1}, {"msg": "line1\nline2"}, {"u": "é "}])
def test_sse_framing_never_breaks_on_newlines(data: dict[str, Any]) -> None:
    frame = format_sse(event_id=7, event="x", data=data)
    assert frame.endswith("\n\n") and frame.count("\n\n") == 1  # JSON escapes embedded newlines
    assert json.loads(frame.split("data: ", 1)[1]) == data
