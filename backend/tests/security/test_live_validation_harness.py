"""Live validation harness (ADR-045): real targets stay refused until authorised; the harness itself
is proven end to end against loopback targets only (``loopback_only`` fails any other connect)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aisw.policy.signoffs import Register, builtin, sha256_file
from aisw.validation import live
from tests.http_server import bundle, loopback_only, make_cert, start_server
from tests.slice import Slice

pytestmark = pytest.mark.security
NOW = datetime(2026, 10, 17, 12, tzinfo=UTC)


def register(plan: Path | None, status: str = "APPROVED") -> Register:
    data = builtin().model_dump(mode="json")
    data["signoffs"] = [s for s in data["signoffs"] if s["id"] != live.SIGNOFF_ID]
    data["signoffs"].append({
        "id": live.SIGNOFF_ID, "subject": "s", "plan_ref": "M9", "artefact": "plan.json", "owner": "o",
        "status": status, "label_while_pending": "l", "next_step": "n",
        "decision": None if status == "PENDING" else
        {"by": "product owner", "at": "2026-10-16", "ref": "CHG-1", "sha256": sha256_file(plan) if plan else "0" * 64},
    })  # fmt: skip
    return Register.model_validate(data)


def test_the_committed_plan_is_refused_in_full_until_it_is_approved() -> None:
    plan = live.load_plan(live.DEFAULT_PLAN)
    assert {t.id for t in plan.targets} == {"example-com-passive-smoke", "scanme-nmap-bounded", "juice-shop-zap-baseline"}  # fmt: skip
    assert builtin().status_of(live.SIGNOFF_ID) == "PENDING"
    for t in plan.targets:
        assert not t.loopback and t.authorisation is None
        reasons = live.authorise(t, live.DEFAULT_PLAN, builtin(), datetime.now(UTC))
        assert reasons == [f"SIGNOFF_NOT_APPROVED:{live.SIGNOFF_ID}", "TARGET_NOT_AUTHORISED"], t.id
    assert live.main(["preflight"]) == 1


def test_authorisation_needs_the_approved_plan_and_a_current_window(tmp_path: Path) -> None:
    raw = json.loads(live.DEFAULT_PLAN.read_text())
    raw["targets"][0]["authorisation"] = {
        "by": "product owner", "reference": "CHG-1",
        "window_start": (NOW - timedelta(hours=1)).isoformat(), "window_end": (NOW + timedelta(hours=1)).isoformat(),
    }  # fmt: skip
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(raw))
    plan = live.load_plan(path)
    smoke, scanme = plan.target("example-com-passive-smoke"), plan.target("scanme-nmap-bounded")
    approved = register(path)
    assert live.authorise(smoke, path, approved, NOW) == []
    assert live.authorise(scanme, path, approved, NOW) == ["TARGET_NOT_AUTHORISED"]
    assert live.authorise(smoke, path, approved, NOW + timedelta(hours=2)) == [
        "OUTSIDE_AUTHORISED_WINDOW"
    ]
    assert live.authorise(smoke, path, register(path, "REJECTED"), NOW) == [f"SIGNOFF_NOT_APPROVED:{live.SIGNOFF_ID}"]  # fmt: skip
    path.write_text(json.dumps(raw) + " ")  # any edit after approval needs a new decision
    assert live.authorise(smoke, path, approved, NOW) == ["PLAN_CHANGED_SINCE_APPROVAL"]
    with pytest.raises(ValueError, match="end after it starts"):
        live.Authorisation(by="x", reference="y", window_start=NOW, window_end=NOW)


def test_evaluation_needs_expectations_and_names_every_mismatch() -> None:
    t = live.Target(id="t", kind="url", selector="https://127.0.0.1/", method="platform",
                    adapter="url_smoke", policy_version="p", expect={"US-1": "PASS", "US-5": "PASS"})  # fmt: skip
    body = {"controls": [{"control_id": "US-1", "outcome": "PASS"}, {"control_id": "US-5", "outcome": "PASS"},
                         {"control_id": "US-5", "outcome": "FAIL"}, {"control_id": "US-6", "outcome": "PASS"}]}  # fmt: skip
    ok, lines = live.evaluate(t, body)
    assert (
        not ok and "US-5: expected PASS, got FAIL  <-- MISMATCH" in lines
    )  # worst outcome across assets
    assert "US-6: PASS (no expectation recorded)" in lines
    observe = t.model_copy(update={"expect": {}})
    ok, lines = live.evaluate(observe, body)
    assert not ok and lines[-1].startswith("no expectations recorded")


@pytest.fixture()
def harness(app_engine: Any, worker_engine: Any, tmp_path: Path) -> Iterator[tuple[Slice, Path, list[tuple[str, int]]]]:  # fmt: skip
    with loopback_only() as attempts:
        good = make_cert(tmp_path, "good")
        expired = make_cert(tmp_path, "expired", not_before_days=-60, not_after_days=-10)
        sl = Slice(app_engine, worker_engine, tmp_path / "evidence", ca_file=bundle(tmp_path, "ca", good, expired))  # fmt: skip
        servers = {"healthy": start_server(good), "expired": start_server(expired)}
        sl.servers = servers  # type: ignore[attr-defined]
        attempts.clear()
        yield sl, tmp_path, attempts
        for s in servers.values():
            s.stop()


def run_target(sl: Slice, target: live.Target) -> dict[str, Any]:
    pid = sl.project()
    r = sl.call("POST", "/api/v1/inventory", "alice", json={"project_id": pid, "kind": "url", "selector": target.selector})  # fmt: skip
    assert r.status_code == 201, r.text
    m = sl.approved_manifest(
        pid, targets=[{"kind": "url", "selector": target.selector}], domains=["url"],
        allowed_adapters=["url_smoke"], profiles={"url_smoke": {"profile_id": "PASSIVE_HTTP_SMOKE", "profile_class": "READ_ONLY"}},
        allowed_ports=target.allowed_ports, internal_range_authorization=["127.0.0.1/32"],
        policy_version=target.policy_version,
    )  # fmt: skip
    r = sl.launch(pid, m, adapter_params={"url_smoke": {}})
    assert r.status_code == 202, r.text
    sl.drain()
    return sl.report(str(r.json()["run_id"]))


def test_loopback_targets_run_through_the_platform_and_are_evaluated(
    harness: tuple[Slice, Path, list[tuple[str, int]]],
) -> None:
    sl, tmp, attempts = harness
    servers: dict[str, Any] = sl.servers  # type: ignore[attr-defined]
    expect = {
        "healthy": {"US-1": "PASS", "US-2": "PASS", "US-3": "PASS", "US-4": "PASS", "US-5": "PASS", "US-6": "PASS"},
        "expired": {"US-1": "FAIL", "US-3": "FAIL"},
    }  # fmt: skip
    plan = {"version": "loopback", "targets": [
        {"id": f"loopback-{k}", "kind": "url", "selector": f"https://127.0.0.1:{s.port}/ok", "method": "platform",
         "adapter": "url_smoke", "policy_version": "url-smoke-baseline:1.0.0", "allowed_ports": [s.port],
         "expect": expect[k]} for k, s in servers.items()]}  # fmt: skip
    plan_path, results = tmp / "loopback-plan.json", tmp / "results.md"
    plan_path.write_text(json.dumps(plan))
    assert live.main(["preflight", "--plan", str(plan_path)]) == 0  # loopback needs no sign-off
    for t in live.load_plan(plan_path).targets:
        assert t.loopback and live.authorise(t, plan_path, builtin(), NOW) == []
        report = run_target(sl, t)
        rpath = tmp / f"{t.id}.json"
        rpath.write_text(json.dumps(report))
        assert live.main(["evaluate", "--plan", str(plan_path), "--target", t.id, "--report", str(rpath),
                          "--results", str(results)]) == 0, results.read_text()  # fmt: skip
    text = results.read_text()
    assert text.count(": MET") == 2 and "MISMATCH" not in text
    assert {a[0] for a in attempts} == {"127.0.0.1"}

    wrong = json.loads(plan_path.read_text())
    wrong["targets"][1]["expect"] = {"US-1": "PASS"}
    plan_path.write_text(json.dumps(wrong))
    assert live.main(["evaluate", "--plan", str(plan_path), "--target", "loopback-expired",
                      "--report", str(tmp / "loopback-expired.json")]) == 1  # fmt: skip


def test_evaluate_refuses_an_unauthorised_target(tmp_path: Path) -> None:
    report = tmp_path / "r.json"
    report.write_text("{}")
    assert (
        live.main(["evaluate", "--target", "example-com-passive-smoke", "--report", str(report)])
        == 2
    )
