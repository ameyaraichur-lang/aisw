"""Configuration imports through the real API, orchestrator, gateway and OPA engine: the Rego pack
``config-baseline`` now has facts to judge. Nothing outside loopback is contacted."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from aisw.policy.opa import OpaClient, OpaEvaluator
from tests.security.test_import_pipeline import codes, findings, reasons, upload
from tests.slice import Slice

pytestmark = pytest.mark.security
GOLD = Path(__file__).resolve().parents[1] / "fixtures" / "golden"
POLICY = "config-baseline:1.0.0"
ADAPTERS = {  # adapter -> (profile, domain, kind, fixture)
    "firewall_import": ("FIREWALL_CONFIG_IMPORT", "network", "aws_security_groups_json", "aws_security_groups.json"),
    "aws_iam_import": ("AWS_CREDENTIAL_REPORT_IMPORT", "identity", "aws_credential_report_csv", "aws_credential_report.csv"),
    "kubescape_import": ("KUBESCAPE_RESULTS_IMPORT", "kubernetes", "kubescape_json", "kubescape.json"),
    "directory_import": ("DIRECTORY_EXPORT_IMPORT", "identity", "ldif", "directory.ldif"),
}  # fmt: skip


@pytest.fixture()
def sl(app_engine: Any, worker_engine: Any, tmp_path: Path, opa_url: str) -> Iterator[Slice]:
    s = Slice(app_engine, worker_engine, tmp_path / "evidence")
    opa = OpaEvaluator(OpaClient(opa_url))
    s.container.evaluator = opa
    s.worker.evaluator = opa
    yield s


def config_run(sl: Slice, adapters: list[str], kind: str, selector: str) -> str:
    pid = sl.project()
    r = sl.call("POST", "/api/v1/inventory", "alice",
                json={"project_id": pid, "kind": kind, "selector": selector, "expected_assets": []})  # fmt: skip
    assert r.status_code == 201, r.text
    m = sl.approved_manifest(
        pid, targets=[{"kind": kind, "selector": selector}], policy_version=POLICY,
        domains=sorted({ADAPTERS[a][1] for a in adapters}), allowed_adapters=adapters,
        profiles={a: {"profile_id": ADAPTERS[a][0], "profile_class": "READ_ONLY"} for a in adapters},
    )  # fmt: skip
    files = {
        a: upload(sl, pid, ADAPTERS[a][2], (GOLD / ADAPTERS[a][3]).read_text()) for a in adapters
    }
    launched = sl.launch(pid, m, adapter_params={a: {"import_id": i} for a, i in files.items()})
    assert launched.status_code == 202, launched.text
    sl.drain()
    return str(launched.json()["run_id"])


def controls(sl: Slice, run_id: str) -> dict[str, str]:
    return dict(
        sl.sql("SELECT control_id, outcome FROM control_assessments WHERE run_id=:r", r=run_id)
    )


def test_cloud_account_firewall_and_iam_imports_produce_rego_findings(sl: Slice) -> None:
    run_id = config_run(sl, ["firewall_import", "aws_iam_import"], "cloud_account", "123456789012")
    assert sl.status(run_id)["state"] == "REPORT_READY"
    assert findings(sl, run_id) == {
        "Administrative ports are not reachable from any source": "HIGH",
        "No rule allows all ports from any source": "CRITICAL",
        "Administrative identities use multi-factor authentication": "CRITICAL",
        "Active access keys are rotated": "MEDIUM",
        "Enabled accounts are in use": "MEDIUM",
    }
    c = controls(sl, run_id)
    assert c["CB-NET-1"] == "FAIL" and c["CB-IAM-1"] == "FAIL"
    assert "CB-NET-3" not in c or c["CB-NET-3"] != "PASS"  # security groups carry no policy fact
    r = reasons(sl, run_id)
    assert (
        "OUT_OF_SCOPE_RECORDS_DROPPED:1" in r and "ADMIN_MEMBERSHIP_NOT_IN_CREDENTIAL_REPORT" in r
    )
    report = str(sl.report(run_id))
    assert POLICY in report and "config-baseline-1.0.0" in report  # pending sign-off label


def test_kubescape_and_directory_imports_judge_rbac_and_staleness(sl: Slice) -> None:
    run_id = config_run(
        sl, ["kubescape_import", "directory_import"], "asset_group", "corp.example.com"
    )
    # the kubescape report names its cluster; under a directory selector it is refused, not merged
    st = sl.status(run_id)
    assert st["state"] == "PARTIAL" and st["tasks"] == {"FAILED": 1, "SUCCEEDED": 1}
    assert findings(sl, run_id) == {"Enabled accounts are in use": "MEDIUM"}
    assert "CLUSTER_MISMATCH" in codes(sl, run_id)

    k8s = config_run(sl, ["kubescape_import"], "asset_group", "prod-cluster-1")
    assert sl.status(k8s)["state"] == "REPORT_READY"
    assert findings(sl, k8s) == {
        "No service account holds cluster-admin": "HIGH",
        "No binding grants rights to anonymous or unauthenticated users": "CRITICAL",
        "No role grants every verb on every resource": "HIGH",
    }
