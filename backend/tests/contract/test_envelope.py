from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from aisw.contracts.envelope import BindingError, TaskEnvelope, TrustedContext, bind_envelope
from aisw.contracts.refs import EvidenceRef, RefError, require_in_scope

H = "sha256:" + "a" * 64
NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)


def env_dict(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "tenant_id": "tenant-a", "project_id": "proj-1", "run_id": "run-1", "task_id": "task-1",
        "agent_id": "discovery", "agent_version": "0.1.0", "scope_manifest_id": "scope-1",
        "scope_manifest_hash": H, "authorization_permit_id": "permit-1",
        "input_refs": ["evidence://tenant-a/proj-1/run-1/assets/batch-1"],
        "idempotency_key": "k1", "status": "SUCCEEDED", "started_at": NOW.isoformat(),
        "completed_at": (NOW + timedelta(seconds=5)).isoformat(),
    }  # fmt: skip
    base.update(over)
    return base


TRUSTED = TrustedContext(
    tenant_id="tenant-a", project_id="proj-1", run_id="run-1", scope_manifest_id="scope-1",
    scope_manifest_hash=H, authorization_permit_id="permit-1",
)  # fmt: skip


def test_valid_envelope_round_trips() -> None:
    env = TaskEnvelope.model_validate(env_dict())
    assert env.contract_version == "1.1"
    assert bind_envelope(env, TRUSTED) is env


@pytest.mark.parametrize(
    "over",
    [
        {"surprise": 1},  # unknown fields are rejected
        {"contract_version": "1.0"},
        {"started_at": "2026-10-15T12:00:00"},  # naive timestamp
        {"status": "DONE"},
        {"agent_version": "latest"},
        {"scope_manifest_hash": "md5:abc"},
        {"status": "FAILED"},  # needs an error
        {"status": "PARTIAL"},  # must name its gaps
        {"completed_at": (NOW - timedelta(seconds=1)).isoformat()},
        {"provenance": {"model_id": "m"}},  # model without prompt version
    ],
)
def test_invalid_envelopes_rejected(over: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        TaskEnvelope.model_validate(env_dict(**over))


@pytest.mark.security
@pytest.mark.parametrize(
    "over",
    [
        {"tenant_id": "tenant-b"},  # model-supplied tenant is ignored/rejected
        {"project_id": "proj-2"},
        {"run_id": "run-2"},
        {"scope_manifest_hash": "sha256:" + "b" * 64},
        {"authorization_permit_id": "permit-x"},
        {"scope_manifest_id": "scope-2"},
        {"input_refs": ["evidence://tenant-b/proj-1/run-1/assets/x"]},
        {"output_refs": ["evidence://tenant-a/proj-9/run-1/assets/x"]},
    ],
)
def test_binding_rejects_untrusted_claims(over: dict[str, Any]) -> None:
    env = TaskEnvelope.model_validate(env_dict(**over))
    with pytest.raises(BindingError):
        bind_envelope(env, TRUSTED)


@pytest.mark.security
@pytest.mark.parametrize(
    "raw",
    [
        "http://x/y",
        "evidence://t/p/r",
        "evidence://t/p/r/../../other",
        "evidence://t/p/r/a//b",
        "evidence://t p/p/r/x",
        "evidence://t/p/r/",
    ],
)
def test_malformed_refs_rejected(raw: str) -> None:
    with pytest.raises(RefError):
        EvidenceRef.parse(raw)


def test_ref_parse_and_scope() -> None:
    ref = EvidenceRef.parse("evidence://tenant-a/proj-1/run-1/net/edges-02")
    assert str(ref) == "evidence://tenant-a/proj-1/run-1/net/edges-02"
    with pytest.raises(RefError):
        require_in_scope([str(ref)], tenant_id="tenant-a", project_id="other")
