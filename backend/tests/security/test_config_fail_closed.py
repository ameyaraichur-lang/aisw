"""Safety flags the MVP forbids relaxing must fail at startup."""

from typing import Any

import pytest
from pydantic import ValidationError

from aisw.core.config import AssessmentMode, Environment, Settings

pytestmark = pytest.mark.security


def make(**kw: Any) -> Settings:
    return Settings(**kw)


def test_defaults_are_fail_closed() -> None:
    s = make()
    assert s.env is Environment.PROD
    assert s.assessment_mode is AssessmentMode.READ_ONLY
    assert s.allow_production_remediation is False
    assert s.require_scope_manifest is True
    assert s.require_approval_for_active_scans is True
    assert s.ai_enabled is False
    assert s.enable_itsm_ticket_creation is False
    assert s.dev_auth_stub is False


@pytest.mark.parametrize(
    "override",
    [
        {"allow_production_remediation": True},
        {"require_scope_manifest": False},
        {"require_approval_for_active_scans": False},
        {"log_redaction_enabled": False},
        {"dev_auth_stub": True},  # env defaults to prod
        {"ai_enabled": True},  # no approved model_id
        {
            "ai_enabled": True,
            "model_provider": "astra",
            "model_id": "d",
        },  # no endpoint/key/approval
        {"astra_endpoint": "https://attacker.example"},  # remote host outside the Azure allow-list
        {"model_provider": "openai"},  # unknown provider
        {"assessment_mode": "read_write"},
        {"unknown_flag": True},
    ],
)
def test_unsafe_settings_rejected(override: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        make(**override)


def test_dev_stub_allowed_only_in_dev() -> None:
    assert make(env="dev", dev_auth_stub=True).dev_auth_stub is True
    with pytest.raises(ValidationError):
        make(env="prod", dev_auth_stub=True)


def test_env_var_cannot_enable_remediation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISW_ALLOW_PRODUCTION_REMEDIATION", "true")
    with pytest.raises(ValidationError):
        Settings()
