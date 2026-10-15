"""Typed, fail-closed configuration (blueprint Appendix B, consolidated).

Secrets are never read from or stored in settings values; only *references*
(e.g. vault paths) are allowed. Safety flags that the MVP forbids relaxing are
validated so that a misconfiguration fails at startup rather than at runtime.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    DEV = "dev"
    TEST = "test"
    PROD = "prod"


class AssessmentMode(StrEnum):
    READ_ONLY = "read_only"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AISW_", extra="forbid", frozen=True)

    env: Environment = Environment.PROD  # fail-closed default
    deployment_mode: str = "customer_hosted"
    assessment_mode: AssessmentMode = AssessmentMode.READ_ONLY
    allow_production_remediation: bool = False
    require_scope_manifest: bool = True
    require_approval_for_active_scans: bool = True

    # Dev-only identity stub (ADR-006). Must never be active outside dev/test.
    dev_auth_stub: bool = False

    # AI is disabled until an approved open-source model is recorded (ADR-009).
    ai_enabled: bool = False
    model_id: str | None = None
    model_timeout_seconds: int = Field(default=60, ge=1, le=600)

    # Reference to the database DSN supplied by the secret provider; never logged or committed.
    database_url: SecretStr | None = None
    worker_database_url: SecretStr | None = None

    # Filesystem locations (paths only; key material stays in the file, never in settings).
    evidence_dir: Path | None = None
    signing_key_path: Path | None = None
    worker_enabled: bool = False

    evidence_retention_days: int = Field(default=365, ge=1)
    max_assessment_concurrency: int = Field(default=2, ge=1, le=32)
    enable_itsm_ticket_creation: bool = False
    log_redaction_enabled: bool = True

    @model_validator(mode="after")
    def _enforce_mvp_safety(self) -> Settings:
        if self.allow_production_remediation:
            raise ValueError("MVP is read-only: allow_production_remediation must be false")
        if not self.require_scope_manifest:
            raise ValueError("require_scope_manifest must be true")
        if not self.require_approval_for_active_scans:
            raise ValueError("require_approval_for_active_scans must be true")
        if not self.log_redaction_enabled:
            raise ValueError("log_redaction_enabled must be true")
        if self.dev_auth_stub and self.env is Environment.PROD:
            raise ValueError("dev_auth_stub is forbidden when env=prod")
        if self.ai_enabled and not self.model_id:
            raise ValueError("ai_enabled requires an approved model_id")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
