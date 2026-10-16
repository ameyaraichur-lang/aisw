"""Typed, fail-closed configuration (blueprint Appendix B, consolidated).

Secrets are never stored in plain settings values: paths and references are
preferred, and the few values the secret provider injects through the environment
(database DSNs, the Astra API key) are held as ``SecretStr``. Safety flags that the
MVP forbids relaxing are validated so that a misconfiguration fails at startup rather
than at runtime.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    DEV = "dev"
    TEST = "test"
    PROD = "prod"


class ReplayMode(StrEnum):
    OFF = "off"
    RECORD = "record"
    REPLAY = "replay"


class AssessmentMode(StrEnum):
    READ_ONLY = "read_only"


class ModelProvider(StrEnum):
    OLLAMA = "ollama"  # local runtime on loopback (ADR-009)
    ASTRA = "astra"  # Astra / Azure OpenAI Responses API, remote and opt-in (ADR-020)


# Azure OpenAI resource hostnames. An Astra endpoint outside these suffixes is refused, so the
# setting cannot be repointed at an arbitrary host.
ASTRA_HOST_SUFFIXES = (
    ".openai.azure.com",
    ".cognitiveservices.azure.com",
    ".services.ai.azure.com",
)


def astra_endpoint_problem(endpoint: str) -> str | None:
    """Why an Astra endpoint is unacceptable, or None. Shared by settings and the client."""
    u = urlparse(endpoint)
    try:
        port = u.port
    except ValueError:
        return "astra_endpoint has an invalid port"
    if u.scheme != "https":
        return "astra_endpoint must use https"
    if u.username is not None or u.password is not None:
        return "astra_endpoint must not carry credentials"
    if port not in (None, 443):
        return "astra_endpoint must use port 443"
    if u.path not in ("", "/") or u.query or u.fragment or u.params:
        return "astra_endpoint must be the resource origin only (no path, query or fragment)"
    host = (u.hostname or "").lower()
    if not any(host.endswith(s) and len(host) > len(s) for s in ASTRA_HOST_SUFFIXES):
        return (
            "astra_endpoint host must be an Azure OpenAI resource ("
            + ", ".join("*" + s for s in ASTRA_HOST_SUFFIXES)
            + ")"
        )
    return None


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

    # AI is disabled until an approved model is recorded (ADR-009; remote Astra per ADR-020).
    ai_enabled: bool = False
    model_provider: ModelProvider = ModelProvider.OLLAMA
    model_id: str | None = None  # Ollama model name, or the Astra deployment name
    model_license: str | None = (
        None  # SPDX id of the reviewed WEIGHTS licence (runtime licence is separate)
    )
    model_endpoint: str = "http://127.0.0.1:11434"  # local runtime only (Ollama default)
    ai_narrative_enabled: bool = True  # feature flags, effective only when ai_enabled
    ai_architecture_enabled: bool = True
    ai_verification_questions_enabled: bool = True  # Agent 4 questions for owners (ADR-024)
    ai_executive_summary_enabled: bool = True  # Agent 8 executive summary (ADR-024)
    model_timeout_seconds: int = Field(default=60, ge=1, le=600)
    # Agent validation pass (ADR-021): the model reviews Agents 1-7 and can only add caution.
    ai_validation_enabled: bool = True  # effective only when ai_enabled
    ai_validation_batch_size: int = Field(default=12, ge=1, le=50)
    ai_validation_max_items_per_agent: int = Field(default=60, ge=1, le=1000)
    ai_validation_concurrency: int = Field(default=4, ge=1, le=16)
    # Model-call routing (ADR-023). Live tokens one run may spend; 0 means no limit.
    ai_run_token_budget: int = Field(default=200_000, ge=0, le=10_000_000)
    # record: store each reply under a hash of its request; replay: answer only from that store and
    # never reach a model. Not available in prod (replies are kept on local disk).
    ai_replay_mode: ReplayMode = ReplayMode.OFF
    ai_replay_dir: Path | None = None

    # Astra (Azure OpenAI Responses API). Used only when model_provider=astra (ADR-020).
    astra_endpoint: str | None = None  # https://<resource>.openai.azure.com
    astra_api_version: str = Field(default="2025-04-01-preview", pattern=r"^[0-9A-Za-z.\-]{1,40}$")
    # Supplied by the secret provider through the environment; never logged or committed.
    astra_api_key: SecretStr | None = None
    # Reference (ticket, decision id) to the approval for sending redacted findings off-host.
    astra_data_approval_ref: str | None = None
    astra_max_output_tokens: int = Field(default=2048, ge=256, le=16384)
    # Separate deployment for the validation pass, so the reviewer is not the generator.
    astra_validation_deployment: str | None = None
    # Comma-separated deployments tried in order when the primary fails transiently (ADR-023).
    astra_fallback_deployments: str | None = Field(default=None, pattern=r"^[\w.\-]+(,[\w.\-]+)*$")
    astra_failover_cooldown_seconds: int = Field(default=60, ge=1, le=3600)

    @property
    def astra_fallbacks(self) -> list[str]:
        return [d for d in (self.astra_fallback_deployments or "").split(",") if d]

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
        if self.astra_endpoint is not None and (
            problem := astra_endpoint_problem(self.astra_endpoint)
        ):
            raise ValueError(problem)
        if self.ai_replay_mode is not ReplayMode.OFF:
            if self.env is Environment.PROD:
                raise ValueError("ai_replay_mode is for dev and test only")
            if self.ai_replay_dir is None:
                raise ValueError("ai_replay_mode requires ai_replay_dir")
        replay_only = self.ai_replay_mode is ReplayMode.REPLAY  # nothing can leave the host
        if self.ai_enabled and replay_only:
            if not self.model_id:
                raise ValueError("ai_replay_mode=replay requires the recorded model_id")
        elif self.ai_enabled and self.model_provider is ModelProvider.ASTRA:
            key = self.astra_api_key.get_secret_value().strip() if self.astra_api_key else ""
            if not (self.model_id and self.astra_endpoint and key):
                raise ValueError(
                    "model_provider=astra requires model_id (deployment), astra_endpoint "
                    "and astra_api_key"
                )
            if not (self.astra_data_approval_ref or "").strip():
                raise ValueError(
                    "model_provider=astra sends redacted findings off-host: "
                    "astra_data_approval_ref must record the data-handling approval"
                )
        elif self.ai_enabled and not (self.model_id and self.model_license):
            raise ValueError("ai_enabled requires an approved model_id AND its reviewed licence")
        if urlparse(self.model_endpoint).hostname not in {
            "127.0.0.1",
            "localhost",
            "::1",
        } or urlparse(self.model_endpoint).scheme not in {"http", "https"}:
            raise ValueError(
                "model_endpoint must be a loopback http(s) URL (use a local tunnel or proxy)"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
