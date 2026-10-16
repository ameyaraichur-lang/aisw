"""Typed, fail-closed configuration (blueprint Appendix B, consolidated).

Secrets are never stored in plain settings values: paths and references are
preferred, and the few values the secret provider injects through the environment
(database DSNs, the Astra API key) are held as ``SecretStr``. Safety flags that the
MVP forbids relaxing are validated so that a misconfiguration fails at startup rather
than at runtime.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from aisw.authz.net_guard import NetGuardError, parse_egress_zones
from aisw.core.rbac import Role


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


def astra_proxy_problem(proxy: str) -> str | None:
    """Why an explicit Astra proxy is unacceptable, or None (ADR-025). Shared by settings and the
    client. The proxy only tunnels (CONNECT): TLS and the Azure host check stay end to end."""
    u = urlparse(proxy)
    try:
        port = u.port
    except ValueError:
        return "astra_proxy has an invalid port"
    if u.scheme not in ("http", "https"):
        return "astra_proxy must be an http or https proxy URL"
    if u.username is not None or u.password is not None:
        return "astra_proxy must not carry credentials"
    if port is None:
        return "astra_proxy must name its port"
    if u.path not in ("", "/") or u.query or u.fragment or u.params:
        return "astra_proxy must be the proxy origin only (no path, query or fragment)"
    host = (u.hostname or "").lower()
    if not host:
        return "astra_proxy needs a host"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return "astra_proxy must not be a link-local, multicast, reserved or unspecified address"
    return None


def _loopback_http(url: str) -> bool:
    u = urlparse(url)
    return u.scheme == "http" and (u.hostname or "") in {"127.0.0.1", "localhost", "::1"}


def oidc_url_problem(name: str, url: str, env: Environment) -> str | None:
    """IdP and callback URLs are https; plain http is accepted only on loopback outside prod."""
    u = urlparse(url)
    if u.username is not None or u.password is not None:
        return f"{name} must not carry credentials"
    if u.query or u.fragment or not u.hostname:
        return f"{name} must be an absolute URL without query or fragment"
    if u.scheme == "https" or (env is not Environment.PROD and _loopback_http(url)):
        return None
    return f"{name} must use https (http is allowed only on loopback outside prod)"


def kms_url_problem(url: str, env: Environment) -> str | None:
    u = urlparse(url)
    if u.username is not None or u.password is not None:
        return "kms_addr must not carry credentials"
    if not u.hostname or u.path not in ("", "/") or u.query or u.fragment:
        return "kms_addr must be an origin (scheme://host:port)"
    if u.scheme == "https" or (env is not Environment.PROD and _loopback_http(url)):
        return None
    return "kms_addr must use https (http is allowed only on loopback outside prod)"


def opa_url_problem(url: str) -> str | None:
    """OPA runs beside the service: loopback or a single-label service name on an internal
    network may use http; anything else must be https."""
    u = urlparse(url)
    if u.username is not None or u.password is not None:
        return "opa_url must not carry credentials"
    if not u.hostname or u.path not in ("", "/") or u.query or u.fragment:
        return "opa_url must be an origin (scheme://host:port)"
    if u.scheme == "https":
        return None
    if u.scheme == "http" and (_loopback_http(url) or "." not in u.hostname):
        return None
    return "opa_url must use https unless it is loopback or an internal service name"


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
    # OIDC sign-in through the BFF (ADR-026); any standards-compliant IdP, nothing IdP-specific.
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: SecretStr | None = None  # confidential client; from the secret provider
    oidc_redirect_uri: str | None = None  # https://<console>/api/v1/auth/callback
    oidc_audience: str | None = None  # bearer API tokens; defaults to the client id
    oidc_scopes: str = Field(default="openid profile email", pattern=r"^openid( [\w:.\-/]+)*$")
    oidc_roles_claim: str = Field(default="roles", pattern=r"^[\w.:\-/]{1,64}$")
    oidc_tenant_claim: str = Field(default="tenant", pattern=r"^[\w.:\-/]{1,64}$")
    # JSON object mapping IdP role/group values to AISW roles; unset means the names are AISW's.
    oidc_role_map: str | None = None
    oidc_session_minutes: int = Field(default=480, ge=5, le=1440)
    # Signs session cookies (>= 32 characters); from the secret provider, never committed.
    session_secret: SecretStr | None = None

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
    # Which agent outcomes the AI validator reviews: aisw/llm/policy/triggers-<version>.yaml.
    ai_validation_trigger_version: str = Field(default="1.0.0", pattern=r"^\d+\.\d+\.\d+$")
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
    # Explicit CONNECT proxy for Astra only (http://host:port). Proxy environment variables are
    # still ignored; the egress allow-list must permit this proxy and nothing else (ADR-025).
    astra_proxy: str | None = None

    @property
    def astra_fallbacks(self) -> list[str]:
        return [d for d in (self.astra_fallback_deployments or "").split(",") if d]

    # Reference to the database DSN supplied by the secret provider; never logged or committed.
    database_url: SecretStr | None = None
    worker_database_url: SecretStr | None = None

    # Filesystem locations (paths only; key material stays in the file, never in settings).
    evidence_dir: Path | None = None
    # Process settings (deploy/). The API binds loopback by default; a reverse proxy fronts it.
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    api_trusted_proxies: str = "127.0.0.1"  # X-Forwarded-* honoured only from these
    worker_heartbeat_file: Path | None = None
    signing_key_path: Path | None = None
    # Manifest signing custody (ADR-027). local_file: dev/test only. transit: a Transit-compatible
    # KMS (OpenBao/Vault); the token is read from a 0600 file written by the secret provider.
    # Policy engine (ADR-003, ADR-031): the Python evaluator, or OPA running the packaged Rego.
    policy_engine: Literal["python", "opa"] = "python"
    opa_url: str | None = None
    signing_backend: Literal["local_file", "transit"] = "local_file"
    kms_addr: str | None = None
    kms_mount: str = Field(default="transit", pattern=r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$")
    kms_key: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,47}$")
    kms_token_file: Path | None = None
    kms_namespace: str | None = None
    # Egress (ADR-028). Scan zones: CIDRs the host firewall lets the worker reach; when set, every
    # resolved target address must fall inside one. Extra hosts: control-plane hosts beyond the
    # configured ones (e.g. an IdP whose JWKS lives on another host). DNS: resolvers to allow.
    egress_scan_cidrs: str | None = None
    egress_scan_ports: str = Field(default="80,443", pattern=r"^\d{1,5}(,\d{1,5})*$")
    egress_allowed_hosts: str | None = None
    egress_dns_servers: str | None = None
    # Comma-separated key ids that must never verify again (compromise), e.g. transit.aisw-manifests.v1.
    signing_revoked_key_ids: str | None = None
    worker_enabled: bool = False

    evidence_retention_days: int = Field(default=365, ge=1)
    # Scheduled retention checks (ADR-019). The scheduler always records a dry-run plan; it moves
    # evidence to quarantine only when auto-execute is on and the same plan was seen confirm_hours ago.
    retention_tenants: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9_\-]+(,[A-Za-z0-9_\-]+)*$"
    )
    retention_auto_execute: bool = False
    retention_confirm_hours: int = Field(default=24, ge=1, le=720)
    exception_max_days: int = Field(default=365, ge=1, le=1095)  # longest lifetime of an exception
    max_assessment_concurrency: int = Field(default=2, ge=1, le=32)
    enable_itsm_ticket_creation: bool = False
    # Ticket delivery (ADR-037): a second person sends an accepted draft. Off by default; drafts
    # can be rendered for Jira or ServiceNow either way. The token comes from the secret provider.
    enable_itsm_ticket_delivery: bool = False
    itsm_target: Literal["jira", "servicenow"] | None = None
    itsm_base_url: str | None = None
    itsm_username: str | None = None
    itsm_token: SecretStr | None = None
    itsm_jira_project_key: str = Field(default="AISW", pattern=r"^[A-Z][A-Z0-9_]{1,9}$")
    itsm_jira_issue_type: str = Field(default="Task", pattern=r"^[A-Za-z][\w \-]{0,39}$")
    itsm_servicenow_table: str = Field(default="incident", pattern=r"^[a-z][a-z0-9_]{1,79}$")
    itsm_timeout_seconds: int = Field(default=10, ge=1, le=60)
    log_redaction_enabled: bool = True

    @property
    def egress_zones(self) -> list[str]:
        return [c.strip() for c in (self.egress_scan_cidrs or "").split(",") if c.strip()]

    @property
    def egress_extra_hosts(self) -> list[str]:
        return [
            h.strip().lower() for h in (self.egress_allowed_hosts or "").split(",") if h.strip()
        ]

    @property
    def egress_dns(self) -> list[str]:
        return [h.strip() for h in (self.egress_dns_servers or "").split(",") if h.strip()]

    @property
    def revoked_signing_keys(self) -> list[str]:
        return [k.strip() for k in (self.signing_revoked_key_ids or "").split(",") if k.strip()]

    @property
    def oidc_enabled(self) -> bool:
        return self.oidc_issuer is not None

    @property
    def oidc_roles(self) -> dict[str, str]:
        """IdP value -> AISW role value. Validated at startup."""
        if self.oidc_role_map is None:
            return {}
        raw = json.loads(self.oidc_role_map)
        return {str(k): str(v) for k, v in raw.items()}

    def _check_egress(self) -> None:
        try:
            parse_egress_zones(self.egress_zones)
        except NetGuardError as exc:
            raise ValueError(f"egress_scan_cidrs: {exc.code} {exc}") from None
        if any(not 0 < int(p) < 65536 for p in self.egress_scan_ports.split(",")):
            raise ValueError("egress_scan_ports must be TCP ports")
        for h in self.egress_extra_hosts:
            host, _, port = h.rpartition(":") if h.count(":") == 1 else (h, "", "")
            if not re.match(r"^[a-z0-9]([a-z0-9.\-]{0,252})$", host) or (
                port and not port.isdigit()
            ):
                raise ValueError(f"egress_allowed_hosts entry is not host[:port]: {h!r}")
        for d in self.egress_dns:
            try:
                ipaddress.ip_address(d)
            except ValueError:
                raise ValueError(f"egress_dns_servers must be IP addresses: {d!r}") from None

    def _check_itsm(self) -> None:
        if not self.enable_itsm_ticket_creation:
            raise ValueError("enable_itsm_ticket_delivery requires enable_itsm_ticket_creation")
        token = self.itsm_token.get_secret_value().strip() if self.itsm_token else ""
        if not (self.itsm_target and self.itsm_base_url and self.itsm_username and token):
            raise ValueError(
                "enable_itsm_ticket_delivery requires itsm_target, itsm_base_url, itsm_username "
                "and itsm_token"
            )
        if problem := kms_url_problem(self.itsm_base_url, self.env):
            raise ValueError(problem.replace("kms_addr", "itsm_base_url"))

    def _check_oidc(self) -> None:
        if not (self.oidc_client_id and self.oidc_redirect_uri):
            raise ValueError("oidc_issuer requires oidc_client_id and oidc_redirect_uri")
        secret = self.session_secret.get_secret_value() if self.session_secret else ""
        if len(secret) < 32:
            raise ValueError("oidc requires session_secret of at least 32 characters")
        for name, url in (("oidc_issuer", self.oidc_issuer or ""),
                          ("oidc_redirect_uri", self.oidc_redirect_uri)):  # fmt: skip
            if problem := oidc_url_problem(name, url, self.env):
                raise ValueError(problem)
        if not urlparse(self.oidc_redirect_uri).path.endswith("/api/v1/auth/callback"):
            raise ValueError("oidc_redirect_uri must end with /api/v1/auth/callback")
        if self.oidc_role_map is not None:
            try:
                raw = json.loads(self.oidc_role_map)
            except ValueError:
                raise ValueError("oidc_role_map must be a JSON object") from None
            valid = {r.value for r in Role}
            if not isinstance(raw, dict) or not all(
                isinstance(k, str) and v in valid for k, v in raw.items()
            ):
                raise ValueError("oidc_role_map must map strings to AISW role names")

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
        if self.oidc_issuer is not None:
            self._check_oidc()
        self._check_egress()
        if self.enable_itsm_ticket_delivery:
            self._check_itsm()
        if self.policy_engine == "opa":
            if not self.opa_url:
                raise ValueError("policy_engine=opa requires opa_url")
            if problem := opa_url_problem(self.opa_url):
                raise ValueError(problem)
        if self.signing_backend == "transit":
            if not (self.kms_addr and self.kms_key and self.kms_token_file):
                raise ValueError(
                    "signing_backend=transit requires kms_addr, kms_key, kms_token_file"
                )
            if problem := kms_url_problem(self.kms_addr, self.env):
                raise ValueError(problem)
        if self.astra_proxy is not None:
            if problem := astra_proxy_problem(self.astra_proxy):
                raise ValueError(problem)
            if self.model_provider is not ModelProvider.ASTRA:
                raise ValueError("astra_proxy applies to model_provider=astra only")
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
def secrets_dir() -> str | None:
    """Secrets as files (``aisw_database_url``, ``aisw_session_secret`` ...): a mounted directory
    (AISW_SECRETS_DIR, e.g. /run/secrets) or systemd's credentials directory."""
    return os.environ.get("AISW_SECRETS_DIR") or os.environ.get("CREDENTIALS_DIRECTORY")


def load_settings(env_file: str | Path | None = None) -> Settings:
    return Settings(_env_file=env_file, _secrets_dir=secrets_dir())


def get_settings() -> Settings:
    return load_settings()
