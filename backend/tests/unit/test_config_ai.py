from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from aisw.core.config import ModelProvider, Settings

FAKE_KEY = "fake-astra-key-0123456789"  # aisw:allow-secret


def astra(**kw: Any) -> Settings:
    base: dict[str, Any] = {
        "ai_enabled": True,
        "model_provider": "astra",
        "model_id": "gpt-astra",
        "astra_endpoint": "https://warden-dev.openai.azure.com",
        "astra_api_key": FAKE_KEY,
        "astra_data_approval_ref": "DPA-2026-17",
    }
    return Settings(**{**base, **kw})


def test_ai_is_disabled_by_default() -> None:
    s = Settings()
    assert s.ai_enabled is False and s.model_id is None


def test_enabling_ai_requires_model_and_licence() -> None:
    with pytest.raises(ValidationError):
        Settings(ai_enabled=True)
    with pytest.raises(ValidationError):
        Settings(ai_enabled=True, model_id="m")
    ok = Settings(ai_enabled=True, model_id="m", model_license="Apache-2.0")
    assert ok.ai_enabled


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com:11434",
        "http://10.0.0.5:11434",
        "ftp://127.0.0.1",
        "http://127.0.0.1.evil.test",
    ],
)
def test_model_endpoint_must_be_loopback(url: str) -> None:
    with pytest.raises(ValidationError):
        Settings(model_endpoint=url)


@pytest.mark.parametrize(
    "url", ["http://127.0.0.1:9", "http://localhost:11434", "https://[::1]:8443"]
)
def test_loopback_endpoints_are_accepted(url: str) -> None:
    assert Settings(model_endpoint=url).model_endpoint == url


def test_provider_defaults_to_local_ollama() -> None:
    s = Settings()
    assert s.model_provider is ModelProvider.OLLAMA
    assert s.astra_endpoint is None and s.astra_api_key is None


def test_astra_fully_configured_is_accepted_without_weights_licence() -> None:
    s = astra()
    assert s.model_provider is ModelProvider.ASTRA and s.model_license is None
    assert s.astra_api_key is not None and s.astra_api_key.get_secret_value() == FAKE_KEY


@pytest.mark.parametrize(
    "missing",
    [
        {"model_id": None},
        {"astra_endpoint": None},
        {"astra_api_key": None},
        {"astra_api_key": "   "},
        {"astra_data_approval_ref": None},
        {"astra_data_approval_ref": "  "},
    ],
)
def test_astra_requires_every_setting_and_the_data_approval(missing: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        astra(**missing)


@pytest.mark.parametrize(
    "url",
    [
        "http://warden-dev.openai.azure.com",  # plaintext
        "https://warden-dev.openai.azure.com:8443",  # odd port
        "https://user:pw@warden-dev.openai.azure.com",  # aisw:allow-secret
        "https://warden-dev.openai.azure.com/openai/responses",  # path
        "https://warden-dev.openai.azure.com/?x=1",
        "https://openai.azure.com",  # bare suffix, no resource
        "https://warden-dev.openai.azure.com.evil.test",
        "https://evil.test/#.openai.azure.com",
        "https://api.openai.com",  # not Azure
        "https://127.0.0.1",
        "https://warden-dev.openai.azure.com:bad",
    ],
)
def test_astra_endpoint_must_be_an_azure_openai_origin(url: str) -> None:
    with pytest.raises(ValidationError):
        astra(astra_endpoint=url)
    with pytest.raises(ValidationError):
        Settings(astra_endpoint=url)  # refused even while AI is off


@pytest.mark.parametrize(
    "url",
    [
        "https://warden-dev.openai.azure.com",
        "https://warden-dev.openai.azure.com/",
        "https://Warden-Dev.cognitiveservices.azure.com:443",
        "https://warden.services.ai.azure.com",
    ],
)
def test_astra_endpoint_accepts_azure_resource_origins(url: str) -> None:
    assert astra(astra_endpoint=url).astra_endpoint == url


def test_astra_api_version_is_constrained() -> None:
    assert astra(astra_api_version="2025-04-01-preview").astra_api_version == "2025-04-01-preview"
    with pytest.raises(ValidationError):
        astra(astra_api_version="x&api-key=steal")


def test_astra_key_never_appears_in_settings_output() -> None:
    s = astra()
    assert FAKE_KEY not in repr(s) and FAKE_KEY not in str(s)
    assert FAKE_KEY not in s.model_dump_json()


def test_astra_settings_load_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISW_AI_ENABLED", "true")
    monkeypatch.setenv("AISW_MODEL_PROVIDER", "astra")
    monkeypatch.setenv("AISW_MODEL_ID", "gpt-astra")
    monkeypatch.setenv("AISW_ASTRA_ENDPOINT", "https://warden-dev.openai.azure.com")
    monkeypatch.setenv("AISW_ASTRA_API_KEY", FAKE_KEY)
    monkeypatch.setenv("AISW_ASTRA_DATA_APPROVAL_REF", "DPA-2026-17")
    s = Settings()
    assert s.ai_enabled and s.model_provider is ModelProvider.ASTRA and s.model_id == "gpt-astra"


# ---- explicit Astra proxy (ADR-025) ---------------------------------------------------------------
@pytest.mark.parametrize(
    "proxy",
    ["http://proxy.corp.example:3128", "https://10.1.2.3:8443", "http://[2001:db8::5]:3128"],
)
def test_an_explicit_proxy_origin_is_accepted(proxy: str) -> None:
    assert astra(astra_proxy=proxy).astra_proxy == proxy


@pytest.mark.parametrize(
    ("proxy", "why"),
    [("socks5://proxy.corp.example:1080", "http or https"),
     ("http://user:pw@proxy.corp.example:3128", "credentials"),  # aisw:allow-secret
     ("http://proxy.corp.example", "name its port"),
     ("http://proxy.corp.example:3128/path", "origin only"),
     ("http://proxy.corp.example:99999", "invalid port"),
     ("http://169.254.169.254:80", "link-local"),
     ("http://0.0.0.0:3128", "unspecified")],
)  # fmt: skip
def test_a_proxy_that_could_become_generic_egress_is_refused(proxy: str, why: str) -> None:
    with pytest.raises(ValidationError, match=why):
        astra(astra_proxy=proxy)


def test_a_proxy_is_only_for_the_astra_provider() -> None:
    with pytest.raises(ValidationError, match="model_provider=astra only"):
        Settings(astra_proxy="http://proxy.corp.example:3128")
