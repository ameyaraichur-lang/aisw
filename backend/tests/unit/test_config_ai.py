from __future__ import annotations

import pytest
from pydantic import ValidationError

from aisw.core.config import Settings


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
