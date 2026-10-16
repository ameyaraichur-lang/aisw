"""Pick the model client from settings. AI stays off unless explicitly and completely configured."""

from __future__ import annotations

from aisw.core.config import ModelProvider, Settings
from aisw.llm.client import AstraClient, DisabledModelClient, ModelClient, OllamaClient


def build_model_client(settings: Settings, *, deployment: str | None = None) -> ModelClient:
    if not settings.ai_enabled or settings.model_id is None:
        return DisabledModelClient()
    if settings.model_provider is ModelProvider.ASTRA:
        if settings.astra_endpoint is None or settings.astra_api_key is None:
            return DisabledModelClient()  # unreachable: Settings refuses this combination
        return AstraClient(
            settings.astra_endpoint,
            deployment or settings.model_id,
            settings.astra_api_key,
            api_version=settings.astra_api_version,
            max_output_tokens=settings.astra_max_output_tokens,
        )
    return OllamaClient(settings.model_endpoint, settings.model_id)


def build_validation_client(settings: Settings) -> ModelClient:
    """The agent validation pass uses its own Astra deployment when one is configured."""
    if not settings.ai_validation_enabled:
        return DisabledModelClient()
    return build_model_client(settings, deployment=settings.astra_validation_deployment)
