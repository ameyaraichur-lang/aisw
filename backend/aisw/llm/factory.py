"""Pick the model client from settings. AI stays off unless explicitly and completely configured."""

from __future__ import annotations

from aisw.core.config import Settings
from aisw.llm.client import DisabledModelClient, ModelClient, OllamaClient


def build_model_client(settings: Settings) -> ModelClient:
    if not settings.ai_enabled or settings.model_id is None:
        return DisabledModelClient()
    return OllamaClient(settings.model_endpoint, settings.model_id)
