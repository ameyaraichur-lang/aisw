from __future__ import annotations

from aisw.core.config import ModelProvider, ReplayMode, Settings
from aisw.llm.client import AstraClient, DisabledModelClient, ModelClient, OllamaClient
from aisw.llm.routing import FailoverClient, RecordReplayClient


def build_model_client(
    settings: Settings, *, deployment: str | None = None, exclude: frozenset[str] = frozenset()
) -> ModelClient:
    """The configured client, composed as replay(failover(deployments)) (ADR-023)."""
    if not settings.ai_enabled or settings.model_id is None:
        return DisabledModelClient()
    primary = deployment or settings.model_id
    if settings.ai_replay_mode is ReplayMode.REPLAY and settings.ai_replay_dir is not None:
        return RecordReplayClient(None, settings.ai_replay_dir, "replay", model_id=primary)
    client = _live_client(settings, primary, exclude)
    if settings.ai_replay_mode is ReplayMode.RECORD and settings.ai_replay_dir is not None:
        return RecordReplayClient(client, settings.ai_replay_dir, "record")
    return client


def _live_client(settings: Settings, primary: str, exclude: frozenset[str]) -> ModelClient:
    if settings.model_provider is not ModelProvider.ASTRA:
        return OllamaClient(settings.model_endpoint, primary)
    if settings.astra_endpoint is None or settings.astra_api_key is None:
        return DisabledModelClient()  # unreachable: Settings refuses this combination
    chain = [primary, *(d for d in settings.astra_fallbacks if d != primary and d not in exclude)]
    clients: list[ModelClient] = [
        AstraClient(
            settings.astra_endpoint,
            name,
            settings.astra_api_key,
            api_version=settings.astra_api_version,
            max_output_tokens=settings.astra_max_output_tokens,
            proxy=settings.astra_proxy,
        )  # fmt: skip
        for name in chain
    ]
    if len(clients) == 1:
        return clients[0]
    return FailoverClient(clients, cooldown=float(settings.astra_failover_cooldown_seconds))


def build_validation_client(settings: Settings) -> ModelClient:
    """The agent validation pass uses its own Astra deployment when one is configured, and then
    never fails over to the generating deployment: the reviewer must not review its own output."""
    if not settings.ai_validation_enabled:
        return DisabledModelClient()
    own = settings.astra_validation_deployment
    return build_model_client(
        settings, deployment=own,
        exclude=frozenset({settings.model_id}) if own and settings.model_id else frozenset(),
    )  # fmt: skip
