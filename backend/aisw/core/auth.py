"""Dev-stub identity resolution. Real sign-in is OIDC through the BFF (ADR-026, aisw.api.auth).

The stub is refused unless settings.dev_auth_stub is on AND env is dev/test (config validation
also forbids it in prod). With no valid identity the answer is 401: fail closed.
"""

from __future__ import annotations

from aisw.core.config import Environment, Settings
from aisw.core.rbac import ActorContext, Role

# Seeded, clearly fake identities for local development and tests. Not credentials.
_SEEDED: dict[str, ActorContext] = {
    "dev-alice": ActorContext(
        "tenant-a", "alice", frozenset({Role.PROJECT_ADMIN, Role.ASSESSMENT_OPERATOR})
    ),
    "dev-bob": ActorContext("tenant-a", "bob", frozenset({Role.APPROVER})),
    "dev-carol": ActorContext("tenant-a", "carol", frozenset({Role.REPORT_READER})),
    "dev-rita": ActorContext("tenant-a", "rita", frozenset({Role.REVIEWER})),
    "dev-sam": ActorContext(
        "tenant-a", "sam", frozenset({Role.ASSESSMENT_OPERATOR, Role.REVIEWER})
    ),
    "dev-erin": ActorContext("tenant-a", "erin", frozenset({Role.AUDITOR})),
    "dev-dave": ActorContext("tenant-b", "dave", frozenset({Role.PROJECT_ADMIN})),
}


class AuthError(Exception):
    pass


def resolve_actor(settings: Settings, authorization: str | None) -> ActorContext:
    if not (settings.dev_auth_stub and settings.env in {Environment.DEV, Environment.TEST}):
        raise AuthError("no identity provider configured")
    if not authorization or not authorization.startswith("Bearer "):
        raise AuthError("missing bearer credential")
    actor = _SEEDED.get(authorization.removeprefix("Bearer ").strip())
    if actor is None:
        raise AuthError("unknown credential")
    return actor


def list_dev_users() -> list[dict[str, object]]:
    """Seeded identities for the dev login picker (names and roles only, never tokens)."""
    return [
        {"name": a.actor_id, "tenant_id": a.tenant_id, "roles": sorted(r.value for r in a.roles)}
        for a in _SEEDED.values()
    ]
