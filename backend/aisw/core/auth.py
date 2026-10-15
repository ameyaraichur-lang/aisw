"""Identity resolution. OIDC (Keycloak) lands later; until then only the dev stub exists.

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
