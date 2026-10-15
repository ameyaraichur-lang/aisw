"""Shared contract primitives: strict base model, identifier types, canonical hashing."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, StringConstraints

CONTRACT_VERSION = "1.1"


class StrictModel(BaseModel):
    """Unknown fields are rejected; instances are immutable (blueprint G.11, section 12.1)."""

    model_config = ConfigDict(extra="forbid", frozen=True)


Slug = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
Sha256 = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
Semver = Annotated[str, StringConstraints(pattern=r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")]
NonEmpty = Annotated[str, StringConstraints(min_length=1, max_length=2048)]
Timestamp = AwareDatetime  # RFC3339 with an explicit offset; naive datetimes are rejected


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON bytes: sorted keys, no whitespace, UTF-8, no NaN."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_hash(obj: Any) -> str:
    return sha256_ref(canonical_json(obj))
