"""Register of human sign-offs (pending plan P0-6, P0-7, A-1).

The product reads it to decide whether a "sample" or "provisional" label still applies. An
approval binds to the sha256 of the exact artefact approved, so editing an approved rubric,
catalog or policy file without a new decision fails ``tools/signoffs.py --check``.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from aisw.contracts.base import NonEmpty, StrictModel

Status = Literal["PENDING", "APPROVED", "REJECTED"]


class Decision(StrictModel):
    by: NonEmpty
    at: date
    ref: NonEmpty
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class Signoff(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{0,63}$")
    subject: NonEmpty
    plan_ref: NonEmpty
    artefact: NonEmpty
    owner: NonEmpty
    status: Status
    label_while_pending: NonEmpty
    next_step: NonEmpty
    decision: Decision | None

    @model_validator(mode="after")
    def _decided(self) -> Signoff:
        if (self.status == "PENDING") != (self.decision is None):
            raise ValueError(
                f"{self.id}: a decision is recorded exactly when status is not PENDING"
            )
        return self


class Register(StrictModel):
    version: int
    note: str = ""
    signoffs: list[Signoff]

    @model_validator(mode="after")
    def _unique(self) -> Register:
        ids = [s.id for s in self.signoffs]
        if len(ids) != len(set(ids)):
            raise ValueError("sign-off ids must be unique")
        return self

    def get(self, signoff_id: str) -> Signoff | None:
        return next((s for s in self.signoffs if s.id == signoff_id), None)

    def status_of(self, signoff_id: str) -> Status | Literal["UNRECORDED"]:
        s = self.get(signoff_id)
        return s.status if s is not None else "UNRECORDED"


@lru_cache(maxsize=1)
def builtin() -> Register:
    text = (resources.files("aisw.policy") / "signoffs.json").read_text(encoding="utf-8")
    return Register.model_validate(json.loads(text))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def problems(register: Register, repo_root: Path) -> list[str]:
    out: list[str] = []
    for s in register.signoffs:
        path = repo_root / s.artefact
        if not path.is_file():
            out.append(f"{s.id}: artefact {s.artefact} does not exist")
            continue
        if s.decision is not None and s.decision.sha256 != sha256_file(path):
            out.append(
                f"{s.id}: {s.artefact} changed after the {s.status} decision {s.decision.ref}"
            )
    return out


def render_markdown(register: Register) -> str:
    rows = [
        "# Sign-off register",
        "",
        "Generated from `backend/aisw/policy/signoffs.json` by `tools/signoffs.py`; do not edit.",
        "",
        "While an item is PENDING, the product keeps the label shown here. A decision needs the",
        "decider, the date, a reference and the sha256 of the exact artefact; changing the artefact",
        "afterwards fails the check until a new decision is recorded.",
        "",
        "| Id | Plan | Subject | Owner | Status | Shown while pending | Next step |",
        "|---|---|---|---|---|---|---|",
    ]
    for s in register.signoffs:
        status: str = s.status
        if s.decision is not None:
            status += f" by {s.decision.by} on {s.decision.at.isoformat()} ({s.decision.ref})"
        rows.append(
            f"| `{s.id}` | {s.plan_ref} | {s.subject} (`{s.artefact}`) | {s.owner} | {status} "
            f"| {s.label_while_pending} | {s.next_step} |"
        )
    return "\n".join(rows) + "\n"
