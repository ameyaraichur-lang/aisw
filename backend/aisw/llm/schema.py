"""Strict shapes for what goes to, and what may come back from, the model."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from aisw.contracts.base import NonEmpty, Slug, StrictModel

Text = Annotated[str, StringConstraints(min_length=1, max_length=400)]


class Fact(StrictModel):
    finding_id: Slug
    title: NonEmpty
    severity: str
    category: str
    asset_ids: list[Slug]
    evidence_refs: list[NonEmpty]
    control_ids: list[str] = Field(default_factory=list)  # "<framework> <control_id>"


class NarrativeSubject(StrictModel):
    purpose: Literal["scenario", "recommendation"]
    subject_ref: Slug
    title: NonEmpty
    tier: Literal["P0", "P1", "P2", "P3"] | None
    facts: list[Fact] = Field(min_length=1)
    context: list[NonEmpty] = Field(
        default_factory=list
    )  # deterministic text already shown to users


class Claim(StrictModel):
    text: Text
    finding_ids: list[Slug] = Field(min_length=1, max_length=8)
    asset_ids: list[Slug] = Field(min_length=1, max_length=8)


class NarrativeOutput(StrictModel):
    """extra="forbid": a "tool_calls", "command" or any other unexpected field is a rejection."""

    summary: Annotated[str, StringConstraints(min_length=1, max_length=800)]
    claims: list[Claim] = Field(min_length=1, max_length=8)
    open_questions: list[Text] = Field(default_factory=list, max_length=5)
