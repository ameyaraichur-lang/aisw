"""Shared machinery for import adapters (file in, normalized evidence out; no network, no host).

Input is UNTRUSTED. Rules every import adapter inherits:
* the file arrives only through ``job.read_import`` (tenant/project/kind/hash verified by the
  gateway); there is no path, URL or file handle to abuse
* XML is parsed with DTDs, entities and external references forbidden (no XXE / entity bombs);
  JSON is depth-limited by the parser; CSV rows and field sizes are capped
* anything outside the signed scope is DROPPED (never ingested) and only counted
* an unsupported or tampered format fails closed with a stable code; it is never half-trusted
* values are truncated and cleaned; only what a policy rule needs is kept, never free-form bodies
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

import defusedxml
from defusedxml import ElementTree as SafeET
from pydantic import Field

from aisw.adapters.normalized import NormalizedBatch
from aisw.contracts.base import StrictModel
from aisw.contracts.enums import ProfileClass
from aisw.gateway.registry import (
    AdapterCapability,
    AdapterJob,
    AdapterOutput,
    ImportReadError,
)

MAX_RECORDS = 20_000
MAX_TEXT = 300


class ImportParseError(Exception):
    """The file is unusable; ``code`` is stable and safe to show."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ImportParams(StrictModel):
    import_id: str = Field(pattern=r"^imp-[0-9a-f]{20}$")


def clean(value: Any, limit: int = MAX_TEXT) -> str:
    s = "" if value is None else str(value)
    return " ".join(s.replace("\r", " ").replace("\n", " ").split())[:limit]


def parse_xml(text: str) -> Any:
    """Parse untrusted XML with DTD/entity/external-reference handling disabled."""
    try:
        return SafeET.fromstring(text, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except defusedxml.DefusedXmlException as exc:
        raise ImportParseError("XML_FORBIDDEN_CONSTRUCT") from exc
    except SafeET.ParseError as exc:
        raise ImportParseError("MALFORMED_XML") from exc


def local(tag: str) -> str:
    """Tag name without its XML namespace."""
    return tag.rsplit("}", 1)[-1]


def parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ImportParseError("MALFORMED_JSON") from exc


def cap(items: list[Any]) -> list[Any]:
    if len(items) > MAX_RECORDS:
        raise ImportParseError("TOO_MANY_RECORDS")
    return items


@dataclass
class Parsed:
    raw: dict[str, Any]
    tool_version: str
    status: Literal["SUCCEEDED", "PARTIAL", "FAILED"] = "SUCCEEDED"
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class ImportAdapter:
    """Subclasses set the class attributes and implement ``parse`` and ``normalize``."""

    adapter_id: str
    tool: str
    version = "0.1.0"
    domains: frozenset[str]
    profiles: dict[str, ProfileClass]
    target_kinds: frozenset[str]
    import_kinds: frozenset[str]
    formats: tuple[str, ...]
    param_model: type[ImportParams] = ImportParams

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self.capability = AdapterCapability(
            adapter_id=self.adapter_id, version=self.version, domains=self.domains,
            profiles=self.profiles, target_kinds=self.target_kinds, param_model=self.param_model,
            kind="import", import_kinds=self.import_kinds, formats=self.formats,
        )  # fmt: skip

    def estimate_requests(self, params: dict[str, Any]) -> int:
        return 1  # reading one stored file; no outbound requests are ever made

    def parse(self, text: str, job: AdapterJob, params: Any) -> Parsed:
        raise NotImplementedError

    def normalize(self, output: AdapterOutput, *, run_id: str, task_id: str) -> NormalizedBatch:
        raise NotImplementedError

    # ------------------------------------------------------------------ execution
    def execute(self, job: AdapterJob) -> AdapterOutput:
        params = self.param_model.model_validate(job.params)
        if job.read_import is None:
            return self._failed("IMPORTS_UNAVAILABLE", params)
        try:
            data = job.read_import(params.import_id, self.import_kinds)
            text = data.decode("utf-8")
        except ImportReadError as exc:
            return self._failed(exc.code, params)
        except UnicodeDecodeError:
            return self._failed("NOT_UTF8", params)
        try:
            parsed = self.parse(text, job, params)
        except ImportParseError as exc:
            return self._failed(exc.code, params)
        raw = {"tool": self.tool, "adapter": self.adapter_id, "import_id": params.import_id,
               "formats": list(self.formats), **parsed.raw}  # fmt: skip
        return AdapterOutput(
            status=parsed.status, tool=self.tool, tool_version=parsed.tool_version,
            collected_at=self._clock(), raw=raw, warnings=parsed.warnings, errors=parsed.errors,
        )  # fmt: skip

    def _failed(self, code: str, params: ImportParams) -> AdapterOutput:
        return AdapterOutput(
            status="FAILED", tool=self.tool, tool_version="unknown", collected_at=self._clock(),
            raw={"tool": self.tool, "adapter": self.adapter_id, "import_id": params.import_id,
                 "error": code, "records": []},
            errors=[code],
        )  # fmt: skip

    # ------------------------------------------------------------------ helpers
    def scope_drop(self, job: AdapterJob, kind: str, selector: str) -> bool:
        """True when a record must be DROPPED because it is outside the signed scope."""
        return job.in_scope is not None and not job.in_scope(kind, selector)
