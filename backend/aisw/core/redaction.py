"""Single redaction path for logs, audit detail, UI payloads and (later) model inputs."""

from __future__ import annotations

import logging
import re
from typing import Any

REDACTED = "[REDACTED]"

_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{8,}=*"),
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s:@]+@"),  # creds in connection strings
    re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b(\s*[:=]\s*)[^\s,;\"']+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\b"),  # JWT
]
_SENSITIVE_KEY = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|token|authorization|private[_-]?key|credential)"
)


def redact_text(text: str) -> str:
    out = text
    for rx in _PATTERNS:
        if rx.groups >= 2:
            out = rx.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", out)
        elif rx.pattern.startswith(r"\b[a-z][a-z0-9+.-]*://"):
            out = rx.sub(lambda m: m.group(0).split("//")[0] + "//" + REDACTED + "@", out)
        else:
            out = rx.sub(REDACTED, out)
    return out


def redact_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {
            k: (REDACTED if isinstance(k, str) and _SENSITIVE_KEY.search(k) else redact_obj(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list | tuple):
        return [redact_obj(v) for v in obj]
    return obj


class RedactingFilter(logging.Filter):
    """Attach to handlers so ordinary logs never carry secrets."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(record.getMessage())
        record.args = ()
        return True
