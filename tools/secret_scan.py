"""Minimal offline secret scanner used by CI and pre-commit (M0 stopgap).

Planned replacement/supplement: gitleaks (MIT) once installable in CI. A line may be
allow-listed with the marker `aisw:allow-secret` (e.g. for deliberately fake fixtures).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "node_modules", "dist", "__pycache__", ".mypy_cache", ".ruff_cache"}
PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "aws-access-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "bearer-token": re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{30,}=*"),
    "generic-secret-assignment": re.compile(
        r"""(?i)\b(?:password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*["'][^"'\s]{12,}["']"""
    ),
    "connection-string-creds": re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s:@]{3,}@"),
}
ALLOW = "aisw:allow-secret"


def scan_text(text: str) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    for no, line in enumerate(text.splitlines(), 1):
        if ALLOW in line:
            continue
        hits.extend((no, name) for name, rx in PATTERNS.items() if rx.search(line))
    return hits


def scan_tree(root: Path) -> list[str]:
    findings: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if path.stat().st_size > 2_000_000:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            findings.extend(f"{path}:{no}: {rule}" for no, rule in scan_text(text))
    return findings


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    findings = scan_tree(root)
    for f in findings:
        print(f)  # noqa: T201
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
