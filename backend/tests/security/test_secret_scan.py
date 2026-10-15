"""The repo secret scanner must catch seeded secrets and pass on this repo."""

import importlib.util
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.security
ROOT = Path(__file__).resolve().parents[3]


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("secret_scan", ROOT / "tools" / "secret_scan.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_detects_seeded_secrets() -> None:
    scan = _load().scan_text
    assert scan("key = 'AKIA" + "ABCDEFGHIJKLMNOP'")
    assert scan("-----BEGIN RSA PRIVATE" + " KEY-----")
    assert scan("password = 'hunter2hunter2hunter2'")  # aisw:allow-secret
    assert scan("postgres://admin:s3cr3tpw@db:5432/x")  # aisw:allow-secret
    assert scan("Authorization: Bearer " + "a" * 40)


def test_allow_marker_and_clean_lines() -> None:
    scan = _load().scan_text
    assert not scan("password = 'hunter2hunter2hunter2'  # aisw:allow-secret")
    assert not scan("AISW_AI_ENABLED=false")


def test_repository_is_clean() -> None:
    assert _load().scan_tree(ROOT) == []
