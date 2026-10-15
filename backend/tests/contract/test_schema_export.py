"""Checked-in JSON Schemas must match the Pydantic contracts (schema-drift gate)."""

import importlib.util
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]


def _tool() -> Any:
    spec = importlib.util.spec_from_file_location(
        "export_schemas", ROOT / "tools" / "export_schemas.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_schemas_in_sync_and_forbid_unknown_fields() -> None:
    tool = _tool()
    rendered = tool.render()
    for name, text in rendered.items():
        assert (ROOT / "schemas" / name).read_text() == text, f"schema drift: {name}"
        assert '"additionalProperties": false' in text, f"{name} must forbid unknown fields"
