"""Every third-party module the aisw package imports is installed in the production image.

The image installs only the runtime dependencies (`uv sync --no-dev`), while tests run with the
dev group as well, so a module that is only a dev dependency imports fine here and fails in
production.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from importlib.metadata import packages_distributions
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]


def _norm(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def runtime_closure() -> set[str]:
    """Names of the locked packages reachable from aisw's runtime dependencies, markers ignored."""
    lock = tomllib.loads((BACKEND / "uv.lock").read_text())
    pkgs = {_norm(p["name"]): p for p in lock["package"]}
    seen: set[str] = set()
    todo = [(d["name"], tuple(d.get("extra", ()))) for d in pkgs["aisw"]["dependencies"]]
    while todo:
        name, extras = todo.pop()
        pkg = pkgs[_norm(name)]
        deps = list(pkg.get("dependencies", []))
        for extra in extras:
            deps += pkg.get("optional-dependencies", {}).get(extra, [])
        new = _norm(name) not in seen
        seen.add(_norm(name))
        if new or extras:
            todo += [(d["name"], tuple(d.get("extra", ()))) for d in deps]
    return seen


def imported_top_levels() -> dict[str, str]:
    """Top-level module name -> first file importing it, for every absolute import under aisw/."""
    found: dict[str, str] = {}
    for path in sorted((BACKEND / "aisw").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(), str(path))):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            else:
                continue
            for n in names:
                found.setdefault(n.split(".")[0], str(path.relative_to(BACKEND)))
    return found


def test_every_third_party_import_is_a_runtime_dependency() -> None:
    closure = runtime_closure()
    dists = packages_distributions()
    missing = {}
    for mod, where in imported_top_levels().items():
        if mod in sys.stdlib_module_names or mod in {"aisw", "__future__"}:
            continue
        owners = {_norm(d) for d in dists.get(mod, [])}
        if not owners & closure:
            missing[mod] = (where, sorted(owners) or ["not installed"])
    assert missing == {}, f"imported but not runtime dependencies: {missing}"


def test_closure_follows_extras() -> None:
    assert {"psycopg", "psycopg-binary", "fastapi", "starlette"} <= runtime_closure()
