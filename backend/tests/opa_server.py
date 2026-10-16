"""A real OPA server on loopback serving the packaged Rego (ADR-031). Skips when the opa binary is
absent, unless AISW_REQUIRE_OPA=1 (CI), where a missing binary is a failure."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

REGO = Path(__file__).resolve().parents[1] / "aisw" / "policy" / "rego"


def opa_binary() -> str | None:
    return os.environ.get("AISW_OPA_BIN") or shutil.which("opa")


def require_opa() -> str:
    binary = opa_binary()
    if binary is None:
        if os.environ.get("AISW_REQUIRE_OPA") == "1":
            pytest.fail("AISW_REQUIRE_OPA=1 but the opa binary was not found")
        pytest.skip("opa binary not installed (set AISW_OPA_BIN or put opa on PATH)")
    return binary


@contextmanager
def opa_server(policy_dir: Path = REGO) -> Iterator[str]:
    binary = require_opa()
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    proc = subprocess.Popen(  # noqa: S603
        [binary, "run", "--server", "--addr", f"127.0.0.1:{port}", "--disable-telemetry",
         "--log-level", "error", "--ignore", "*_test.rego", str(policy_dir)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )  # fmt: skip
    url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 20
        while True:
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(f"{url}/health", timeout=1) as r:  # noqa: S310
                    if r.status == 200:
                        break
            except OSError:
                pass
            if proc.poll() is not None or time.monotonic() > deadline:
                err = proc.stderr.read().decode() if proc.stderr else ""
                pytest.fail(f"opa server did not start: {err}")
            time.sleep(0.1)
        yield url
    finally:
        proc.terminate()
        proc.wait(timeout=10)
