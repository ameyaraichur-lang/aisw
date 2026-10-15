from __future__ import annotations

import logging

import pytest

from aisw.core.redaction import REDACTED, RedactingFilter, redact_obj, redact_text

pytestmark = pytest.mark.security

SECRETS = [
    "AKIA" + "ABCDEFGHIJKLMNOP",
    "Bearer " + "abc123def456ghi789jkl",
    "password=" + "hunter2hunter2",
    "api_key: " + "sk_live_abcdef123456",
    "postgres://svc:" + "s3cr3tpass@db:5432/app",
    "-----BEGIN RSA PRIVATE " + "KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig_abcdef",
]
LEAK_MARKERS = ["ABCDEFGHIJKLMNOP", "abc123def456", "hunter2", "sk_live", "s3cr3tpass", "MIIEow",
                "eyJzdWIi"]  # fmt: skip


@pytest.mark.parametrize("secret", SECRETS, ids=[f"secret-kind-{i}" for i in range(len(SECRETS))])
def test_text_secrets_are_redacted(secret: str) -> None:
    out = redact_text(f"before {secret} after")
    assert REDACTED in out and not any(m in out for m in LEAK_MARKERS)
    assert out.startswith("before") and out.endswith("after") or "PRIVATE KEY" not in secret


def test_nested_objects_and_sensitive_keys() -> None:
    obj = {
        "ok": "value",
        "Authorization": "Bearer xyz",
        "nested": {"db_password": "p", "list": [{"api-key": "k"}, "token=abcdefgh1234"]},
    }
    out = redact_obj(obj)
    assert out["ok"] == "value"
    assert out["Authorization"] == REDACTED
    assert out["nested"]["db_password"] == REDACTED
    assert out["nested"]["list"][0]["api-key"] == REDACTED
    assert "abcdefgh1234" not in str(out)
    assert obj["Authorization"] == "Bearer xyz"  # input not mutated


def test_non_secret_text_untouched() -> None:
    s = "scan of https://example.com finished: 12 findings, status=PARTIAL"
    assert redact_text(s) == s


def test_logging_filter_scrubs_records(caplog: pytest.LogCaptureFixture) -> None:
    log = logging.getLogger("aisw.test")
    seen: list[str] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record.getMessage())

    handler = Capture()
    handler.addFilter(RedactingFilter())
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.info("connecting with %s", "password=" + "hunter2hunter2")
    assert seen and "hunter2" not in seen[0] and REDACTED in seen[0]
