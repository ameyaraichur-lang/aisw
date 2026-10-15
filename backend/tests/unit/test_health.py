from fastapi.testclient import TestClient

from aisw.api.app import create_app
from aisw.core.config import Settings


def test_health_and_ready() -> None:
    client = TestClient(create_app(Settings()))
    assert client.get("/healthz").json()["status"] == "ok"
    ready = client.get("/readyz").json()
    assert ready["assessment_mode"] == "read_only"
    assert ready["ai_enabled"] is False


def test_no_docs_or_openapi_ui_exposed() -> None:
    client = TestClient(create_app(Settings()))
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
