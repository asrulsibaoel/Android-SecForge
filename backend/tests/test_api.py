from fastapi.testclient import TestClient

from app.main import app


def test_health_endpoint() -> None:
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_root_serves_web_ui() -> None:
    response = TestClient(app).get("/")
    assert response.status_code == 200
    assert "AndroidSecForge" in response.text
    assert response.headers["content-type"].startswith("text/html")


def test_artifact_list_endpoint() -> None:
    response = TestClient(app).get("/api/v1/apk")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_ipc_route_returns_404_for_unknown_artifact() -> None:
    response = TestClient(app).get("/api/v1/apk/00000000-0000-0000-0000-000000000000/ipc")
    assert response.status_code == 404


def test_dex_route_returns_404_for_unknown_artifact() -> None:
    response = TestClient(app).get("/api/v1/apk/00000000-0000-0000-0000-000000000000/dex")
    assert response.status_code == 404


def test_framework_route_returns_model() -> None:
    response = TestClient(app).get("/api/v1/apk/00000000-0000-0000-0000-000000000000/framework")
    assert response.status_code == 404


def test_analysis_report_route_returns_404_for_unknown() -> None:
    response = TestClient(app).get("/api/v1/analysis/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404


def test_analyses_for_unknown_apk_returns_empty_list() -> None:
    response = TestClient(app).get("/api/v1/apk/00000000-0000-0000-0000-000000000000/analyses")
    assert response.status_code == 200
    assert response.json() == []