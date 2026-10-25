"""Testes da API com banco simulado; nunca acessam o MySQL de produção."""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api import create_app
from api_modules.config import APISettings


class FakeCursor:
    def execute(self, *_args, **_kwargs) -> None:
        pass

    def fetchone(self):
        return (1,)

    def close(self) -> None:
        pass


class FakeConnection:
    def cursor(self, **_kwargs):
        return FakeCursor()


def settings(*, docs: bool = True) -> APISettings:
    return APISettings(
        environment="test",
        docs_enabled=docs,
        cors_origins=("https://app.example.test",),
        mysql={},
        pool_size=1,
        report_directory="unused",
    )


def connection_provider():
    yield FakeConnection()


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(settings(), connection_provider=connection_provider))


def auth() -> dict[str, str]:
    return {}


def test_endpoints_do_not_require_api_key(client: TestClient) -> None:
    with patch("api_modules.routes.fetch_inventory", return_value=[]):
        assert client.get("/api/v1/devices").status_code == 200


def test_devices_returns_json_and_applies_pagination(client: TestClient) -> None:
    row = {"network": "192.168.1.0/24", "mac": "AA:BB:CC:DD:EE:FF", "status": "online"}
    with patch("api_modules.routes.fetch_inventory", return_value=[row]) as fetch:
        response = client.get(
            "/api/v1/devices?page=3&limit=20&network=192.168.1.7/24&status=online",
            headers=auth(),
        )
    assert response.status_code == 200
    assert response.json()["data"] == [row]
    assert response.json()["pagination"] == {"page": 3, "limit": 20, "returned": 1}
    filters = fetch.call_args.args[1]
    assert filters.network == "192.168.1.0/24"
    assert filters.status == "online"
    assert filters.offset == 40


def test_events_filter_by_type(client: TestClient) -> None:
    with patch("api_modules.routes.fetch_events", return_value=[]) as fetch:
        response = client.get("/api/v1/events?event_type=OFFLINE&page=2&limit=5", headers=auth())
    assert response.status_code == 200
    assert fetch.call_args.kwargs["event_types"] == {"OFFLINE"}
    assert fetch.call_args.args[1].offset == 5


@pytest.mark.parametrize(
    "query",
    ["limit=0", "page=0", "ip=not-an-ip", "network=invalid", "start_date=2026-12-31&end_date=2026-01-01"],
)
def test_invalid_parameters_return_422(client: TestClient, query: str) -> None:
    assert client.get(f"/api/v1/devices?{query}", headers=auth()).status_code == 422


def test_unknown_device_returns_404(client: TestClient) -> None:
    with patch("api_modules.routes.get_device_history", return_value=None):
        response = client.get("/api/v1/devices/AA:BB:CC:DD:EE:FF", headers=auth())
    assert response.status_code == 404


def test_database_failure_is_generic_503() -> None:
    def broken_provider():
        raise ConnectionError("password=must-not-leak")
        yield

    local_client = TestClient(
        create_app(settings(), connection_provider=broken_provider),
        raise_server_exceptions=False,
    )
    response = local_client.get("/api/v1/health", headers=auth())
    assert response.status_code == 503
    assert "password" not in response.text


def test_health_checks_database(client: TestClient) -> None:
    assert client.get("/api/v1/health", headers=auth()).json() == {
        "status": "ok", "database": "connected"
    }


def test_report_json(client: TestClient) -> None:
    with patch("api_modules.routes.report_datasets", return_value={"inventario": [{"mac": "AA"}]}):
        response = client.get(
            "/api/v1/reports?report_type=inventario&format=json", headers=auth()
        )
    assert response.status_code == 200
    assert response.json()["data"]["inventario"][0]["mac"] == "AA"


def test_report_file_download(client: TestClient) -> None:
    def fake_report(_connection, _type, _format, _filters, directory, **_kwargs):
        path = Path(directory) / "report.csv"
        path.write_text("mac,status\nAA,online\n", encoding="utf-8")
        return (path,)

    with patch("api_modules.routes.generate_report", side_effect=fake_report):
        response = client.get(
            "/api/v1/reports?report_type=inventario&format=csv", headers=auth()
        )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "AA,online" in response.text


def test_production_can_disable_documentation() -> None:
    local_client = TestClient(create_app(settings(docs=False), connection_provider=connection_provider))
    assert local_client.get("/docs").status_code == 404
    assert local_client.get("/openapi.json").status_code == 404


def test_api_does_not_import_scanner_module() -> None:
    source = Path("api.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    )
    assert "network_mapper" not in imported
