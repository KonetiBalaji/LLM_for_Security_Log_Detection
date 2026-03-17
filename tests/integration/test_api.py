"""Integration tests for the FastAPI application."""

from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient

from sentinel.api.app import create_app
from sentinel.core.config import SentinelSettings


@pytest.fixture
def client():
    """Create a test client with auth disabled."""
    settings = SentinelSettings(auth_enabled=False)
    app = create_app(settings)
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data


class TestAnalyzeRawEndpoint:
    def test_analyze_raw_logs(self, client):
        logs = "Backup completed successfully.\nMultiple failed login attempts from 10.0.0.1"
        response = client.post(
            "/v1/analyze/raw",
            data={"logs": logs},
        )
        assert response.status_code == 200
        data = response.json()
        assert "events" in data
        assert "summary" in data
        assert "recommendations" in data

    def test_analyze_empty_logs_returns_400(self, client):
        response = client.post(
            "/v1/analyze/raw",
            data={"logs": "   "},
        )
        assert response.status_code == 400


class TestClassifyEndpoint:
    def test_classify_csv_file(self, client):
        csv_content = "source,log_message\nTestSys,Backup completed successfully.\nTestSys,User admin logged in."
        file = io.BytesIO(csv_content.encode())
        response = client.post(
            "/v1/classify",
            files={"file": ("test.csv", file, "text/csv")},
        )
        assert response.status_code == 200
        assert "text/csv" in response.headers.get("content-type", "")

    def test_classify_rejects_unsupported_extension(self, client):
        file = io.BytesIO(b"some data")
        response = client.post(
            "/v1/classify",
            files={"file": ("test.exe", file, "application/octet-stream")},
        )
        assert response.status_code == 400


class TestAnalyzeFileEndpoint:
    def test_analyze_csv_file(self, client):
        csv_content = (
            "source,log_message\n"
            "TestSys,Multiple failed login attempts from 10.0.0.1\n"
            "TestSys,Backup completed successfully.\n"
        )
        file = io.BytesIO(csv_content.encode())
        response = client.post(
            "/v1/analyze",
            files={"file": ("test.csv", file, "text/csv")},
        )
        assert response.status_code == 200
        data = response.json()
        assert "events" in data
        assert "mitre_coverage" in data
