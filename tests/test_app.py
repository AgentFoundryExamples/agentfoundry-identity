# ============================================================
# SPDX-License-Identifier: GPL-3.0-or-later
# This program was generated as part of the AgentFoundry project.
# Copyright (C) 2025  John Brosnihan
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ============================================================
"""Tests for the FastAPI application."""

import pytest
from fastapi.testclient import TestClient

from af_identity_service import __service_name__, __version__
from af_identity_service.app import create_app
from af_identity_service.config import Settings
from af_identity_service.dependencies import reset_dependencies


@pytest.fixture
def valid_settings() -> Settings:
    """Create valid settings for testing."""
    return Settings(
        identity_jwt_secret="a" * 32,
        github_client_id="test-client-id",
        github_client_secret="test-client-secret",
        log_format="console",  # Use console format for tests
    )


@pytest.fixture
def client(valid_settings: Settings) -> TestClient:
    """Create a test client with valid settings."""
    reset_dependencies()
    app = create_app(valid_settings)
    return TestClient(app)


class TestHealthEndpoint:
    """Tests for the /healthz endpoint."""

    def test_healthz_returns_200(self, client: TestClient) -> None:
        """Test that /healthz returns 200 when healthy."""
        response = client.get("/healthz")

        assert response.status_code == 200

    def test_healthz_returns_correct_body(self, client: TestClient) -> None:
        """Test that /healthz returns correct response body."""
        response = client.get("/healthz")
        data = response.json()

        assert data["status"] == "healthy"
        assert data["service"] == __service_name__
        assert data["version"] == __version__

    def test_healthz_includes_request_id_header(self, client: TestClient) -> None:
        """Test that /healthz response includes X-Request-ID header."""
        response = client.get("/healthz")

        assert "X-Request-ID" in response.headers
        # Verify it's a valid UUID format
        request_id = response.headers["X-Request-ID"]
        assert len(request_id) == 36  # UUID4 with dashes


class TestRequestIDMiddleware:
    """Tests for the request ID middleware."""

    def test_request_id_is_unique_per_request(self, client: TestClient) -> None:
        """Test that each request gets a unique request ID."""
        response1 = client.get("/healthz")
        response2 = client.get("/healthz")

        assert response1.headers["X-Request-ID"] != response2.headers["X-Request-ID"]

    def test_request_id_is_valid_uuid(self, client: TestClient) -> None:
        """Test that request ID is a valid UUID4."""
        import uuid

        response = client.get("/healthz")
        request_id = response.headers["X-Request-ID"]

        # This will raise ValueError if not a valid UUID
        parsed = uuid.UUID(request_id)
        assert parsed.version == 4


class TestAppFactory:
    """Tests for the create_app factory function."""

    def test_create_app_returns_fastapi_instance(
        self, valid_settings: Settings
    ) -> None:
        """Test that create_app returns a FastAPI instance."""
        from fastapi import FastAPI

        reset_dependencies()
        app = create_app(valid_settings)

        assert isinstance(app, FastAPI)
        reset_dependencies()

    def test_create_app_has_correct_title(self, valid_settings: Settings) -> None:
        """Test that app has correct title."""
        reset_dependencies()
        app = create_app(valid_settings)

        assert app.title == "Agent Foundry Identity Service"
        reset_dependencies()

    def test_create_app_has_correct_version(self, valid_settings: Settings) -> None:
        """Test that app has correct version."""
        reset_dependencies()
        app = create_app(valid_settings)

        assert app.version == __version__
        reset_dependencies()


class TestAPIDocumentation:
    """Tests for API documentation endpoints."""

    def test_docs_endpoint_accessible(self, client: TestClient) -> None:
        """Test that /docs endpoint is accessible."""
        response = client.get("/docs")

        assert response.status_code == 200

    def test_redoc_endpoint_accessible(self, client: TestClient) -> None:
        """Test that /redoc endpoint is accessible."""
        response = client.get("/redoc")

        assert response.status_code == 200

    def test_openapi_schema_accessible(self, client: TestClient) -> None:
        """Test that OpenAPI schema is accessible."""
        response = client.get("/openapi.json")

        assert response.status_code == 200
        data = response.json()
        assert data["info"]["title"] == "Agent Foundry Identity Service"
        assert data["info"]["version"] == __version__
