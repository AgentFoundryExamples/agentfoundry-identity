# SPDX-License-Identifier: GPL-3.0-only
"""Tests for health endpoint and application factory."""

import os
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from af_identity_service import __service__, __version__


# Test environment with valid configuration
VALID_ENV = {
    "IDENTITY_JWT_SECRET": "a" * 32,
    "GITHUB_CLIENT_ID": "test-client-id",
    "GITHUB_CLIENT_SECRET": "test-client-secret",
}


@pytest.fixture
def valid_env():
    """Fixture to set valid environment variables."""
    with patch.dict(os.environ, VALID_ENV, clear=True):
        yield


@pytest.fixture
async def app_with_lifespan(valid_env):
    """Fixture that provides a FastAPI app with lifespan initialized."""
    from af_identity_service.app import create_app

    app = create_app()
    async with app.router.lifespan_context(app):
        yield app


class TestHealthEndpoint:
    """Tests for the /healthz endpoint."""

    @pytest.mark.asyncio
    async def test_healthz_returns_healthy_status(self, app_with_lifespan) -> None:
        """Test that /healthz returns healthy status with valid config."""
        transport = ASGITransport(app=app_with_lifespan)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/healthz")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == __service__
        assert data["version"] == __version__
        assert data["checks"]["driver_factory"] == "ok"
        assert data["checks"]["session_store_factory"] == "ok"

    @pytest.mark.asyncio
    async def test_healthz_returns_correct_service_name(self, app_with_lifespan) -> None:
        """Test that /healthz returns the correct service name."""
        transport = ASGITransport(app=app_with_lifespan)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/healthz")

        assert response.status_code == 200
        assert response.json()["service"] == "af-identity-service"

    @pytest.mark.asyncio
    async def test_healthz_returns_correct_version(self, app_with_lifespan) -> None:
        """Test that /healthz returns the correct version."""
        transport = ASGITransport(app=app_with_lifespan)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/healthz")

        assert response.status_code == 200
        assert response.json()["version"] == "0.1.0"


class TestRequestIdMiddleware:
    """Tests for request ID middleware."""

    @pytest.mark.asyncio
    async def test_generates_request_id_when_missing(self, app_with_lifespan) -> None:
        """Test that middleware generates request ID when not provided."""
        transport = ASGITransport(app=app_with_lifespan)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/healthz")

        assert response.status_code == 200
        assert "x-request-id" in response.headers
        # Check it's a valid UUID format (36 chars with hyphens)
        request_id = response.headers["x-request-id"]
        assert len(request_id) == 36
        assert request_id.count("-") == 4

    @pytest.mark.asyncio
    async def test_propagates_existing_request_id(self, app_with_lifespan) -> None:
        """Test that middleware propagates existing request ID."""
        existing_id = "test-request-id-12345"
        transport = ASGITransport(app=app_with_lifespan)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/healthz", headers={"X-Request-ID": existing_id}
            )

        assert response.status_code == 200
        assert response.headers["x-request-id"] == existing_id


class TestApplicationFactory:
    """Tests for the application factory."""

    @pytest.mark.asyncio
    async def test_create_app_returns_fastapi_instance(self, valid_env) -> None:
        """Test that create_app returns a FastAPI instance."""
        from fastapi import FastAPI

        from af_identity_service.app import create_app

        app = create_app()
        assert isinstance(app, FastAPI)

    @pytest.mark.asyncio
    async def test_app_has_correct_title(self, valid_env) -> None:
        """Test that app has the correct title."""
        from af_identity_service.app import create_app

        app = create_app()
        assert app.title == "AF Identity Service"

    @pytest.mark.asyncio
    async def test_app_has_correct_version(self, valid_env) -> None:
        """Test that app has the correct version."""
        from af_identity_service.app import create_app

        app = create_app()
        assert app.version == "0.1.0"
