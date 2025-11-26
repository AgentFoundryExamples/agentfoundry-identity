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
"""Tests for GitHub token route and service."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from af_identity_service.config import Settings
from af_identity_service.dependencies import reset_dependencies
from af_identity_service.github.driver import GitHubOAuthDriver, GitHubOAuthDriverError
from af_identity_service.models.github import GitHubOAuthResult
from af_identity_service.models.session import Session
from af_identity_service.routes.github_token import create_github_token_router
from af_identity_service.security.jwt import mint_af_jwt
from af_identity_service.services.github_tokens import (
    GitHubAccessTokenResult,
    GitHubTokenService,
    RefreshTokenMissingError,
    TokenRefreshError,
)
from af_identity_service.stores.github_token_store import InMemoryGitHubTokenStore
from af_identity_service.stores.session_store import InMemorySessionStore
from af_identity_service.stores.user_store import InMemoryUserRepository


@pytest.fixture
def valid_settings() -> Settings:
    """Create valid settings for testing."""
    return Settings(
        identity_jwt_secret="a" * 32,
        github_client_id="test-client-id",
        github_client_secret="test-client-secret",
        log_format="console",
    )


@pytest.fixture
def session_store() -> InMemorySessionStore:
    """Create an in-memory session store."""
    return InMemorySessionStore()


@pytest.fixture
def user_repository() -> InMemoryUserRepository:
    """Create an in-memory user repository."""
    return InMemoryUserRepository()


@pytest.fixture
def token_store() -> InMemoryGitHubTokenStore:
    """Create an in-memory token store."""
    return InMemoryGitHubTokenStore()


@pytest.fixture
def jwt_secret() -> str:
    """Return a valid JWT secret."""
    return "a" * 32


class TestGitHubTokenService:
    """Tests for GitHubTokenService."""

    @pytest.fixture
    def mock_github_driver(self) -> AsyncMock:
        """Create a mock GitHub driver."""
        driver = AsyncMock(spec=GitHubOAuthDriver)
        return driver

    @pytest.fixture
    def github_token_service(
        self,
        token_store: InMemoryGitHubTokenStore,
        mock_github_driver: AsyncMock,
    ) -> GitHubTokenService:
        """Create a GitHub token service with test dependencies."""
        return GitHubTokenService(
            token_store=token_store,
            github_driver=mock_github_driver,
        )

    @pytest.mark.asyncio
    async def test_get_access_token_returns_cached_token(
        self,
        github_token_service: GitHubTokenService,
        token_store: InMemoryGitHubTokenStore,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test that cached tokens are returned when valid."""
        # Create user
        user = await user_repository.upsert_by_github_id(12345, "testuser")

        # Store tokens
        now = datetime.now(timezone.utc)
        tokens = GitHubOAuthResult(
            access_token="cached_access_token",
            access_token_expires_at=now + timedelta(hours=8),
            refresh_token="test_refresh_token",
            refresh_token_expires_at=now + timedelta(days=180),
        )
        await token_store.store_tokens(user.id, tokens)

        # Get access token
        result = await github_token_service.get_access_token(user.id)

        assert result.access_token == "cached_access_token"

    @pytest.mark.asyncio
    async def test_get_access_token_refreshes_when_expired(
        self,
        github_token_service: GitHubTokenService,
        token_store: InMemoryGitHubTokenStore,
        user_repository: InMemoryUserRepository,
        mock_github_driver: AsyncMock,
    ) -> None:
        """Test that expired tokens trigger a refresh."""
        # Create user
        user = await user_repository.upsert_by_github_id(12345, "testuser")

        # Store expired tokens
        now = datetime.now(timezone.utc)
        expired_tokens = GitHubOAuthResult(
            access_token="expired_token",
            access_token_expires_at=now - timedelta(hours=1),
            refresh_token="test_refresh_token",
            refresh_token_expires_at=now + timedelta(days=180),
        )
        await token_store.store_tokens(user.id, expired_tokens)

        # Setup mock to return new tokens
        new_tokens = GitHubOAuthResult(
            access_token="new_access_token",
            access_token_expires_at=now + timedelta(hours=8),
            refresh_token="new_refresh_token",
            refresh_token_expires_at=now + timedelta(days=180),
        )
        mock_github_driver.refresh_access_token.return_value = new_tokens

        # Get access token (should refresh)
        result = await github_token_service.get_access_token(user.id)

        assert result.access_token == "new_access_token"
        mock_github_driver.refresh_access_token.assert_called_once_with("test_refresh_token")

    @pytest.mark.asyncio
    async def test_get_access_token_force_refresh_bypasses_cache(
        self,
        github_token_service: GitHubTokenService,
        token_store: InMemoryGitHubTokenStore,
        user_repository: InMemoryUserRepository,
        mock_github_driver: AsyncMock,
    ) -> None:
        """Test that force_refresh bypasses cache."""
        # Create user
        user = await user_repository.upsert_by_github_id(12345, "testuser")

        # Store valid tokens
        now = datetime.now(timezone.utc)
        tokens = GitHubOAuthResult(
            access_token="cached_access_token",
            access_token_expires_at=now + timedelta(hours=8),
            refresh_token="test_refresh_token",
            refresh_token_expires_at=now + timedelta(days=180),
        )
        await token_store.store_tokens(user.id, tokens)

        # Setup mock to return new tokens
        new_tokens = GitHubOAuthResult(
            access_token="fresh_access_token",
            access_token_expires_at=now + timedelta(hours=8),
            refresh_token="test_refresh_token",
            refresh_token_expires_at=now + timedelta(days=180),
        )
        mock_github_driver.refresh_access_token.return_value = new_tokens

        # Get access token with force refresh
        result = await github_token_service.get_access_token(user.id, force_refresh=True)

        assert result.access_token == "fresh_access_token"
        mock_github_driver.refresh_access_token.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_access_token_refreshes_near_expiry_tokens(
        self,
        github_token_service: GitHubTokenService,
        token_store: InMemoryGitHubTokenStore,
        user_repository: InMemoryUserRepository,
        mock_github_driver: AsyncMock,
    ) -> None:
        """Test that near-expiry tokens (within buffer) trigger a refresh."""
        # Create user
        user = await user_repository.upsert_by_github_id(12345, "testuser")

        # Store tokens that expire within the 5-minute buffer
        now = datetime.now(timezone.utc)
        near_expiry_tokens = GitHubOAuthResult(
            access_token="near_expiry_token",
            access_token_expires_at=now + timedelta(minutes=2),  # Expires in 2 min (within 5 min buffer)
            refresh_token="test_refresh_token",
            refresh_token_expires_at=now + timedelta(days=180),
        )
        await token_store.store_tokens(user.id, near_expiry_tokens)

        # Setup mock to return new tokens
        new_tokens = GitHubOAuthResult(
            access_token="fresh_access_token",
            access_token_expires_at=now + timedelta(hours=8),
            refresh_token="test_refresh_token",
            refresh_token_expires_at=now + timedelta(days=180),
        )
        mock_github_driver.refresh_access_token.return_value = new_tokens

        # Get access token (should refresh because near-expiry)
        result = await github_token_service.get_access_token(user.id)

        assert result.access_token == "fresh_access_token"
        mock_github_driver.refresh_access_token.assert_called_once_with("test_refresh_token")

    @pytest.mark.asyncio
    async def test_get_access_token_returns_actual_expiry_time(
        self,
        github_token_service: GitHubTokenService,
        token_store: InMemoryGitHubTokenStore,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test that returned expiry time reflects actual stored expiry."""
        # Create user
        user = await user_repository.upsert_by_github_id(12345, "testuser")

        # Store tokens with specific expiry
        now = datetime.now(timezone.utc)
        expected_expiry = now + timedelta(hours=6)
        tokens = GitHubOAuthResult(
            access_token="cached_access_token",
            access_token_expires_at=expected_expiry,
            refresh_token="test_refresh_token",
            refresh_token_expires_at=now + timedelta(days=180),
        )
        await token_store.store_tokens(user.id, tokens)

        # Get access token
        result = await github_token_service.get_access_token(user.id)

        # Verify the returned expiry matches what was stored
        assert result.expires_at == expected_expiry

    @pytest.mark.asyncio
    async def test_get_access_token_raises_on_missing_refresh_token(
        self,
        github_token_service: GitHubTokenService,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test that missing refresh token raises appropriate error."""
        # Create user without storing tokens
        user = await user_repository.upsert_by_github_id(12345, "testuser")

        # Get access token should raise
        with pytest.raises(RefreshTokenMissingError):
            await github_token_service.get_access_token(user.id)

    @pytest.mark.asyncio
    async def test_get_access_token_raises_on_driver_error(
        self,
        github_token_service: GitHubTokenService,
        token_store: InMemoryGitHubTokenStore,
        user_repository: InMemoryUserRepository,
        mock_github_driver: AsyncMock,
    ) -> None:
        """Test that driver errors are wrapped appropriately."""
        # Create user
        user = await user_repository.upsert_by_github_id(12345, "testuser")

        # Store tokens with valid refresh token but expired access
        now = datetime.now(timezone.utc)
        tokens = GitHubOAuthResult(
            access_token="expired_token",
            access_token_expires_at=now - timedelta(hours=1),
            refresh_token="test_refresh_token",
            refresh_token_expires_at=now + timedelta(days=180),
        )
        await token_store.store_tokens(user.id, tokens)

        # Setup mock to raise error
        mock_github_driver.refresh_access_token.side_effect = GitHubOAuthDriverError("API error")

        # Get access token should raise
        with pytest.raises(TokenRefreshError):
            await github_token_service.get_access_token(user.id)


class TestGitHubTokenRoute:
    """Tests for POST /v1/github/token endpoint."""

    @pytest.fixture
    def mock_github_token_service(self) -> AsyncMock:
        """Create a mock GitHub token service."""
        service = AsyncMock(spec=GitHubTokenService)
        return service

    @pytest.fixture
    def test_client(
        self,
        jwt_secret: str,
        session_store: InMemorySessionStore,
        user_repository: InMemoryUserRepository,
        mock_github_token_service: AsyncMock,
    ) -> TestClient:
        """Create a test client with GitHub token routes."""
        app = FastAPI()
        router = create_github_token_router(
            jwt_secret=jwt_secret,
            session_store=session_store,
            user_repository=user_repository,
            github_token_service=mock_github_token_service,
        )
        app.include_router(router)
        return TestClient(app)

    @pytest.mark.asyncio
    async def test_get_github_token_success(
        self,
        test_client: TestClient,
        jwt_secret: str,
        session_store: InMemorySessionStore,
        user_repository: InMemoryUserRepository,
        mock_github_token_service: AsyncMock,
    ) -> None:
        """Test successful GitHub token retrieval."""
        # Create user and session
        user = await user_repository.upsert_by_github_id(12345, "testuser")
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        session = Session(user_id=user.id, expires_at=expires_at)
        await session_store.create(session)

        # Mint token
        token = mint_af_jwt(
            secret=jwt_secret,
            user_id=user.id,
            session_id=session.session_id,
            expires_at=expires_at,
        )

        # Setup mock
        mock_github_token_service.get_access_token.return_value = GitHubAccessTokenResult(
            access_token="github_access_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
        )

        response = test_client.post(
            "/v1/github/token",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] == "github_access_token"
        assert "expires_at" in data

    @pytest.mark.asyncio
    async def test_get_github_token_with_force_refresh(
        self,
        test_client: TestClient,
        jwt_secret: str,
        session_store: InMemorySessionStore,
        user_repository: InMemoryUserRepository,
        mock_github_token_service: AsyncMock,
    ) -> None:
        """Test GitHub token retrieval with force_refresh."""
        # Create user and session
        user = await user_repository.upsert_by_github_id(12345, "testuser")
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        session = Session(user_id=user.id, expires_at=expires_at)
        await session_store.create(session)

        # Mint token
        token = mint_af_jwt(
            secret=jwt_secret,
            user_id=user.id,
            session_id=session.session_id,
            expires_at=expires_at,
        )

        # Setup mock
        mock_github_token_service.get_access_token.return_value = GitHubAccessTokenResult(
            access_token="fresh_github_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
        )

        response = test_client.post(
            "/v1/github/token",
            headers={"Authorization": f"Bearer {token}"},
            json={"force_refresh": True},
        )

        assert response.status_code == 200
        mock_github_token_service.get_access_token.assert_called_once()
        call_args = mock_github_token_service.get_access_token.call_args
        assert call_args.kwargs["force_refresh"] is True

    def test_get_github_token_without_auth(self, test_client: TestClient) -> None:
        """Test GitHub token retrieval without authentication."""
        response = test_client.post("/v1/github/token")

        assert response.status_code == 401
        data = response.json()
        assert data["detail"]["error"] == "missing_authorization"

    @pytest.mark.asyncio
    async def test_get_github_token_missing_refresh_token(
        self,
        test_client: TestClient,
        jwt_secret: str,
        session_store: InMemorySessionStore,
        user_repository: InMemoryUserRepository,
        mock_github_token_service: AsyncMock,
    ) -> None:
        """Test GitHub token retrieval when refresh token is missing."""
        # Create user and session
        user = await user_repository.upsert_by_github_id(12345, "testuser")
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        session = Session(user_id=user.id, expires_at=expires_at)
        await session_store.create(session)

        # Mint token
        token = mint_af_jwt(
            secret=jwt_secret,
            user_id=user.id,
            session_id=session.session_id,
            expires_at=expires_at,
        )

        # Setup mock to raise error
        mock_github_token_service.get_access_token.side_effect = RefreshTokenMissingError(
            "No refresh token"
        )

        response = test_client.post(
            "/v1/github/token",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 404
        data = response.json()
        assert data["detail"]["error"] == "github_not_linked"

    @pytest.mark.asyncio
    async def test_get_github_token_refresh_failure(
        self,
        test_client: TestClient,
        jwt_secret: str,
        session_store: InMemorySessionStore,
        user_repository: InMemoryUserRepository,
        mock_github_token_service: AsyncMock,
    ) -> None:
        """Test GitHub token retrieval when refresh fails."""
        # Create user and session
        user = await user_repository.upsert_by_github_id(12345, "testuser")
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        session = Session(user_id=user.id, expires_at=expires_at)
        await session_store.create(session)

        # Mint token
        token = mint_af_jwt(
            secret=jwt_secret,
            user_id=user.id,
            session_id=session.session_id,
            expires_at=expires_at,
        )

        # Setup mock to raise error
        mock_github_token_service.get_access_token.side_effect = TokenRefreshError(
            "Refresh failed"
        )

        response = test_client.post(
            "/v1/github/token",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 502
        data = response.json()
        assert data["detail"]["error"] == "github_error"


class TestAppIntegration:
    """Integration tests for the full application with GitHub token routes."""

    def test_github_token_route_accessible(self, valid_settings: Settings) -> None:
        """Test that GitHub token route is accessible in the full app."""
        from af_identity_service.app import create_app

        reset_dependencies()
        app = create_app(valid_settings)
        client = TestClient(app)

        # Should return 401 without auth, not 404
        response = client.post("/v1/github/token")

        assert response.status_code == 401
        reset_dependencies()

    def test_openapi_includes_github_token_route(self, valid_settings: Settings) -> None:
        """Test that OpenAPI schema includes GitHub token route."""
        from af_identity_service.app import create_app

        reset_dependencies()
        app = create_app(valid_settings)
        client = TestClient(app)

        response = client.get("/openapi.json")
        data = response.json()

        assert "/v1/github/token" in data["paths"]
        reset_dependencies()

    def test_full_oauth_then_github_token_flow(self, valid_settings: Settings) -> None:
        """Test complete flow: OAuth login then GitHub token retrieval."""
        from af_identity_service.app import create_app

        reset_dependencies()
        app = create_app(valid_settings)
        client = TestClient(app)

        # Start OAuth
        start_response = client.post(
            "/v1/auth/github/start",
            json={"redirect_uri": "https://example.com/callback"},
        )
        assert start_response.status_code == 200
        state = start_response.json()["state"]

        # Complete callback
        callback_response = client.post(
            "/v1/auth/github/callback",
            json={"code": "test-code", "state": state},
        )
        assert callback_response.status_code == 200
        af_token = callback_response.json()["af_token"]

        # Get GitHub token
        token_response = client.post(
            "/v1/github/token",
            headers={"Authorization": f"Bearer {af_token}"},
        )
        assert token_response.status_code == 200
        data = token_response.json()
        assert "access_token" in data
        assert "expires_at" in data

        reset_dependencies()


class TestMeRoute:
    """Tests for GET /v1/me endpoint."""

    def test_me_route_accessible(self, valid_settings: Settings) -> None:
        """Test that /v1/me route is accessible in the full app."""
        from af_identity_service.app import create_app

        reset_dependencies()
        app = create_app(valid_settings)
        client = TestClient(app)

        # Should return 401 without auth, not 404
        response = client.get("/v1/me")

        assert response.status_code == 401
        reset_dependencies()

    def test_me_returns_user_profile(self, valid_settings: Settings) -> None:
        """Test that /v1/me returns user profile after OAuth."""
        from af_identity_service.app import create_app

        reset_dependencies()
        app = create_app(valid_settings)
        client = TestClient(app)

        # Start and complete OAuth
        start_response = client.post(
            "/v1/auth/github/start",
            json={"redirect_uri": "https://example.com/callback"},
        )
        state = start_response.json()["state"]

        callback_response = client.post(
            "/v1/auth/github/callback",
            json={"code": "test-code", "state": state},
        )
        af_token = callback_response.json()["af_token"]

        # Get user profile
        me_response = client.get(
            "/v1/me",
            headers={"Authorization": f"Bearer {af_token}"},
        )

        assert me_response.status_code == 200
        data = me_response.json()
        assert "id" in data
        assert "github_login" in data
        assert "github_user_id" in data
        assert "linked_providers" in data
        assert "github" in data["linked_providers"]

        reset_dependencies()

    def test_openapi_includes_me_route(self, valid_settings: Settings) -> None:
        """Test that OpenAPI schema includes /v1/me route."""
        from af_identity_service.app import create_app

        reset_dependencies()
        app = create_app(valid_settings)
        client = TestClient(app)

        response = client.get("/openapi.json")
        data = response.json()

        assert "/v1/me" in data["paths"]
        reset_dependencies()


class TestAdminRoute:
    """Tests for admin endpoints."""

    def test_admin_route_returns_404_when_disabled(self, valid_settings: Settings) -> None:
        """Test that admin route returns 404 when ADMIN_TOOLS_ENABLED is False."""
        from af_identity_service.app import create_app

        # Ensure admin_tools_enabled is False (default)
        assert valid_settings.admin_tools_enabled is False

        reset_dependencies()
        app = create_app(valid_settings)
        client = TestClient(app)

        # Start and complete OAuth to get a token
        start_response = client.post(
            "/v1/auth/github/start",
            json={"redirect_uri": "https://example.com/callback"},
        )
        state = start_response.json()["state"]

        callback_response = client.post(
            "/v1/auth/github/callback",
            json={"code": "test-code", "state": state},
        )
        af_token = callback_response.json()["af_token"]
        user_id = callback_response.json()["user"]["id"]

        # Try to access admin endpoint
        response = client.get(
            f"/v1/admin/users/{user_id}/sessions",
            headers={"Authorization": f"Bearer {af_token}"},
        )

        # Should return 404 when admin tools are disabled
        assert response.status_code == 404

        reset_dependencies()

    def test_admin_route_works_when_enabled(self) -> None:
        """Test that admin route works when ADMIN_TOOLS_ENABLED is True."""
        from af_identity_service.app import create_app

        # Create settings with admin tools enabled
        settings_with_admin = Settings(
            identity_jwt_secret="a" * 32,
            github_client_id="test-client-id",
            github_client_secret="test-client-secret",
            log_format="console",
            admin_tools_enabled=True,
        )

        reset_dependencies()
        app = create_app(settings_with_admin)
        client = TestClient(app)

        # Start and complete OAuth to get a token
        start_response = client.post(
            "/v1/auth/github/start",
            json={"redirect_uri": "https://example.com/callback"},
        )
        state = start_response.json()["state"]

        callback_response = client.post(
            "/v1/auth/github/callback",
            json={"code": "test-code", "state": state},
        )
        af_token = callback_response.json()["af_token"]
        user_id = callback_response.json()["user"]["id"]

        # Access admin endpoint
        response = client.get(
            f"/v1/admin/users/{user_id}/sessions",
            headers={"Authorization": f"Bearer {af_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == user_id
        assert "sessions" in data
        assert len(data["sessions"]) >= 1  # At least the current session

        reset_dependencies()

    def test_admin_route_without_auth(self, valid_settings: Settings) -> None:
        """Test that admin route requires authentication."""
        from af_identity_service.app import create_app

        # Create settings with admin tools enabled
        settings_with_admin = Settings(
            identity_jwt_secret="a" * 32,
            github_client_id="test-client-id",
            github_client_secret="test-client-secret",
            log_format="console",
            admin_tools_enabled=True,
        )

        reset_dependencies()
        app = create_app(settings_with_admin)
        client = TestClient(app)

        response = client.get("/v1/admin/users/some-user-id/sessions")

        assert response.status_code == 401

        reset_dependencies()

    def test_openapi_includes_admin_routes(self, valid_settings: Settings) -> None:
        """Test that OpenAPI schema includes admin routes."""
        from af_identity_service.app import create_app

        reset_dependencies()
        app = create_app(valid_settings)
        client = TestClient(app)

        response = client.get("/openapi.json")
        data = response.json()

        # Admin route should be in OpenAPI even when disabled
        assert "/v1/admin/users/{user_id}/sessions" in data["paths"]
        reset_dependencies()
