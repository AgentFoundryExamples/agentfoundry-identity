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
"""Tests for GitHub OAuth routes and OAuth service."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from af_identity_service.config import Settings
from af_identity_service.dependencies import reset_dependencies
from af_identity_service.github.driver import (
    GitHubOAuthDriver,
    GitHubOAuthDriverError,
    StubGitHubOAuthDriver,
)
from af_identity_service.models.github import GitHubIdentity, GitHubOAuthResult
from af_identity_service.routes.auth_github import create_auth_github_router
from af_identity_service.security.jwt import JWTMintError, mint_af_jwt
from af_identity_service.services.oauth import (
    GitHubDriverError,
    InMemoryStateStore,
    InvalidStateError,
    OAuthService,
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
def stub_github_driver() -> StubGitHubOAuthDriver:
    """Create a stub GitHub driver."""
    return StubGitHubOAuthDriver(client_id="test-client-id")


@pytest.fixture
def user_repository() -> InMemoryUserRepository:
    """Create an in-memory user repository."""
    return InMemoryUserRepository()


@pytest.fixture
def session_store() -> InMemorySessionStore:
    """Create an in-memory session store."""
    return InMemorySessionStore()


@pytest.fixture
def token_store() -> InMemoryGitHubTokenStore:
    """Create an in-memory token store."""
    return InMemoryGitHubTokenStore()


@pytest.fixture
def state_store() -> InMemoryStateStore:
    """Create an in-memory state store."""
    return InMemoryStateStore()


@pytest.fixture
def oauth_service(
    stub_github_driver: StubGitHubOAuthDriver,
    user_repository: InMemoryUserRepository,
    session_store: InMemorySessionStore,
    token_store: InMemoryGitHubTokenStore,
    state_store: InMemoryStateStore,
    valid_settings: Settings,
) -> OAuthService:
    """Create an OAuth service with test dependencies."""
    return OAuthService(
        github_driver=stub_github_driver,
        user_repository=user_repository,
        session_store=session_store,
        token_store=token_store,
        state_store=state_store,
        client_id=valid_settings.github_client_id,
        scopes=valid_settings.oauth_scopes_list,
        jwt_secret=valid_settings.identity_jwt_secret,
        jwt_expiry_seconds=valid_settings.jwt_expiry_seconds,
        session_expiry_seconds=valid_settings.session_expiry_seconds,
    )


@pytest.fixture
def test_client(oauth_service: OAuthService) -> TestClient:
    """Create a test client with OAuth routes."""
    app = FastAPI()
    router = create_auth_github_router(oauth_service)
    app.include_router(router)
    return TestClient(app)


class TestMintAfJwt:
    """Tests for JWT minting function."""

    def test_mint_jwt_creates_valid_token(self) -> None:
        """Test that minting creates a valid JWT."""
        user_id = uuid4()
        session_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        token = mint_af_jwt(
            secret="a" * 32,
            user_id=user_id,
            session_id=session_id,
            expires_at=expires_at,
        )

        # JWT should have three parts
        parts = token.split(".")
        assert len(parts) == 3

    def test_mint_jwt_requires_minimum_secret_length(self) -> None:
        """Test that minting fails with short secret."""
        with pytest.raises(JWTMintError):
            mint_af_jwt(
                secret="short",
                user_id=uuid4(),
                session_id=uuid4(),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )

    def test_mint_jwt_handles_naive_datetime(self) -> None:
        """Test that minting handles naive datetime by assuming UTC."""
        user_id = uuid4()
        session_id = uuid4()
        naive_expires = datetime.now() + timedelta(hours=1)

        # Should not raise
        token = mint_af_jwt(
            secret="a" * 32,
            user_id=user_id,
            session_id=session_id,
            expires_at=naive_expires,
        )

        assert len(token.split(".")) == 3


class TestInMemoryStateStore:
    """Tests for InMemoryStateStore."""

    @pytest.mark.asyncio
    async def test_store_and_validate_state(self, state_store: InMemoryStateStore) -> None:
        """Test storing and validating a state token."""
        state = "test-state-token"
        redirect_uri = "https://example.com/callback"

        await state_store.store(state, redirect_uri)
        result = await state_store.validate_and_consume(state)

        assert result == redirect_uri

    @pytest.mark.asyncio
    async def test_validate_consumes_state(self, state_store: InMemoryStateStore) -> None:
        """Test that validating consumes the state token."""
        state = "test-state-token"
        redirect_uri = "https://example.com/callback"

        await state_store.store(state, redirect_uri)
        await state_store.validate_and_consume(state)

        # Second validation should fail
        result = await state_store.validate_and_consume(state)
        assert result is None

    @pytest.mark.asyncio
    async def test_validate_invalid_state(self, state_store: InMemoryStateStore) -> None:
        """Test validating an invalid state token."""
        result = await state_store.validate_and_consume("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_validate_expired_state(self, state_store: InMemoryStateStore) -> None:
        """Test validating an expired state token."""
        state = "test-state-token"
        redirect_uri = "https://example.com/callback"

        # Store with very short TTL
        await state_store.store(state, redirect_uri, ttl_seconds=0)

        # Should be expired immediately
        result = await state_store.validate_and_consume(state)
        assert result is None


class TestOAuthServiceStart:
    """Tests for OAuth service start flow."""

    @pytest.mark.asyncio
    async def test_start_oauth_returns_authorization_url(
        self, oauth_service: OAuthService
    ) -> None:
        """Test that starting OAuth returns an authorization URL."""
        result = await oauth_service.start_oauth("https://example.com/callback")

        assert "https://github.com/login/oauth/authorize" in result.authorization_url
        assert "client_id=" in result.authorization_url
        assert "state=" in result.authorization_url

    @pytest.mark.asyncio
    async def test_start_oauth_returns_state(self, oauth_service: OAuthService) -> None:
        """Test that starting OAuth returns a state token."""
        result = await oauth_service.start_oauth("https://example.com/callback")

        assert result.state is not None
        assert len(result.state) > 0

    @pytest.mark.asyncio
    async def test_start_oauth_includes_redirect_uri(
        self, oauth_service: OAuthService
    ) -> None:
        """Test that authorization URL includes redirect URI."""
        redirect_uri = "https://example.com/callback"
        result = await oauth_service.start_oauth(redirect_uri)

        assert "redirect_uri=" in result.authorization_url


class TestOAuthServiceCallback:
    """Tests for OAuth service callback flow."""

    @pytest.mark.asyncio
    async def test_callback_success(self, oauth_service: OAuthService) -> None:
        """Test successful OAuth callback."""
        # Start OAuth to get valid state
        start_result = await oauth_service.start_oauth("https://example.com/callback")

        # Complete callback
        result = await oauth_service.handle_callback(
            code="test-code",
            state=start_result.state,
        )

        assert result.af_token is not None
        assert result.user is not None
        assert result.user.github_user_id is not None
        assert result.session is not None

    @pytest.mark.asyncio
    async def test_callback_invalid_state(self, oauth_service: OAuthService) -> None:
        """Test callback with invalid state raises error."""
        with pytest.raises(InvalidStateError):
            await oauth_service.handle_callback(
                code="test-code",
                state="invalid-state",
            )

    @pytest.mark.asyncio
    async def test_callback_creates_session(
        self,
        oauth_service: OAuthService,
        session_store: InMemorySessionStore,
    ) -> None:
        """Test that callback creates a session."""
        start_result = await oauth_service.start_oauth("https://example.com/callback")
        result = await oauth_service.handle_callback(
            code="test-code",
            state=start_result.state,
        )

        # Session should be retrievable
        session = await session_store.get(result.session.session_id)
        assert session is not None
        assert session.user_id == result.user.id

    @pytest.mark.asyncio
    async def test_callback_stores_tokens(
        self,
        oauth_service: OAuthService,
        token_store: InMemoryGitHubTokenStore,
    ) -> None:
        """Test that callback stores tokens."""
        start_result = await oauth_service.start_oauth("https://example.com/callback")
        result = await oauth_service.handle_callback(
            code="test-code",
            state=start_result.state,
        )

        # Token should be retrievable
        access_token = await token_store.get_access_token(result.user.id)
        assert access_token is not None

    @pytest.mark.asyncio
    async def test_callback_upserts_existing_user(
        self,
        oauth_service: OAuthService,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test that callback upserts existing user."""
        # First callback
        start1 = await oauth_service.start_oauth("https://example.com/callback")
        result1 = await oauth_service.handle_callback(
            code="test-code",
            state=start1.state,
        )

        # Second callback with same code (same user from stub)
        start2 = await oauth_service.start_oauth("https://example.com/callback")
        result2 = await oauth_service.handle_callback(
            code="test-code",
            state=start2.state,
        )

        # Should be same user (upserted, not duplicated)
        assert result1.user.id == result2.user.id


class TestOAuthServiceDriverErrors:
    """Tests for OAuth service handling of driver errors."""

    @pytest.mark.asyncio
    async def test_callback_driver_exchange_error(
        self,
        user_repository: InMemoryUserRepository,
        session_store: InMemorySessionStore,
        token_store: InMemoryGitHubTokenStore,
        state_store: InMemoryStateStore,
        valid_settings: Settings,
    ) -> None:
        """Test callback with driver exchange error."""
        # Create mock driver that fails
        mock_driver = AsyncMock(spec=GitHubOAuthDriver)
        mock_driver.exchange_code_for_tokens.side_effect = GitHubOAuthDriverError(
            "Token exchange failed"
        )

        service = OAuthService(
            github_driver=mock_driver,
            user_repository=user_repository,
            session_store=session_store,
            token_store=token_store,
            state_store=state_store,
            client_id=valid_settings.github_client_id,
            scopes=valid_settings.oauth_scopes_list,
            jwt_secret=valid_settings.identity_jwt_secret,
            jwt_expiry_seconds=valid_settings.jwt_expiry_seconds,
            session_expiry_seconds=valid_settings.session_expiry_seconds,
        )

        start_result = await service.start_oauth("https://example.com/callback")

        with pytest.raises(GitHubDriverError):
            await service.handle_callback(
                code="test-code",
                state=start_result.state,
            )

    @pytest.mark.asyncio
    async def test_callback_driver_profile_error(
        self,
        user_repository: InMemoryUserRepository,
        session_store: InMemorySessionStore,
        token_store: InMemoryGitHubTokenStore,
        state_store: InMemoryStateStore,
        valid_settings: Settings,
    ) -> None:
        """Test callback with driver profile error."""
        # Create mock driver that succeeds on exchange but fails on profile
        mock_driver = AsyncMock(spec=GitHubOAuthDriver)
        mock_driver.exchange_code_for_tokens.return_value = GitHubOAuthResult(
            access_token="test-token",
            access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
        )
        mock_driver.get_user_profile.side_effect = GitHubOAuthDriverError(
            "Profile fetch failed"
        )

        service = OAuthService(
            github_driver=mock_driver,
            user_repository=user_repository,
            session_store=session_store,
            token_store=token_store,
            state_store=state_store,
            client_id=valid_settings.github_client_id,
            scopes=valid_settings.oauth_scopes_list,
            jwt_secret=valid_settings.identity_jwt_secret,
            jwt_expiry_seconds=valid_settings.jwt_expiry_seconds,
            session_expiry_seconds=valid_settings.session_expiry_seconds,
        )

        start_result = await service.start_oauth("https://example.com/callback")

        with pytest.raises(GitHubDriverError):
            await service.handle_callback(
                code="test-code",
                state=start_result.state,
            )


class TestOAuthServiceRefreshTokenOptional:
    """Tests for OAuth service handling of optional refresh tokens."""

    @pytest.mark.asyncio
    async def test_callback_without_refresh_token(
        self,
        user_repository: InMemoryUserRepository,
        session_store: InMemorySessionStore,
        token_store: InMemoryGitHubTokenStore,
        state_store: InMemoryStateStore,
        valid_settings: Settings,
    ) -> None:
        """Test callback when GitHub returns no refresh token."""
        # Create mock driver that returns no refresh token
        mock_driver = AsyncMock(spec=GitHubOAuthDriver)
        mock_driver.exchange_code_for_tokens.return_value = GitHubOAuthResult(
            access_token="test-token",
            access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
            refresh_token=None,  # No refresh token
        )
        mock_driver.get_user_profile.return_value = GitHubIdentity(
            github_user_id=12345,
            login="testuser",
            avatar_url="https://example.com/avatar.png",
        )

        service = OAuthService(
            github_driver=mock_driver,
            user_repository=user_repository,
            session_store=session_store,
            token_store=token_store,
            state_store=state_store,
            client_id=valid_settings.github_client_id,
            scopes=valid_settings.oauth_scopes_list,
            jwt_secret=valid_settings.identity_jwt_secret,
            jwt_expiry_seconds=valid_settings.jwt_expiry_seconds,
            session_expiry_seconds=valid_settings.session_expiry_seconds,
        )

        start_result = await service.start_oauth("https://example.com/callback")
        result = await service.handle_callback(
            code="test-code",
            state=start_result.state,
        )

        # Should still succeed
        assert result.af_token is not None
        assert result.user is not None
        # But should indicate refresh token unavailable
        assert result.github_token_available is False


class TestAuthGitHubRoutes:
    """Tests for GitHub OAuth HTTP routes."""

    def test_start_returns_authorization_url(self, test_client: TestClient) -> None:
        """Test POST /v1/auth/github/start returns authorization URL."""
        response = test_client.post(
            "/v1/auth/github/start",
            json={"redirect_uri": "https://example.com/callback"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "authorization_url" in data
        assert "state" in data
        assert "https://github.com/login/oauth/authorize" in data["authorization_url"]

    def test_start_requires_redirect_uri(self, test_client: TestClient) -> None:
        """Test POST /v1/auth/github/start requires redirect_uri."""
        response = test_client.post("/v1/auth/github/start", json={})

        assert response.status_code == 422

    def test_callback_success(self, test_client: TestClient) -> None:
        """Test POST /v1/auth/github/callback success."""
        # First start OAuth to get valid state
        start_response = test_client.post(
            "/v1/auth/github/start",
            json={"redirect_uri": "https://example.com/callback"},
        )
        state = start_response.json()["state"]

        # Then complete callback
        response = test_client.post(
            "/v1/auth/github/callback",
            json={"code": "test-code", "state": state},
        )

        assert response.status_code == 200
        data = response.json()
        assert "af_token" in data
        assert "user" in data
        assert "id" in data["user"]
        assert "github_login" in data["user"]
        assert "github_user_id" in data["user"]

    def test_callback_invalid_state(self, test_client: TestClient) -> None:
        """Test POST /v1/auth/github/callback with invalid state."""
        response = test_client.post(
            "/v1/auth/github/callback",
            json={"code": "test-code", "state": "invalid-state"},
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["error"] == "invalid_state"

    def test_callback_requires_code(self, test_client: TestClient) -> None:
        """Test POST /v1/auth/github/callback requires code."""
        response = test_client.post(
            "/v1/auth/github/callback",
            json={"state": "some-state"},
        )

        assert response.status_code == 422

    def test_callback_requires_state(self, test_client: TestClient) -> None:
        """Test POST /v1/auth/github/callback requires state."""
        response = test_client.post(
            "/v1/auth/github/callback",
            json={"code": "test-code"},
        )

        assert response.status_code == 422

    def test_callback_does_not_expose_github_tokens(
        self, test_client: TestClient
    ) -> None:
        """Test that callback response does not contain GitHub tokens."""
        # Start OAuth
        start_response = test_client.post(
            "/v1/auth/github/start",
            json={"redirect_uri": "https://example.com/callback"},
        )
        state = start_response.json()["state"]

        # Complete callback
        response = test_client.post(
            "/v1/auth/github/callback",
            json={"code": "test-code", "state": state},
        )

        data = response.json()

        # Should not contain GitHub tokens
        assert "access_token" not in data
        assert "refresh_token" not in data
        assert "access_token" not in str(data)
        assert "refresh_token" not in str(data)
        assert "gho_" not in str(data)
        assert "ghr_" not in str(data)


class TestAuthGitHubRoutesDriverErrors:
    """Tests for GitHub OAuth routes handling driver errors."""

    def test_callback_driver_error_returns_502(
        self,
        user_repository: InMemoryUserRepository,
        session_store: InMemorySessionStore,
        token_store: InMemoryGitHubTokenStore,
        state_store: InMemoryStateStore,
        valid_settings: Settings,
    ) -> None:
        """Test that driver errors return 502."""
        # Create mock driver that fails
        mock_driver = AsyncMock(spec=GitHubOAuthDriver)
        mock_driver.exchange_code_for_tokens.side_effect = GitHubOAuthDriverError(
            "GitHub API error"
        )

        service = OAuthService(
            github_driver=mock_driver,
            user_repository=user_repository,
            session_store=session_store,
            token_store=token_store,
            state_store=state_store,
            client_id=valid_settings.github_client_id,
            scopes=valid_settings.oauth_scopes_list,
            jwt_secret=valid_settings.identity_jwt_secret,
            jwt_expiry_seconds=valid_settings.jwt_expiry_seconds,
            session_expiry_seconds=valid_settings.session_expiry_seconds,
        )

        app = FastAPI()
        router = create_auth_github_router(service)
        app.include_router(router)
        client = TestClient(app)

        # Start OAuth
        start_response = client.post(
            "/v1/auth/github/start",
            json={"redirect_uri": "https://example.com/callback"},
        )
        state = start_response.json()["state"]

        # Callback should return 502
        response = client.post(
            "/v1/auth/github/callback",
            json={"code": "test-code", "state": state},
        )

        assert response.status_code == 502
        data = response.json()
        assert data["detail"]["error"] == "github_error"


class TestAppIntegration:
    """Integration tests for the full application with OAuth routes."""

    def test_oauth_routes_accessible(self, valid_settings: Settings) -> None:
        """Test that OAuth routes are accessible in the full app."""
        from af_identity_service.app import create_app

        reset_dependencies()
        app = create_app(valid_settings)
        client = TestClient(app)

        # Should be able to call start
        response = client.post(
            "/v1/auth/github/start",
            json={"redirect_uri": "https://example.com/callback"},
        )

        assert response.status_code == 200
        reset_dependencies()

    def test_openapi_includes_auth_routes(self, valid_settings: Settings) -> None:
        """Test that OpenAPI schema includes auth routes."""
        from af_identity_service.app import create_app

        reset_dependencies()
        app = create_app(valid_settings)
        client = TestClient(app)

        response = client.get("/openapi.json")
        data = response.json()

        # Should have auth routes
        assert "/v1/auth/github/start" in data["paths"]
        assert "/v1/auth/github/callback" in data["paths"]
        reset_dependencies()
