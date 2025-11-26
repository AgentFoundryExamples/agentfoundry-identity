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
"""Tests for token introspection and session revocation routes."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from af_identity_service.config import Settings
from af_identity_service.dependencies import reset_dependencies
from af_identity_service.models.session import Session
from af_identity_service.routes.session import create_session_router
from af_identity_service.routes.token import create_token_router
from af_identity_service.security.jwt import (
    JWTClaims,
    JWTExpiredError,
    JWTValidationError,
    mint_af_jwt,
    validate_af_jwt,
)
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
def jwt_secret() -> str:
    """Return a valid JWT secret."""
    return "a" * 32


class TestJWTValidation:
    """Tests for JWT validation functionality."""

    def test_validate_valid_token(self, jwt_secret: str) -> None:
        """Test validating a valid JWT token."""
        user_id = uuid4()
        session_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        token = mint_af_jwt(
            secret=jwt_secret,
            user_id=user_id,
            session_id=session_id,
            expires_at=expires_at,
        )

        claims = validate_af_jwt(token, jwt_secret)

        assert claims.user_id == user_id
        assert claims.session_id == session_id

    def test_validate_expired_token_raises_jwt_expired_error(
        self, jwt_secret: str
    ) -> None:
        """Test that expired tokens raise JWTExpiredError."""
        user_id = uuid4()
        session_id = uuid4()
        expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        issued_at = datetime.now(timezone.utc) - timedelta(hours=2)

        token = mint_af_jwt(
            secret=jwt_secret,
            user_id=user_id,
            session_id=session_id,
            expires_at=expires_at,
            issued_at=issued_at,
        )

        with pytest.raises(JWTExpiredError):
            validate_af_jwt(token, jwt_secret)

    def test_validate_invalid_signature_raises_error(self, jwt_secret: str) -> None:
        """Test that invalid signature raises JWTValidationError."""
        user_id = uuid4()
        session_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        token = mint_af_jwt(
            secret=jwt_secret,
            user_id=user_id,
            session_id=session_id,
            expires_at=expires_at,
        )

        # Modify the signature to make it invalid
        parts = token.split(".")
        parts[2] = "invalid_signature"
        invalid_token = ".".join(parts)

        with pytest.raises(JWTValidationError):
            validate_af_jwt(invalid_token, jwt_secret)

    def test_validate_wrong_secret_raises_error(self, jwt_secret: str) -> None:
        """Test that wrong secret raises JWTValidationError."""
        user_id = uuid4()
        session_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        token = mint_af_jwt(
            secret=jwt_secret,
            user_id=user_id,
            session_id=session_id,
            expires_at=expires_at,
        )

        wrong_secret = "b" * 32

        with pytest.raises(JWTValidationError):
            validate_af_jwt(token, wrong_secret)

    def test_validate_malformed_token_raises_error(self, jwt_secret: str) -> None:
        """Test that malformed tokens raise JWTValidationError."""
        with pytest.raises(JWTValidationError):
            validate_af_jwt("not.a.valid.token.at.all", jwt_secret)

        with pytest.raises(JWTValidationError):
            validate_af_jwt("not_enough_parts", jwt_secret)

    def test_validate_returns_jwt_claims_object(self, jwt_secret: str) -> None:
        """Test that validation returns a JWTClaims object."""
        user_id = uuid4()
        session_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        issued_at = datetime.now(timezone.utc)

        token = mint_af_jwt(
            secret=jwt_secret,
            user_id=user_id,
            session_id=session_id,
            expires_at=expires_at,
            issued_at=issued_at,
        )

        claims = validate_af_jwt(token, jwt_secret)

        assert isinstance(claims, JWTClaims)
        assert claims.user_id == user_id
        assert claims.session_id == session_id
        assert claims.exp == int(expires_at.timestamp())
        assert claims.iat == int(issued_at.timestamp())


class TestTokenIntrospectionRoute:
    """Tests for POST /v1/auth/token/introspect endpoint."""

    @pytest.fixture
    def test_client(
        self,
        jwt_secret: str,
        session_store: InMemorySessionStore,
        user_repository: InMemoryUserRepository,
    ) -> TestClient:
        """Create a test client with token routes."""
        app = FastAPI()
        router = create_token_router(
            jwt_secret=jwt_secret,
            session_store=session_store,
            user_repository=user_repository,
        )
        app.include_router(router)
        return TestClient(app)

    @pytest.mark.asyncio
    async def test_introspect_valid_token(
        self,
        test_client: TestClient,
        jwt_secret: str,
        session_store: InMemorySessionStore,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test introspecting a valid token returns user info."""
        # Create user
        user = await user_repository.upsert_by_github_id(12345, "testuser")

        # Create session
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

        response = test_client.post(
            "/v1/auth/token/introspect",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == str(user.id)
        assert data["session_id"] == str(session.session_id)
        assert data["github_login"] == "testuser"
        assert data["github_user_id"] == 12345

    def test_introspect_missing_authorization(self, test_client: TestClient) -> None:
        """Test introspection without Authorization header returns 401."""
        response = test_client.post("/v1/auth/token/introspect")

        assert response.status_code == 401
        data = response.json()
        assert data["detail"]["error"] == "missing_authorization"

    def test_introspect_malformed_authorization(self, test_client: TestClient) -> None:
        """Test introspection with malformed Authorization header returns 401."""
        response = test_client.post(
            "/v1/auth/token/introspect",
            headers={"Authorization": "NotBearer token"},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["detail"]["error"] == "missing_authorization"

    @pytest.mark.asyncio
    async def test_introspect_expired_token(
        self,
        test_client: TestClient,
        jwt_secret: str,
        session_store: InMemorySessionStore,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test introspection with expired token returns 401."""
        # Create user
        user = await user_repository.upsert_by_github_id(12345, "testuser")

        # Create session (still valid)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        session = Session(user_id=user.id, expires_at=expires_at)
        await session_store.create(session)

        # Mint expired token
        expired_at = datetime.now(timezone.utc) - timedelta(hours=1)
        issued_at = datetime.now(timezone.utc) - timedelta(hours=2)
        token = mint_af_jwt(
            secret=jwt_secret,
            user_id=user.id,
            session_id=session.session_id,
            expires_at=expired_at,
            issued_at=issued_at,
        )

        response = test_client.post(
            "/v1/auth/token/introspect",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["detail"]["error"] == "invalid_token"

    @pytest.mark.asyncio
    async def test_introspect_revoked_session(
        self,
        test_client: TestClient,
        jwt_secret: str,
        session_store: InMemorySessionStore,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test introspection with revoked session returns 401."""
        # Create user
        user = await user_repository.upsert_by_github_id(12345, "testuser")

        # Create and revoke session
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        session = Session(user_id=user.id, expires_at=expires_at)
        await session_store.create(session)
        await session_store.revoke(session.session_id)

        # Mint token
        token = mint_af_jwt(
            secret=jwt_secret,
            user_id=user.id,
            session_id=session.session_id,
            expires_at=expires_at,
        )

        response = test_client.post(
            "/v1/auth/token/introspect",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["detail"]["error"] == "invalid_token"

    @pytest.mark.asyncio
    async def test_introspect_nonexistent_session(
        self,
        test_client: TestClient,
        jwt_secret: str,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test introspection with nonexistent session returns 401."""
        # Create user but no session
        user = await user_repository.upsert_by_github_id(12345, "testuser")
        fake_session_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

        # Mint token with nonexistent session
        token = mint_af_jwt(
            secret=jwt_secret,
            user_id=user.id,
            session_id=fake_session_id,
            expires_at=expires_at,
        )

        response = test_client.post(
            "/v1/auth/token/introspect",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["detail"]["error"] == "session_not_found"

    def test_introspect_invalid_token_signature(
        self,
        test_client: TestClient,
        jwt_secret: str,
    ) -> None:
        """Test introspection with invalid signature returns 401."""
        # Create a token and tamper with the signature
        user_id = uuid4()
        session_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        token = mint_af_jwt(
            secret=jwt_secret,
            user_id=user_id,
            session_id=session_id,
            expires_at=expires_at,
        )

        # Tamper with signature
        parts = token.split(".")
        parts[2] = "tampered_signature"
        tampered_token = ".".join(parts)

        response = test_client.post(
            "/v1/auth/token/introspect",
            headers={"Authorization": f"Bearer {tampered_token}"},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["detail"]["error"] == "invalid_token"


class TestSessionRevocationRoute:
    """Tests for POST /v1/auth/session/revoke endpoint."""

    @pytest.fixture
    def test_client(
        self,
        jwt_secret: str,
        session_store: InMemorySessionStore,
        user_repository: InMemoryUserRepository,
    ) -> TestClient:
        """Create a test client with session routes."""
        app = FastAPI()
        router = create_session_router(
            jwt_secret=jwt_secret,
            session_store=session_store,
            user_repository=user_repository,
        )
        app.include_router(router)
        return TestClient(app)

    @pytest.mark.asyncio
    async def test_revoke_current_session(
        self,
        test_client: TestClient,
        jwt_secret: str,
        session_store: InMemorySessionStore,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test revoking the current session."""
        # Create user
        user = await user_repository.upsert_by_github_id(12345, "testuser")

        # Create session
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

        response = test_client.post(
            "/v1/auth/session/revoke",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "current"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["session_id"] == str(session.session_id)

        # Verify session is revoked
        revoked_session = await session_store.get(session.session_id)
        assert revoked_session is not None
        assert revoked_session.is_revoked() is True

    @pytest.mark.asyncio
    async def test_revoke_specific_session_by_id(
        self,
        test_client: TestClient,
        jwt_secret: str,
        session_store: InMemorySessionStore,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test revoking a specific session by UUID."""
        # Create user
        user = await user_repository.upsert_by_github_id(12345, "testuser")

        # Create two sessions
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        session1 = Session(user_id=user.id, expires_at=expires_at)
        session2 = Session(user_id=user.id, expires_at=expires_at)
        await session_store.create(session1)
        await session_store.create(session2)

        # Mint token with session1
        token = mint_af_jwt(
            secret=jwt_secret,
            user_id=user.id,
            session_id=session1.session_id,
            expires_at=expires_at,
        )

        # Revoke session2 using session1's auth
        response = test_client.post(
            "/v1/auth/session/revoke",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": str(session2.session_id)},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["session_id"] == str(session2.session_id)

        # Verify session2 is revoked
        revoked_session = await session_store.get(session2.session_id)
        assert revoked_session is not None
        assert revoked_session.is_revoked() is True

        # Verify session1 is still active
        active_session = await session_store.get(session1.session_id)
        assert active_session is not None
        assert active_session.is_revoked() is False

    @pytest.mark.asyncio
    async def test_revoke_already_revoked_session_is_idempotent(
        self,
        test_client: TestClient,
        jwt_secret: str,
        session_store: InMemorySessionStore,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test that revoking an already revoked session is idempotent."""
        # Create user
        user = await user_repository.upsert_by_github_id(12345, "testuser")

        # Create sessions (one to authenticate, one to revoke)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        auth_session = Session(user_id=user.id, expires_at=expires_at)
        target_session = Session(user_id=user.id, expires_at=expires_at)
        await session_store.create(auth_session)
        await session_store.create(target_session)

        # Mint token with auth_session
        token = mint_af_jwt(
            secret=jwt_secret,
            user_id=user.id,
            session_id=auth_session.session_id,
            expires_at=expires_at,
        )

        # First revocation
        response1 = test_client.post(
            "/v1/auth/session/revoke",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": str(target_session.session_id)},
        )
        assert response1.status_code == 200

        # Second revocation (should still succeed)
        response2 = test_client.post(
            "/v1/auth/session/revoke",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": str(target_session.session_id)},
        )
        assert response2.status_code == 200
        data = response2.json()
        assert data["status"] == "ok"

    def test_revoke_missing_authorization(self, test_client: TestClient) -> None:
        """Test revocation without Authorization header returns 401."""
        response = test_client.post(
            "/v1/auth/session/revoke",
            json={"session_id": "current"},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["detail"]["error"] == "missing_authorization"

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_session_returns_404(
        self,
        test_client: TestClient,
        jwt_secret: str,
        session_store: InMemorySessionStore,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test revoking a nonexistent session returns 404."""
        # Create user
        user = await user_repository.upsert_by_github_id(12345, "testuser")

        # Create session
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

        # Try to revoke a nonexistent session
        nonexistent_id = uuid4()
        response = test_client.post(
            "/v1/auth/session/revoke",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": str(nonexistent_id)},
        )

        assert response.status_code == 404
        data = response.json()
        assert data["detail"]["error"] == "session_not_found"

    @pytest.mark.asyncio
    async def test_revoke_invalid_session_id_format_returns_400(
        self,
        test_client: TestClient,
        jwt_secret: str,
        session_store: InMemorySessionStore,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test revoking with invalid session ID format returns 400."""
        # Create user
        user = await user_repository.upsert_by_github_id(12345, "testuser")

        # Create session
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

        response = test_client.post(
            "/v1/auth/session/revoke",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "not-a-valid-uuid"},
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["error"] == "invalid_session_id"

    @pytest.mark.asyncio
    async def test_revoke_with_expired_token_returns_401(
        self,
        test_client: TestClient,
        jwt_secret: str,
        session_store: InMemorySessionStore,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test revocation with expired token returns 401."""
        # Create user
        user = await user_repository.upsert_by_github_id(12345, "testuser")

        # Create session (still valid)
        session_expires = datetime.now(timezone.utc) + timedelta(hours=24)
        session = Session(user_id=user.id, expires_at=session_expires)
        await session_store.create(session)

        # Mint expired token
        token_expires = datetime.now(timezone.utc) - timedelta(hours=1)
        token_issued = datetime.now(timezone.utc) - timedelta(hours=2)
        token = mint_af_jwt(
            secret=jwt_secret,
            user_id=user.id,
            session_id=session.session_id,
            expires_at=token_expires,
            issued_at=token_issued,
        )

        response = test_client.post(
            "/v1/auth/session/revoke",
            headers={"Authorization": f"Bearer {token}"},
            json={"session_id": "current"},
        )

        assert response.status_code == 401
        data = response.json()
        assert data["detail"]["error"] == "invalid_token"


class TestAppIntegrationWithNewRoutes:
    """Integration tests for the full application with new routes."""

    def test_token_introspect_route_accessible(
        self, valid_settings: Settings
    ) -> None:
        """Test that token introspect route is accessible in the full app."""
        from af_identity_service.app import create_app

        reset_dependencies()
        app = create_app(valid_settings)
        client = TestClient(app)

        # Should return 401 without auth, not 404
        response = client.post("/v1/auth/token/introspect")

        assert response.status_code == 401
        reset_dependencies()

    def test_session_revoke_route_accessible(self, valid_settings: Settings) -> None:
        """Test that session revoke route is accessible in the full app."""
        from af_identity_service.app import create_app

        reset_dependencies()
        app = create_app(valid_settings)
        client = TestClient(app)

        # Should return 401 without auth, not 404
        response = client.post(
            "/v1/auth/session/revoke",
            json={"session_id": "current"},
        )

        assert response.status_code == 401
        reset_dependencies()

    def test_openapi_includes_new_routes(self, valid_settings: Settings) -> None:
        """Test that OpenAPI schema includes new routes."""
        from af_identity_service.app import create_app

        reset_dependencies()
        app = create_app(valid_settings)
        client = TestClient(app)

        response = client.get("/openapi.json")
        data = response.json()

        # Should have new routes
        assert "/v1/auth/token/introspect" in data["paths"]
        assert "/v1/auth/session/revoke" in data["paths"]
        reset_dependencies()

    def test_full_oauth_then_introspect_flow(self, valid_settings: Settings) -> None:
        """Test complete flow: OAuth login then token introspection."""
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

        # Complete callback (using stub driver)
        callback_response = client.post(
            "/v1/auth/github/callback",
            json={"code": "test-code", "state": state},
        )
        assert callback_response.status_code == 200
        af_token = callback_response.json()["af_token"]

        # Introspect token
        introspect_response = client.post(
            "/v1/auth/token/introspect",
            headers={"Authorization": f"Bearer {af_token}"},
        )
        assert introspect_response.status_code == 200
        data = introspect_response.json()
        assert "user_id" in data
        assert "session_id" in data

        reset_dependencies()

    def test_full_oauth_then_revoke_flow(self, valid_settings: Settings) -> None:
        """Test complete flow: OAuth login then session revocation."""
        from af_identity_service.app import create_app

        reset_dependencies()
        app = create_app(valid_settings)
        client = TestClient(app)

        # Start OAuth
        start_response = client.post(
            "/v1/auth/github/start",
            json={"redirect_uri": "https://example.com/callback"},
        )
        state = start_response.json()["state"]

        # Complete callback
        callback_response = client.post(
            "/v1/auth/github/callback",
            json={"code": "test-code", "state": state},
        )
        af_token = callback_response.json()["af_token"]

        # Revoke current session
        revoke_response = client.post(
            "/v1/auth/session/revoke",
            headers={"Authorization": f"Bearer {af_token}"},
            json={"session_id": "current"},
        )
        assert revoke_response.status_code == 200
        data = revoke_response.json()
        assert data["status"] == "ok"

        # Token should no longer work for introspection
        introspect_response = client.post(
            "/v1/auth/token/introspect",
            headers={"Authorization": f"Bearer {af_token}"},
        )
        assert introspect_response.status_code == 401

        reset_dependencies()
