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
"""Tests for identity stores."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from af_identity_service.models.github import GitHubOAuthResult
from af_identity_service.models.session import Session
from af_identity_service.stores.github_token_store import (
    InMemoryGitHubTokenStore,
    RefreshTokenNotFoundError,
)
from af_identity_service.stores.session_store import InMemorySessionStore
from af_identity_service.stores.user_store import InMemoryUserRepository


class TestInMemoryUserRepository:
    """Tests for InMemoryUserRepository."""

    @pytest.fixture
    def repo(self) -> InMemoryUserRepository:
        """Create a fresh user repository for each test."""
        return InMemoryUserRepository()

    @pytest.mark.asyncio
    async def test_get_by_id_not_found(self, repo: InMemoryUserRepository) -> None:
        """Test getting a user by ID that doesn't exist."""
        user_id = uuid4()
        result = await repo.get_by_id(user_id)

        assert result is None

    @pytest.mark.asyncio
    async def test_get_by_id_invalid_type(self, repo: InMemoryUserRepository) -> None:
        """Test that invalid UUID type raises ValueError."""
        with pytest.raises(ValueError):
            await repo.get_by_id("not-a-uuid")  # type: ignore

    @pytest.mark.asyncio
    async def test_get_by_github_id_not_found(
        self, repo: InMemoryUserRepository
    ) -> None:
        """Test getting a user by GitHub ID that doesn't exist."""
        result = await repo.get_by_github_id(12345)

        assert result is None

    @pytest.mark.asyncio
    async def test_upsert_creates_new_user(
        self, repo: InMemoryUserRepository
    ) -> None:
        """Test upserting creates a new user when not exists."""
        user = await repo.upsert_by_github_id(12345, "octocat")

        assert user.github_user_id == 12345
        assert user.github_login == "octocat"
        assert user.id is not None

    @pytest.mark.asyncio
    async def test_upsert_updates_existing_user(
        self, repo: InMemoryUserRepository
    ) -> None:
        """Test upserting updates an existing user."""
        # Create user
        user1 = await repo.upsert_by_github_id(12345, "octocat")
        original_id = user1.id

        # Update user
        user2 = await repo.upsert_by_github_id(12345, "new_login")

        assert user2.id == original_id
        assert user2.github_login == "new_login"
        assert user2.updated_at > user1.updated_at

    @pytest.mark.asyncio
    async def test_get_by_id_after_upsert(
        self, repo: InMemoryUserRepository
    ) -> None:
        """Test getting user by ID after upsert."""
        user = await repo.upsert_by_github_id(12345, "octocat")
        found = await repo.get_by_id(user.id)

        assert found is not None
        assert found.id == user.id
        assert found.github_user_id == 12345

    @pytest.mark.asyncio
    async def test_get_by_github_id_after_upsert(
        self, repo: InMemoryUserRepository
    ) -> None:
        """Test getting user by GitHub ID after upsert."""
        user = await repo.upsert_by_github_id(12345, "octocat")
        found = await repo.get_by_github_id(12345)

        assert found is not None
        assert found.id == user.id


class TestInMemorySessionStore:
    """Tests for InMemorySessionStore."""

    @pytest.fixture
    def store(self) -> InMemorySessionStore:
        """Create a fresh session store for each test."""
        return InMemorySessionStore()

    @pytest.mark.asyncio
    async def test_create_session(self, store: InMemorySessionStore) -> None:
        """Test creating a session."""
        user_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        session = Session(user_id=user_id, expires_at=expires_at)

        created = await store.create(session)

        assert created.session_id == session.session_id
        assert created.user_id == user_id

    @pytest.mark.asyncio
    async def test_get_session(self, store: InMemorySessionStore) -> None:
        """Test getting a session by ID."""
        user_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        session = Session(user_id=user_id, expires_at=expires_at)

        await store.create(session)
        found = await store.get(session.session_id)

        assert found is not None
        assert found.session_id == session.session_id

    @pytest.mark.asyncio
    async def test_get_session_not_found(self, store: InMemorySessionStore) -> None:
        """Test getting a session that doesn't exist."""
        session_id = uuid4()
        found = await store.get(session_id)

        assert found is None

    @pytest.mark.asyncio
    async def test_get_session_invalid_type(
        self, store: InMemorySessionStore
    ) -> None:
        """Test that invalid UUID type raises ValueError."""
        with pytest.raises(ValueError):
            await store.get("not-a-uuid")  # type: ignore

    @pytest.mark.asyncio
    async def test_revoke_session(self, store: InMemorySessionStore) -> None:
        """Test revoking a session."""
        user_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        session = Session(user_id=user_id, expires_at=expires_at)

        await store.create(session)
        result = await store.revoke(session.session_id)

        assert result is True

        found = await store.get(session.session_id)
        assert found is not None
        assert found.is_revoked() is True

    @pytest.mark.asyncio
    async def test_revoke_session_not_found(
        self, store: InMemorySessionStore
    ) -> None:
        """Test revoking a session that doesn't exist."""
        session_id = uuid4()
        result = await store.revoke(session_id)

        assert result is False

    @pytest.mark.asyncio
    async def test_revoke_session_invalid_type(
        self, store: InMemorySessionStore
    ) -> None:
        """Test that invalid UUID type raises ValueError."""
        with pytest.raises(ValueError):
            await store.revoke("not-a-uuid")  # type: ignore

    @pytest.mark.asyncio
    async def test_list_by_user_active_only(
        self, store: InMemorySessionStore
    ) -> None:
        """Test listing only active sessions for a user."""
        user_id = uuid4()

        # Active session
        active = Session(
            user_id=user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        await store.create(active)

        # Expired session
        expired = Session(
            user_id=user_id,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        await store.create(expired)

        # Revoked session
        revoked = Session(
            user_id=user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        await store.create(revoked)
        await store.revoke(revoked.session_id)

        sessions = await store.list_by_user(user_id, include_inactive=False)

        assert len(sessions) == 1
        assert sessions[0].session_id == active.session_id

    @pytest.mark.asyncio
    async def test_list_by_user_include_inactive(
        self, store: InMemorySessionStore
    ) -> None:
        """Test listing all sessions including inactive."""
        user_id = uuid4()

        # Create multiple sessions
        for _ in range(3):
            session = Session(
                user_id=user_id,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            await store.create(session)

        sessions = await store.list_by_user(user_id, include_inactive=True)

        assert len(sessions) == 3

    @pytest.mark.asyncio
    async def test_list_by_user_invalid_type(
        self, store: InMemorySessionStore
    ) -> None:
        """Test that invalid UUID type raises ValueError."""
        with pytest.raises(ValueError):
            await store.list_by_user("not-a-uuid")  # type: ignore


class TestInMemoryGitHubTokenStore:
    """Tests for InMemoryGitHubTokenStore."""

    @pytest.fixture
    def store(self) -> InMemoryGitHubTokenStore:
        """Create a fresh token store for each test."""
        return InMemoryGitHubTokenStore()

    @pytest.mark.asyncio
    async def test_store_and_get_access_token(
        self, store: InMemoryGitHubTokenStore
    ) -> None:
        """Test storing and retrieving an access token."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)
        tokens = GitHubOAuthResult(
            access_token="gho_xxx",
            access_token_expires_at=now + timedelta(hours=8),
            refresh_token="ghr_xxx",
            refresh_token_expires_at=now + timedelta(days=180),
        )

        await store.store_tokens(user_id, tokens)
        access_token = await store.get_access_token(user_id)

        assert access_token == "gho_xxx"

    @pytest.mark.asyncio
    async def test_get_access_token_expired(
        self, store: InMemoryGitHubTokenStore
    ) -> None:
        """Test that expired access tokens return None."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)
        tokens = GitHubOAuthResult(
            access_token="gho_xxx",
            access_token_expires_at=now - timedelta(hours=1),  # Already expired
        )

        await store.store_tokens(user_id, tokens)
        access_token = await store.get_access_token(user_id)

        assert access_token is None

    @pytest.mark.asyncio
    async def test_get_access_token_not_found(
        self, store: InMemoryGitHubTokenStore
    ) -> None:
        """Test that missing tokens return None."""
        user_id = uuid4()
        access_token = await store.get_access_token(user_id)

        assert access_token is None

    @pytest.mark.asyncio
    async def test_get_access_token_invalid_type(
        self, store: InMemoryGitHubTokenStore
    ) -> None:
        """Test that invalid UUID type raises ValueError."""
        with pytest.raises(ValueError):
            await store.get_access_token("not-a-uuid")  # type: ignore

    @pytest.mark.asyncio
    async def test_get_refresh_token(
        self, store: InMemoryGitHubTokenStore
    ) -> None:
        """Test retrieving a refresh token."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)
        tokens = GitHubOAuthResult(
            access_token="gho_xxx",
            access_token_expires_at=now + timedelta(hours=8),
            refresh_token="ghr_xxx",
            refresh_token_expires_at=now + timedelta(days=180),
        )

        await store.store_tokens(user_id, tokens)
        refresh_token = await store.get_refresh_token(user_id)

        assert refresh_token == "ghr_xxx"

    @pytest.mark.asyncio
    async def test_get_refresh_token_not_found(
        self, store: InMemoryGitHubTokenStore
    ) -> None:
        """Test that missing refresh token raises error."""
        user_id = uuid4()

        with pytest.raises(RefreshTokenNotFoundError):
            await store.get_refresh_token(user_id)

    @pytest.mark.asyncio
    async def test_get_refresh_token_none(
        self, store: InMemoryGitHubTokenStore
    ) -> None:
        """Test that None refresh token raises error."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)
        tokens = GitHubOAuthResult(
            access_token="gho_xxx",
            access_token_expires_at=now + timedelta(hours=8),
            refresh_token=None,  # No refresh token
        )

        await store.store_tokens(user_id, tokens)

        with pytest.raises(RefreshTokenNotFoundError):
            await store.get_refresh_token(user_id)

    @pytest.mark.asyncio
    async def test_get_refresh_token_expired(
        self, store: InMemoryGitHubTokenStore
    ) -> None:
        """Test that expired refresh token raises error."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)
        tokens = GitHubOAuthResult(
            access_token="gho_xxx",
            access_token_expires_at=now + timedelta(hours=8),
            refresh_token="ghr_xxx",
            refresh_token_expires_at=now - timedelta(days=1),  # Already expired
        )

        await store.store_tokens(user_id, tokens)

        with pytest.raises(RefreshTokenNotFoundError):
            await store.get_refresh_token(user_id)

    @pytest.mark.asyncio
    async def test_get_refresh_token_invalid_type(
        self, store: InMemoryGitHubTokenStore
    ) -> None:
        """Test that invalid UUID type raises ValueError."""
        with pytest.raises(ValueError):
            await store.get_refresh_token("not-a-uuid")  # type: ignore

    @pytest.mark.asyncio
    async def test_clear_tokens(
        self, store: InMemoryGitHubTokenStore
    ) -> None:
        """Test clearing tokens for a user."""
        user_id = uuid4()
        now = datetime.now(timezone.utc)
        tokens = GitHubOAuthResult(
            access_token="gho_xxx",
            access_token_expires_at=now + timedelta(hours=8),
            refresh_token="ghr_xxx",
            refresh_token_expires_at=now + timedelta(days=180),
        )

        await store.store_tokens(user_id, tokens)
        await store.clear_tokens(user_id)

        assert await store.get_access_token(user_id) is None

        with pytest.raises(RefreshTokenNotFoundError):
            await store.get_refresh_token(user_id)

    @pytest.mark.asyncio
    async def test_clear_tokens_not_found(
        self, store: InMemoryGitHubTokenStore
    ) -> None:
        """Test clearing tokens for a user that doesn't have any."""
        user_id = uuid4()

        # Should not raise
        await store.clear_tokens(user_id)

    @pytest.mark.asyncio
    async def test_store_tokens_with_naive_datetime(
        self, store: InMemoryGitHubTokenStore
    ) -> None:
        """Test that naive datetimes are normalized to UTC in GitHubOAuthResult."""
        user_id = uuid4()
        # Use a naive datetime (no tzinfo) in the future
        naive_future = datetime(2099, 12, 31, 23, 59, 59)
        tokens = GitHubOAuthResult(
            access_token="gho_xxx",
            access_token_expires_at=naive_future,
        )

        # The token should be normalized to UTC
        assert tokens.access_token_expires_at.tzinfo == timezone.utc

        await store.store_tokens(user_id, tokens)
        # Should retrieve successfully without TypeError
        access_token = await store.get_access_token(user_id)
        assert access_token == "gho_xxx"
