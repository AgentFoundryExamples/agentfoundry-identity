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
"""Tests for identity models."""

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from af_identity_service.models import (
    AFTokenIntrospection,
    AFUser,
    GitHubIdentity,
    GitHubOAuthResult,
    Session,
)


class TestAFUser:
    """Tests for the AFUser model."""

    def test_create_user_with_defaults(self) -> None:
        """Test creating a user with default values."""
        user = AFUser()

        assert isinstance(user.id, UUID)
        assert user.github_user_id is None
        assert user.github_login is None
        assert isinstance(user.created_at, datetime)
        assert isinstance(user.updated_at, datetime)
        assert user.created_at.tzinfo is not None

    def test_create_user_with_github_identity(self) -> None:
        """Test creating a user with GitHub identity."""
        user = AFUser(github_user_id=12345, github_login="octocat")

        assert user.github_user_id == 12345
        assert user.github_login == "octocat"

    def test_create_user_with_explicit_id(self) -> None:
        """Test creating a user with an explicit UUID."""
        user_id = uuid4()
        user = AFUser(id=user_id)

        assert user.id == user_id

    def test_user_datetime_is_utc(self) -> None:
        """Test that user timestamps are UTC."""
        user = AFUser()

        assert user.created_at.tzinfo == timezone.utc
        assert user.updated_at.tzinfo == timezone.utc

    def test_user_json_serialization(self) -> None:
        """Test that user can be serialized to JSON."""
        user = AFUser(github_user_id=12345, github_login="octocat")
        json_data = user.model_dump_json()

        assert "12345" in json_data
        assert "octocat" in json_data


class TestGitHubIdentity:
    """Tests for the GitHubIdentity model."""

    def test_create_github_identity(self) -> None:
        """Test creating a GitHub identity."""
        identity = GitHubIdentity(
            github_user_id=12345,
            login="octocat",
            avatar_url="https://avatars.githubusercontent.com/u/12345",
        )

        assert identity.github_user_id == 12345
        assert identity.login == "octocat"
        assert identity.avatar_url == "https://avatars.githubusercontent.com/u/12345"

    def test_github_identity_optional_avatar(self) -> None:
        """Test that avatar_url is optional."""
        identity = GitHubIdentity(github_user_id=12345, login="octocat")

        assert identity.avatar_url is None

    def test_github_identity_required_fields(self) -> None:
        """Test that required fields are enforced."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            GitHubIdentity(login="octocat")  # Missing github_user_id


class TestGitHubOAuthResult:
    """Tests for the GitHubOAuthResult model."""

    def test_create_oauth_result(self) -> None:
        """Test creating an OAuth result."""
        now = datetime.now(timezone.utc)
        result = GitHubOAuthResult(
            access_token="gho_xxx",
            access_token_expires_at=now + timedelta(hours=8),
            refresh_token="ghr_xxx",
            refresh_token_expires_at=now + timedelta(days=180),
        )

        assert result.access_token == "gho_xxx"
        assert result.refresh_token == "ghr_xxx"
        assert result.access_token_expires_at > now
        assert result.refresh_token_expires_at > result.access_token_expires_at

    def test_oauth_result_optional_refresh_token(self) -> None:
        """Test that refresh token is optional."""
        now = datetime.now(timezone.utc)
        result = GitHubOAuthResult(
            access_token="gho_xxx",
            access_token_expires_at=now + timedelta(hours=8),
        )

        assert result.refresh_token is None
        assert result.refresh_token_expires_at is None


class TestSession:
    """Tests for the Session model."""

    def test_create_session(self) -> None:
        """Test creating a session."""
        user_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        session = Session(user_id=user_id, expires_at=expires_at)

        assert isinstance(session.session_id, UUID)
        assert session.user_id == user_id
        assert session.expires_at == expires_at
        assert session.revoked is False

    def test_session_is_revoked(self) -> None:
        """Test is_revoked method."""
        user_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

        session = Session(user_id=user_id, expires_at=expires_at)
        assert session.is_revoked() is False

        revoked_session = Session(user_id=user_id, expires_at=expires_at, revoked=True)
        assert revoked_session.is_revoked() is True

    def test_session_is_expired(self) -> None:
        """Test is_expired method."""
        user_id = uuid4()

        # Future expiration
        future_session = Session(
            user_id=user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        assert future_session.is_expired() is False

        # Past expiration
        past_session = Session(
            user_id=user_id,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert past_session.is_expired() is True

    def test_session_is_expired_with_custom_now(self) -> None:
        """Test is_expired with custom now parameter."""
        user_id = uuid4()
        expires_at = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        session = Session(user_id=user_id, expires_at=expires_at)

        before_expiry = datetime(2025, 6, 15, 11, 0, 0, tzinfo=timezone.utc)
        assert session.is_expired(before_expiry) is False

        after_expiry = datetime(2025, 6, 15, 13, 0, 0, tzinfo=timezone.utc)
        assert session.is_expired(after_expiry) is True

    def test_session_is_active(self) -> None:
        """Test is_active method."""
        user_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

        # Active session
        active_session = Session(user_id=user_id, expires_at=expires_at)
        assert active_session.is_active() is True

        # Revoked session
        revoked_session = Session(user_id=user_id, expires_at=expires_at, revoked=True)
        assert revoked_session.is_active() is False

        # Expired session
        expired_session = Session(
            user_id=user_id,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert expired_session.is_active() is False


class TestAFTokenIntrospection:
    """Tests for the AFTokenIntrospection model."""

    def test_create_token_introspection(self) -> None:
        """Test creating a token introspection response."""
        user_id = uuid4()
        session_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        introspection = AFTokenIntrospection(
            user_id=user_id,
            github_login="octocat",
            github_user_id=12345,
            session_id=session_id,
            expires_at=expires_at,
        )

        assert introspection.user_id == user_id
        assert introspection.github_login == "octocat"
        assert introspection.github_user_id == 12345
        assert introspection.session_id == session_id
        assert introspection.expires_at == expires_at

    def test_token_introspection_optional_github_fields(self) -> None:
        """Test that GitHub fields are optional."""
        user_id = uuid4()
        session_id = uuid4()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

        introspection = AFTokenIntrospection(
            user_id=user_id,
            session_id=session_id,
            expires_at=expires_at,
        )

        assert introspection.github_login is None
        assert introspection.github_user_id is None
