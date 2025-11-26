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
"""GitHub OAuth driver abstraction and stub implementation.

This module defines the GitHubOAuthDriver abstract base class for
GitHub OAuth operations and provides a StubGitHubOAuthDriver for
development that logs fake interactions.

The driver interface is designed to be swappable for production
implementations that make real GitHub API calls.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone

import structlog

from af_identity_service.models.github import GitHubIdentity, GitHubOAuthResult

logger = structlog.get_logger(__name__)


class GitHubOAuthDriverError(Exception):
    """Base exception for GitHub OAuth driver errors."""

    pass


class GitHubOAuthDriver(ABC):
    """Abstract base class for GitHub OAuth operations.

    Implementations must handle GitHub OAuth token exchange, token refresh,
    and user profile retrieval. Production implementations should use
    secure HTTP clients and validate responses.

    Methods:
        exchange_code_for_tokens: Exchange an authorization code for tokens.
        refresh_access_token: Refresh an expired access token.
        get_user_profile: Get the authenticated user's GitHub profile.
    """

    @abstractmethod
    async def exchange_code_for_tokens(self, code: str) -> GitHubOAuthResult:
        """Exchange an OAuth authorization code for tokens.

        Args:
            code: The authorization code from GitHub OAuth callback.

        Returns:
            GitHubOAuthResult containing access and refresh tokens.

        Raises:
            GitHubOAuthDriverError: If the code exchange fails.
        """
        pass

    @abstractmethod
    async def refresh_access_token(self, refresh_token: str) -> GitHubOAuthResult:
        """Refresh an expired access token using a refresh token.

        Args:
            refresh_token: The refresh token from a previous OAuth flow.

        Returns:
            GitHubOAuthResult containing new access and refresh tokens.

        Raises:
            GitHubOAuthDriverError: If the token refresh fails.
        """
        pass

    @abstractmethod
    async def get_user_profile(self, access_token: str) -> GitHubIdentity:
        """Get the authenticated user's GitHub profile.

        Args:
            access_token: A valid GitHub access token.

        Returns:
            GitHubIdentity containing user profile information.

        Raises:
            GitHubOAuthDriverError: If the profile retrieval fails.
        """
        pass


class StubGitHubOAuthDriver(GitHubOAuthDriver):
    """Stub implementation of GitHubOAuthDriver for development.

    This driver does NOT make real GitHub API calls. It returns fake
    data and logs all interactions for development and testing purposes.

    WARNING: This driver should NEVER be used in production. It does not
    perform real authentication and accepts any input as valid.

    The stub driver:
    - Returns predictable fake tokens and user profiles
    - Logs all operations for debugging
    - Simulates token expiration times

    Attributes:
        _client_id: The GitHub OAuth client ID (for logging only).
    """

    def __init__(self, client_id: str) -> None:
        """Initialize the stub GitHub OAuth driver.

        Args:
            client_id: The GitHub OAuth client ID (used for logging only).
        """
        self._client_id = client_id
        logger.warning(
            "Initialized stub GitHub OAuth driver (dev-only, NOT for production)",
            client_id=client_id,
        )

    async def exchange_code_for_tokens(self, code: str) -> GitHubOAuthResult:
        """Exchange an OAuth authorization code for fake tokens.

        This stub implementation returns fake tokens without making
        any real API calls.

        Args:
            code: The authorization code (accepted without validation).

        Returns:
            GitHubOAuthResult with fake tokens.
        """
        logger.info(
            "Stub: exchanging code for tokens",
            code_prefix=code[:8] if len(code) > 8 else code,
        )

        now = datetime.now(timezone.utc)
        result = GitHubOAuthResult(
            access_token=f"gho_stub_access_{code[:8]}",
            access_token_expires_at=now + timedelta(hours=8),
            refresh_token=f"ghr_stub_refresh_{code[:8]}",
            refresh_token_expires_at=now + timedelta(days=180),
        )

        logger.info(
            "Stub: code exchange complete",
            access_token_expires_at=result.access_token_expires_at.isoformat(),
        )
        return result

    async def refresh_access_token(self, refresh_token: str) -> GitHubOAuthResult:
        """Refresh an access token using fake token refresh.

        This stub implementation returns fake tokens without making
        any real API calls.

        Args:
            refresh_token: The refresh token (accepted without validation).

        Returns:
            GitHubOAuthResult with new fake tokens.
        """
        logger.info("Stub: refreshing access token")

        now = datetime.now(timezone.utc)
        result = GitHubOAuthResult(
            access_token=f"gho_stub_refreshed_{now.timestamp():.0f}",
            access_token_expires_at=now + timedelta(hours=8),
            refresh_token=f"ghr_stub_renewed_{now.timestamp():.0f}",
            refresh_token_expires_at=now + timedelta(days=180),
        )

        logger.info(
            "Stub: token refresh complete",
            access_token_expires_at=result.access_token_expires_at.isoformat(),
        )
        return result

    async def get_user_profile(self, access_token: str) -> GitHubIdentity:
        """Get a fake user profile.

        This stub implementation returns a fake user profile without
        making any real API calls. The user ID is derived from the
        access token for consistency.

        Args:
            access_token: The access token (used to derive fake user ID).

        Returns:
            GitHubIdentity with fake user profile data.
        """
        logger.info("Stub: getting user profile")

        # Generate a consistent fake user ID from the token
        fake_user_id = abs(hash(access_token)) % 1000000 + 1

        profile = GitHubIdentity(
            github_user_id=fake_user_id,
            login=f"stub_user_{fake_user_id}",
            avatar_url=f"https://avatars.githubusercontent.com/u/{fake_user_id}",
        )

        logger.info(
            "Stub: user profile retrieved",
            github_user_id=profile.github_user_id,
            login=profile.login,
        )
        return profile
