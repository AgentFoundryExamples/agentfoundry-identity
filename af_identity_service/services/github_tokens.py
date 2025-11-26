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
"""GitHub token service for token distribution to AF services.

This module provides the GitHubTokenService class that handles:
- Access token caching with expiry buffer
- Token refresh via GitHubOAuthDriver
- Refresh token rotation persistence
- Structured audit logging
"""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import structlog

from af_identity_service.github.driver import GitHubOAuthDriver, GitHubOAuthDriverError
from af_identity_service.stores.github_token_store import (
    GitHubTokenStore,
    RefreshTokenNotFoundError,
)

logger = structlog.get_logger(__name__)

# Buffer time before expiry to treat token as expired (avoid returning tokens
# that will die mid-request)
ACCESS_TOKEN_EXPIRY_BUFFER_SECONDS = 300  # 5 minutes


class GitHubTokenServiceError(Exception):
    """Base exception for GitHub token service errors."""

    pass


class RefreshTokenMissingError(GitHubTokenServiceError):
    """Raised when user has no stored refresh token (GitHub linking incomplete)."""

    pass


class TokenRefreshError(GitHubTokenServiceError):
    """Raised when token refresh fails."""

    pass


@dataclass
class GitHubAccessTokenResult:
    """Result of getting a GitHub access token."""

    access_token: str
    expires_at: datetime


class GitHubTokenService:
    """Service for distributing GitHub access tokens to AF services.

    This service:
    - Returns cached access tokens when valid (respecting expiry buffer)
    - Refreshes tokens via GitHubOAuthDriver when expired
    - Persists rotated refresh tokens immediately
    - Supports force_refresh to bypass cache
    - Emits structured audit logs for successes and failures
    """

    def __init__(
        self,
        token_store: GitHubTokenStore,
        github_driver: GitHubOAuthDriver,
    ) -> None:
        """Initialize the GitHub token service.

        Args:
            token_store: Store for GitHub token persistence.
            github_driver: Driver for GitHub OAuth operations.
        """
        self._token_store = token_store
        self._github_driver = github_driver

    async def get_access_token(
        self,
        user_id: UUID,
        force_refresh: bool = False,
    ) -> GitHubAccessTokenResult:
        """Get a GitHub access token for a user.

        Attempts to return a cached token if valid and force_refresh is False.
        Otherwise, refreshes the token using the stored refresh token.

        Args:
            user_id: The AF user's UUID.
            force_refresh: If True, bypass cache and always refresh token.

        Returns:
            GitHubAccessTokenResult with access token and expiry.

        Raises:
            RefreshTokenMissingError: If user has no stored refresh token.
            TokenRefreshError: If token refresh fails.
        """
        # Try to get cached access token if not forcing refresh
        if not force_refresh:
            cached_token = await self._get_cached_token_if_valid(user_id)
            if cached_token is not None:
                logger.info(
                    "github.token.cache.hit",
                    af_user_id=str(user_id),
                )
                return cached_token

        # Need to refresh - get stored refresh token
        try:
            refresh_token = await self._token_store.get_refresh_token(user_id)
        except RefreshTokenNotFoundError as e:
            logger.warning(
                "github.token.refresh.failure",
                af_user_id=str(user_id),
                reason="refresh_token_missing",
            )
            raise RefreshTokenMissingError(
                "GitHub linking incomplete - no refresh token available. "
                "Please re-authenticate with GitHub."
            ) from e

        # Refresh the token
        try:
            new_tokens = await self._github_driver.refresh_access_token(refresh_token)
        except GitHubOAuthDriverError as e:
            logger.error(
                "github.token.refresh.failure",
                af_user_id=str(user_id),
                reason="driver_error",
                error=str(e),
            )
            raise TokenRefreshError(f"Failed to refresh GitHub token: {e}") from e

        # Store the new tokens (including potentially rotated refresh token)
        await self._token_store.store_tokens(user_id, new_tokens)

        logger.info(
            "github.token.refresh.success",
            af_user_id=str(user_id),
            access_token_expires_at=new_tokens.access_token_expires_at.isoformat(),
            refresh_token_rotated=new_tokens.refresh_token is not None,
        )

        return GitHubAccessTokenResult(
            access_token=new_tokens.access_token,
            expires_at=new_tokens.access_token_expires_at,
        )

    async def _get_cached_token_if_valid(
        self,
        user_id: UUID,
    ) -> GitHubAccessTokenResult | None:
        """Get cached access token if it's valid with safety buffer.

        Applies a safety buffer to avoid returning tokens that will expire
        mid-request. Tokens expiring within ACCESS_TOKEN_EXPIRY_BUFFER_SECONDS
        are treated as expired.

        Args:
            user_id: The AF user's UUID.

        Returns:
            GitHubAccessTokenResult if valid token found, None otherwise.
        """
        result = await self._token_store.get_access_token_with_expiry(
            user_id, buffer_seconds=ACCESS_TOKEN_EXPIRY_BUFFER_SECONDS
        )
        if result is None:
            return None

        access_token, expires_at = result
        return GitHubAccessTokenResult(
            access_token=access_token,
            expires_at=expires_at,
        )
