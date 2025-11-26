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
"""GitHub token store abstraction and in-memory implementation.

This module defines the GitHubTokenStore abstract base class for
persisting encrypted refresh tokens and cached access tokens, and
provides an InMemoryGitHubTokenStore for development use.

ENCRYPTION EXPECTATIONS:
In production implementations, refresh tokens MUST be encrypted at rest
using a secure encryption algorithm (e.g., AES-256-GCM). The encryption
key should be managed via a secure key management service (KMS).

The in-memory dev store does NOT encrypt tokens and is only suitable
for development and testing. Production implementations must:
1. Encrypt refresh tokens before storage
2. Decrypt refresh tokens on retrieval
3. Use a secure key rotation strategy
4. Never log or expose raw token values
"""

import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from uuid import UUID

import structlog

from af_identity_service.models.github import GitHubOAuthResult

logger = structlog.get_logger(__name__)


class GitHubTokenStoreError(Exception):
    """Base exception for GitHub token store errors."""

    pass


class RefreshTokenNotFoundError(GitHubTokenStoreError):
    """Raised when a refresh token is not found for a user."""

    pass


class GitHubTokenStore(ABC):
    """Abstract base class for GitHub token persistence.

    Implementations are responsible for persisting encrypted refresh tokens
    and cached access tokens for users. Production implementations MUST
    encrypt refresh tokens at rest.

    Methods:
        store_tokens: Store access and refresh tokens for a user.
        get_access_token: Retrieve cached access token if not expired.
        get_refresh_token: Retrieve the refresh token for a user.
        clear_tokens: Clear all tokens for a user.
    """

    @abstractmethod
    async def store_tokens(self, user_id: UUID, tokens: GitHubOAuthResult) -> None:
        """Store access and refresh tokens for a user.

        In production, the refresh token must be encrypted before storage.

        Args:
            user_id: The user's UUID.
            tokens: The OAuth result containing tokens and expiration times.
        """
        pass

    @abstractmethod
    async def get_access_token(self, user_id: UUID) -> str | None:
        """Retrieve cached access token if not expired.

        Args:
            user_id: The user's UUID.

        Returns:
            The access token if cached and not expired, None otherwise.

        Raises:
            ValueError: If user_id is not a valid UUID.
        """
        pass

    @abstractmethod
    async def get_refresh_token(self, user_id: UUID) -> str:
        """Retrieve the refresh token for a user.

        In production, the refresh token must be decrypted on retrieval.

        Args:
            user_id: The user's UUID.

        Returns:
            The refresh token.

        Raises:
            ValueError: If user_id is not a valid UUID.
            RefreshTokenNotFoundError: If no refresh token exists for the user.
        """
        pass

    @abstractmethod
    async def clear_tokens(self, user_id: UUID) -> None:
        """Clear all tokens for a user.

        Args:
            user_id: The user's UUID.
        """
        pass


class _StoredTokens:
    """Internal representation of stored tokens."""

    def __init__(
        self,
        access_token: str,
        access_token_expires_at: datetime,
        refresh_token: str | None,
        refresh_token_expires_at: datetime | None,
    ) -> None:
        self.access_token = access_token
        self.access_token_expires_at = access_token_expires_at
        self.refresh_token = refresh_token
        self.refresh_token_expires_at = refresh_token_expires_at


class InMemoryGitHubTokenStore(GitHubTokenStore):
    """In-memory implementation of GitHubTokenStore.

    WARNING: This implementation does NOT encrypt tokens and is only
    suitable for development and testing. Production implementations
    MUST encrypt refresh tokens at rest.

    This implementation is thread-safe and suitable for single-instance
    development deployments.

    Attributes:
        _tokens: Dictionary mapping user UUIDs to stored tokens.
        _lock: Threading lock for thread-safe operations.
    """

    def __init__(self) -> None:
        """Initialize the in-memory GitHub token store."""
        self._tokens: dict[UUID, _StoredTokens] = {}
        self._lock = threading.Lock()
        logger.warning(
            "Initialized in-memory GitHub token store (dev-only, tokens NOT encrypted)"
        )

    async def store_tokens(self, user_id: UUID, tokens: GitHubOAuthResult) -> None:
        """Store access and refresh tokens for a user.

        WARNING: Tokens are stored in plain text in this dev implementation.

        Args:
            user_id: The user's UUID.
            tokens: The OAuth result containing tokens and expiration times.

        Raises:
            ValueError: If user_id is not a valid UUID.
        """
        if not isinstance(user_id, UUID):
            raise ValueError(f"user_id must be a UUID, got {type(user_id).__name__}")

        with self._lock:
            self._tokens[user_id] = _StoredTokens(
                access_token=tokens.access_token,
                access_token_expires_at=tokens.access_token_expires_at,
                refresh_token=tokens.refresh_token,
                refresh_token_expires_at=tokens.refresh_token_expires_at,
            )

        logger.info(
            "Stored GitHub tokens",
            user_id=str(user_id),
            has_refresh_token=tokens.refresh_token is not None,
            access_token_expires_at=tokens.access_token_expires_at.isoformat(),
        )

    async def get_access_token(self, user_id: UUID) -> str | None:
        """Retrieve cached access token if not expired.

        Args:
            user_id: The user's UUID.

        Returns:
            The access token if cached and not expired, None otherwise.

        Raises:
            ValueError: If user_id is not a valid UUID.
        """
        if not isinstance(user_id, UUID):
            raise ValueError(f"user_id must be a UUID, got {type(user_id).__name__}")

        now = datetime.now(timezone.utc)

        with self._lock:
            stored = self._tokens.get(user_id)
            if stored is None:
                logger.debug("No tokens found for user", user_id=str(user_id))
                return None

            if now >= stored.access_token_expires_at:
                logger.debug("Access token expired", user_id=str(user_id))
                return None

            logger.debug("Access token retrieved", user_id=str(user_id))
            return stored.access_token

    async def get_refresh_token(self, user_id: UUID) -> str:
        """Retrieve the refresh token for a user.

        Args:
            user_id: The user's UUID.

        Returns:
            The refresh token.

        Raises:
            ValueError: If user_id is not a valid UUID.
            RefreshTokenNotFoundError: If no refresh token exists for the user.
        """
        if not isinstance(user_id, UUID):
            raise ValueError(f"user_id must be a UUID, got {type(user_id).__name__}")

        with self._lock:
            stored = self._tokens.get(user_id)
            if stored is None or stored.refresh_token is None:
                logger.warning("Refresh token not found", user_id=str(user_id))
                raise RefreshTokenNotFoundError(
                    f"No refresh token found for user {user_id}"
                )

            # Check if refresh token is expired
            if (
                stored.refresh_token_expires_at is not None
                and datetime.now(timezone.utc) >= stored.refresh_token_expires_at
            ):
                logger.warning("Refresh token expired", user_id=str(user_id))
                raise RefreshTokenNotFoundError(
                    f"Refresh token expired for user {user_id}"
                )

            logger.debug("Refresh token retrieved", user_id=str(user_id))
            return stored.refresh_token

    async def clear_tokens(self, user_id: UUID) -> None:
        """Clear all tokens for a user.

        Args:
            user_id: The user's UUID.

        Raises:
            ValueError: If user_id is not a valid UUID.
        """
        if not isinstance(user_id, UUID):
            raise ValueError(f"user_id must be a UUID, got {type(user_id).__name__}")

        with self._lock:
            if user_id in self._tokens:
                del self._tokens[user_id]
                logger.info("Cleared GitHub tokens", user_id=str(user_id))
            else:
                logger.debug("No tokens to clear", user_id=str(user_id))
