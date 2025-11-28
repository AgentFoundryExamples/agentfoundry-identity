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
"""Postgres implementation of GitHubTokenStore with AES-256-GCM encryption.

This module provides a durable, Postgres-backed implementation of the
GitHubTokenStore interface. All tokens are encrypted at rest using
AES-256-GCM before being stored in the database.

Security Properties:
    - Tokens are encrypted with AES-256-GCM before storage
    - Random IVs are used for each encryption operation
    - Decryption failures are logged without exposing token data
    - All database operations use transactions for consistency

Thread Safety:
    This implementation is thread-safe. Each operation uses its own connection
    from the connection pool, and SQLAlchemy handles connection management.

Error Handling:
    - Decryption failures raise RefreshTokenNotFoundError to avoid leaking details
    - Database connection errors raise DatabaseOperationError
    - All errors are logged with redacted token information
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID

import structlog
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError

from af_identity_service.models.github import GitHubOAuthResult
from af_identity_service.security.crypto import DecryptionError, TokenEncryptor
from af_identity_service.stores.github_token_store import (
    GitHubTokenStore,
    GitHubTokenStoreError,
    RefreshTokenNotFoundError,
)

logger = structlog.get_logger(__name__)


class DatabaseOperationError(GitHubTokenStoreError):
    """Raised when a database operation fails.

    This error provides a sanitized message that does not leak credentials
    or sensitive data.
    """

    def __init__(self, message: str) -> None:
        """Initialize the error.

        Args:
            message: A sanitized error message without credentials.
        """
        super().__init__(message)


class PostgresGitHubTokenStore(GitHubTokenStore):
    """Postgres implementation of GitHubTokenStore with encryption.

    This implementation provides durable persistence of GitHub tokens
    using PostgreSQL with AES-256-GCM encryption at rest.

    All tokens are encrypted before storage and decrypted on retrieval.
    Decryption failures (e.g., from key rotation) are handled gracefully
    and logged without exposing token data.

    Attributes:
        _engine: SQLAlchemy engine for database connections.
        _encryptor: TokenEncryptor for encrypting/decrypting tokens.
        _table: Reference to the github_tokens table definition.
    """

    def __init__(self, engine: Engine, encryptor: TokenEncryptor) -> None:
        """Initialize the Postgres GitHub token store.

        Args:
            engine: SQLAlchemy engine connected to the target database.
                   The engine should be configured with appropriate
                   connection pool settings for the deployment environment.
            encryptor: TokenEncryptor for encrypting/decrypting tokens.
        """
        # Import table definition here to avoid circular imports
        from af_identity_service.migrations.github_token_schema import github_tokens_table

        self._engine = engine
        self._encryptor = encryptor
        self._table = github_tokens_table
        logger.info("Initialized PostgresGitHubTokenStore with encryption")

    def _row_to_datetime(self, dt: datetime | None) -> datetime | None:
        """Ensure datetime is UTC-aware.

        Args:
            dt: A datetime that may be naive or timezone-aware.

        Returns:
            UTC-aware datetime or None.
        """
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    async def store_tokens(self, user_id: UUID, tokens: GitHubOAuthResult) -> None:
        """Store access and refresh tokens for a user.

        Tokens are encrypted before storage. This operation is atomic -
        either all tokens are stored or none are.

        Args:
            user_id: The user's UUID.
            tokens: The OAuth result containing tokens and expiration times.

        Raises:
            ValueError: If user_id is not a valid UUID.
            DatabaseOperationError: If there is a database error.
        """
        if not isinstance(user_id, UUID):
            raise ValueError(f"user_id must be a UUID, got {type(user_id).__name__}")

        now = datetime.now(timezone.utc)

        # Encrypt tokens before storage
        encrypted_refresh = None
        if tokens.refresh_token is not None:
            encrypted_refresh = self._encryptor.encrypt(tokens.refresh_token)

        encrypted_access = self._encryptor.encrypt(tokens.access_token)

        try:
            with self._engine.connect() as conn:
                # Use upsert (INSERT ... ON CONFLICT DO UPDATE)
                stmt = insert(self._table).values(
                    user_id=user_id,
                    encrypted_refresh_token=encrypted_refresh,
                    refresh_token_expires_at=tokens.refresh_token_expires_at,
                    encrypted_access_token=encrypted_access,
                    access_token_expires_at=tokens.access_token_expires_at,
                    created_at=now,
                    updated_at=now,
                )

                stmt = stmt.on_conflict_do_update(
                    index_elements=["user_id"],
                    set_={
                        "encrypted_refresh_token": encrypted_refresh,
                        "refresh_token_expires_at": tokens.refresh_token_expires_at,
                        "encrypted_access_token": encrypted_access,
                        "access_token_expires_at": tokens.access_token_expires_at,
                        "updated_at": now,
                    },
                )

                conn.execute(stmt)
                conn.commit()

            logger.info(
                "Stored GitHub tokens",
                user_id=str(user_id),
                has_refresh_token=tokens.refresh_token is not None,
                access_token_expires_at=tokens.access_token_expires_at.isoformat(),
            )

        except OperationalError as e:
            logger.error("Database error storing tokens", user_id=str(user_id), error=str(e))
            raise DatabaseOperationError(
                "Failed to store tokens. Check database connection."
            ) from e

    async def get_access_token(self, user_id: UUID) -> str | None:
        """Retrieve cached access token if not expired.

        Args:
            user_id: The user's UUID.

        Returns:
            The access token if cached and not expired, None otherwise.

        Raises:
            ValueError: If user_id is not a valid UUID.
            DatabaseOperationError: If there is a database error.
        """
        if not isinstance(user_id, UUID):
            raise ValueError(f"user_id must be a UUID, got {type(user_id).__name__}")

        now = datetime.now(timezone.utc)

        try:
            with self._engine.connect() as conn:
                stmt = select(
                    self._table.c.encrypted_access_token,
                    self._table.c.access_token_expires_at,
                ).where(self._table.c.user_id == user_id)

                result = conn.execute(stmt)
                row = result.fetchone()

                if row is None:
                    logger.debug("No tokens found for user", user_id=str(user_id))
                    return None

                encrypted_access = row.encrypted_access_token
                expires_at = self._row_to_datetime(row.access_token_expires_at)

                if encrypted_access is None:
                    logger.debug("No access token for user", user_id=str(user_id))
                    return None

                if expires_at is not None and now >= expires_at:
                    logger.debug("Access token expired", user_id=str(user_id))
                    return None

                # Decrypt the access token
                try:
                    access_token = self._encryptor.decrypt(encrypted_access)
                    logger.debug("Access token retrieved", user_id=str(user_id))
                    return access_token
                except DecryptionError:
                    logger.warning(
                        "Failed to decrypt access token - key may have changed",
                        user_id=str(user_id),
                    )
                    return None

        except OperationalError as e:
            logger.error("Database error getting access token", user_id=str(user_id), error=str(e))
            raise DatabaseOperationError(
                "Failed to retrieve access token. Check database connection."
            ) from e

    async def get_access_token_with_expiry(
        self, user_id: UUID, buffer_seconds: int = 300
    ) -> tuple[str, datetime] | None:
        """Retrieve cached access token with expiry time if still valid with buffer.

        This method applies a safety buffer to avoid returning tokens that will
        expire mid-request.

        Args:
            user_id: The user's UUID.
            buffer_seconds: Safety buffer in seconds. Default is 300 (5 minutes).

        Returns:
            Tuple of (access_token, expires_at) if valid, None otherwise.

        Raises:
            ValueError: If user_id is not a valid UUID.
            DatabaseOperationError: If there is a database error.
        """
        if not isinstance(user_id, UUID):
            raise ValueError(f"user_id must be a UUID, got {type(user_id).__name__}")

        now = datetime.now(timezone.utc)
        buffer_cutoff = now + timedelta(seconds=buffer_seconds)

        try:
            with self._engine.connect() as conn:
                stmt = select(
                    self._table.c.encrypted_access_token,
                    self._table.c.access_token_expires_at,
                ).where(self._table.c.user_id == user_id)

                result = conn.execute(stmt)
                row = result.fetchone()

                if row is None:
                    logger.debug("No tokens found for user", user_id=str(user_id))
                    return None

                encrypted_access = row.encrypted_access_token
                expires_at = self._row_to_datetime(row.access_token_expires_at)

                if encrypted_access is None or expires_at is None:
                    logger.debug("No access token or expiry for user", user_id=str(user_id))
                    return None

                if buffer_cutoff >= expires_at:
                    logger.debug(
                        "Access token expired or near-expiry",
                        user_id=str(user_id),
                        expires_at=expires_at.isoformat(),
                        buffer_seconds=buffer_seconds,
                    )
                    return None

                # Decrypt the access token
                try:
                    access_token = self._encryptor.decrypt(encrypted_access)
                    logger.debug(
                        "Access token with expiry retrieved",
                        user_id=str(user_id),
                        expires_at=expires_at.isoformat(),
                    )
                    return (access_token, expires_at)
                except DecryptionError:
                    logger.warning(
                        "Failed to decrypt access token - key may have changed",
                        user_id=str(user_id),
                    )
                    return None

        except OperationalError as e:
            logger.error(
                "Database error getting access token with expiry",
                user_id=str(user_id),
                error=str(e),
            )
            raise DatabaseOperationError(
                "Failed to retrieve access token. Check database connection."
            ) from e

    async def get_refresh_token(self, user_id: UUID) -> str:
        """Retrieve the refresh token for a user.

        Args:
            user_id: The user's UUID.

        Returns:
            The refresh token.

        Raises:
            ValueError: If user_id is not a valid UUID.
            RefreshTokenNotFoundError: If no refresh token exists or decryption fails.
            DatabaseOperationError: If there is a database error.
        """
        if not isinstance(user_id, UUID):
            raise ValueError(f"user_id must be a UUID, got {type(user_id).__name__}")

        try:
            with self._engine.connect() as conn:
                stmt = select(
                    self._table.c.encrypted_refresh_token,
                    self._table.c.refresh_token_expires_at,
                ).where(self._table.c.user_id == user_id)

                result = conn.execute(stmt)
                row = result.fetchone()

                if row is None or row.encrypted_refresh_token is None:
                    logger.warning("Refresh token not found", user_id=str(user_id))
                    raise RefreshTokenNotFoundError(
                        f"No refresh token found for user {user_id}"
                    )

                expires_at = self._row_to_datetime(row.refresh_token_expires_at)

                # Check if refresh token is expired
                if expires_at is not None and datetime.now(timezone.utc) >= expires_at:
                    logger.warning("Refresh token expired", user_id=str(user_id))
                    raise RefreshTokenNotFoundError(
                        f"Refresh token expired for user {user_id}"
                    )

                # Decrypt the refresh token
                try:
                    refresh_token = self._encryptor.decrypt(row.encrypted_refresh_token)
                    logger.debug("Refresh token retrieved", user_id=str(user_id))
                    return refresh_token
                except DecryptionError:
                    # Log without exposing token data
                    logger.warning(
                        "Failed to decrypt refresh token - key may have changed. "
                        "Re-encrypt tokens with current key to resolve.",
                        user_id=str(user_id),
                    )
                    raise RefreshTokenNotFoundError(
                        f"Unable to decrypt refresh token for user {user_id}. "
                        "Key rotation may have occurred. Please re-authenticate."
                    )

        except RefreshTokenNotFoundError:
            raise
        except OperationalError as e:
            logger.error(
                "Database error getting refresh token", user_id=str(user_id), error=str(e)
            )
            raise DatabaseOperationError(
                "Failed to retrieve refresh token. Check database connection."
            ) from e

    async def clear_tokens(self, user_id: UUID) -> None:
        """Clear all tokens for a user.

        Args:
            user_id: The user's UUID.

        Raises:
            ValueError: If user_id is not a valid UUID.
            DatabaseOperationError: If there is a database error.
        """
        if not isinstance(user_id, UUID):
            raise ValueError(f"user_id must be a UUID, got {type(user_id).__name__}")

        try:
            with self._engine.connect() as conn:
                stmt = delete(self._table).where(self._table.c.user_id == user_id)
                result = conn.execute(stmt)
                conn.commit()

                if result.rowcount > 0:
                    logger.info("Cleared GitHub tokens", user_id=str(user_id))
                else:
                    logger.debug("No tokens to clear", user_id=str(user_id))

        except OperationalError as e:
            logger.error("Database error clearing tokens", user_id=str(user_id), error=str(e))
            raise DatabaseOperationError(
                "Failed to clear tokens. Check database connection."
            ) from e
