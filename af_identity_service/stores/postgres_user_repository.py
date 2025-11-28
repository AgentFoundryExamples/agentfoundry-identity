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
"""Postgres implementation of AFUserRepository.

This module provides a durable, Postgres-backed implementation of the
AFUserRepository interface. It uses SQLAlchemy Core for database operations
and ensures all timestamps are stored and returned as UTC-aware datetimes.

Thread Safety:
    This implementation is thread-safe. Each operation uses its own connection
    from the connection pool, and SQLAlchemy handles connection management.

Error Handling:
    - Duplicate github_user_id inserts raise DuplicateGitHubUserError
    - Database connection errors raise ConnectionError with descriptive messages
    - Invalid UUID inputs raise ValueError early
"""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError, OperationalError

from af_identity_service.models.user import AFUser
from af_identity_service.stores.user_store import AFUserRepository

logger = structlog.get_logger(__name__)


class DuplicateGitHubUserError(Exception):
    """Raised when attempting to create a user with a duplicate github_user_id."""

    def __init__(self, github_user_id: int) -> None:
        """Initialize the error.

        Args:
            github_user_id: The duplicate GitHub user ID.
        """
        self.github_user_id = github_user_id
        super().__init__(f"User with github_user_id {github_user_id} already exists")


class DatabaseConnectionError(Exception):
    """Raised when there is a database connection failure.

    This error provides a sanitized message that does not leak credentials.
    """

    def __init__(self, message: str) -> None:
        """Initialize the error.

        Args:
            message: A sanitized error message without credentials.
        """
        super().__init__(message)


class PostgresUserRepository(AFUserRepository):
    """Postgres implementation of AFUserRepository.

    This implementation provides durable persistence of AFUser records
    using PostgreSQL. All datetime fields are stored as TIMESTAMPTZ
    and returned as UTC-aware Python datetimes.

    Attributes:
        _engine: SQLAlchemy engine for database connections.
    """

    def __init__(self, engine: Engine) -> None:
        """Initialize the Postgres user repository.

        Args:
            engine: SQLAlchemy engine connected to the target database.
                   The engine should be configured with appropriate
                   connection pool settings for the deployment environment.
        """
        # Import table definition here to avoid circular imports
        from af_identity_service.migrations.user_schema import af_users_table

        self._engine = engine
        self._table = af_users_table
        logger.info("Initialized PostgresUserRepository")

    def _row_to_user(self, row) -> AFUser:
        """Convert a database row to an AFUser model.

        Args:
            row: A SQLAlchemy row result.

        Returns:
            An AFUser instance with UTC-aware timestamps.
        """
        created_at = row.created_at
        updated_at = row.updated_at

        # Ensure timestamps are UTC-aware
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if updated_at.tzinfo is None:
            updated_at = updated_at.replace(tzinfo=timezone.utc)

        return AFUser(
            id=row.id,
            github_user_id=row.github_user_id,
            github_login=row.github_login,
            created_at=created_at,
            updated_at=updated_at,
        )

    async def get_by_id(self, user_id: UUID) -> AFUser | None:
        """Retrieve a user by their UUID.

        Args:
            user_id: The user's UUID.

        Returns:
            The AFUser if found, None otherwise.

        Raises:
            ValueError: If user_id is not a valid UUID.
            DatabaseConnectionError: If there is a database connection failure.
        """
        if not isinstance(user_id, UUID):
            raise ValueError(f"user_id must be a UUID, got {type(user_id).__name__}")

        try:
            with self._engine.connect() as conn:
                stmt = select(self._table).where(self._table.c.id == user_id)
                result = conn.execute(stmt)
                row = result.fetchone()

                if row:
                    logger.debug("User found by ID", user_id=str(user_id))
                    return self._row_to_user(row)
                else:
                    logger.debug("User not found by ID", user_id=str(user_id))
                    return None

        except OperationalError as e:
            logger.error("Database connection error in get_by_id", error=str(e))
            raise DatabaseConnectionError(
                "Failed to connect to database. Check connection settings."
            ) from e

    async def get_by_github_id(self, github_user_id: int) -> AFUser | None:
        """Retrieve a user by their GitHub user ID.

        Args:
            github_user_id: The GitHub user ID.

        Returns:
            The AFUser if found, None otherwise.

        Raises:
            DatabaseConnectionError: If there is a database connection failure.
        """
        try:
            with self._engine.connect() as conn:
                stmt = select(self._table).where(
                    self._table.c.github_user_id == github_user_id
                )
                result = conn.execute(stmt)
                row = result.fetchone()

                if row:
                    logger.debug("User found by GitHub ID", github_user_id=github_user_id)
                    return self._row_to_user(row)
                else:
                    logger.debug("User not found by GitHub ID", github_user_id=github_user_id)
                    return None

        except OperationalError as e:
            logger.error("Database connection error in get_by_github_id", error=str(e))
            raise DatabaseConnectionError(
                "Failed to connect to database. Check connection settings."
            ) from e

    async def upsert_by_github_id(
        self, github_user_id: int, github_login: str
    ) -> AFUser:
        """Create or update a user by their GitHub ID.

        If a user with the given GitHub ID exists, updates their
        github_login and updated_at fields. Otherwise, creates a
        new user with the provided GitHub identity.

        This operation uses PostgreSQL's INSERT ... ON CONFLICT DO UPDATE
        with RETURNING for atomic upsert behavior.

        Args:
            github_user_id: The GitHub user ID.
            github_login: The GitHub username.

        Returns:
            The created or updated AFUser.

        Raises:
            DatabaseConnectionError: If there is a database connection failure.
        """
        now = datetime.now(timezone.utc)

        try:
            with self._engine.connect() as conn:
                # Use PostgreSQL upsert (INSERT ... ON CONFLICT DO UPDATE)
                # with RETURNING to atomically get the result
                stmt = insert(self._table).values(
                    id=uuid4(),
                    github_user_id=github_user_id,
                    github_login=github_login,
                    created_at=now,
                    updated_at=now,
                )

                # On conflict with github_user_id, update login and updated_at
                stmt = stmt.on_conflict_do_update(
                    index_elements=["github_user_id"],
                    set_={
                        "github_login": github_login,
                        "updated_at": now,
                    },
                )

                # Use RETURNING to get the result atomically
                stmt = stmt.returning(self._table)

                # Execute the upsert and get the result in one operation
                result = conn.execute(stmt)
                row = result.fetchone()
                conn.commit()

                if row is None:
                    # This should never happen after a successful upsert
                    raise RuntimeError(
                        f"Failed to fetch user after upsert: github_user_id={github_user_id}"
                    )

                user = self._row_to_user(row)

                # Log whether this was a create or update based on whether
                # created_at and updated_at are within a small time window
                # (database precision may differ)
                time_diff = abs(
                    (row.updated_at - row.created_at).total_seconds()
                )
                is_new_user = time_diff < 1.0  # Within 1 second = new user
                if is_new_user:
                    logger.info(
                        "Created new user by GitHub ID",
                        user_id=str(user.id),
                        github_user_id=github_user_id,
                        github_login=github_login,
                    )
                else:
                    logger.info(
                        "Updated user by GitHub ID",
                        user_id=str(user.id),
                        github_user_id=github_user_id,
                        github_login=github_login,
                    )

                return user

        except OperationalError as e:
            logger.error("Database connection error in upsert_by_github_id", error=str(e))
            raise DatabaseConnectionError(
                "Failed to connect to database. Check connection settings."
            ) from e
        except IntegrityError as e:
            # Check if this is a github_user_id uniqueness violation
            error_str = str(e).lower()
            if "github_user_id" in error_str or "unique" in error_str:
                logger.error("Integrity error in upsert_by_github_id", error=str(e))
                raise DuplicateGitHubUserError(github_user_id) from e
            # For other integrity errors, re-raise as-is
            raise
