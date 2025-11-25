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
"""AFUser repository abstraction and in-memory implementation.

This module defines the AFUserRepository abstract base class for user
persistence and provides an InMemoryUserRepository for development use.
Production implementations should be thread-safe and persistent.
"""

import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from uuid import UUID

import structlog

from af_identity_service.models.user import AFUser

logger = structlog.get_logger(__name__)


class AFUserRepository(ABC):
    """Abstract base class for AFUser persistence.

    Implementations must be thread-safe to avoid race conditions
    in multi-worker environments like Cloud Run.

    Methods:
        get_by_id: Retrieve a user by their UUID.
        get_by_github_id: Retrieve a user by their GitHub user ID.
        upsert_by_github_id: Create or update a user by GitHub ID.
    """

    @abstractmethod
    async def get_by_id(self, user_id: UUID) -> AFUser | None:
        """Retrieve a user by their UUID.

        Args:
            user_id: The user's UUID.

        Returns:
            The AFUser if found, None otherwise.

        Raises:
            ValueError: If user_id is not a valid UUID.
        """
        pass

    @abstractmethod
    async def get_by_github_id(self, github_user_id: int) -> AFUser | None:
        """Retrieve a user by their GitHub user ID.

        Args:
            github_user_id: The GitHub user ID.

        Returns:
            The AFUser if found, None otherwise.
        """
        pass

    @abstractmethod
    async def upsert_by_github_id(
        self, github_user_id: int, github_login: str
    ) -> AFUser:
        """Create or update a user by their GitHub ID.

        If a user with the given GitHub ID exists, updates their
        github_login and updated_at fields. Otherwise, creates a
        new user with the provided GitHub identity.

        Args:
            github_user_id: The GitHub user ID.
            github_login: The GitHub username.

        Returns:
            The created or updated AFUser.
        """
        pass


class InMemoryUserRepository(AFUserRepository):
    """In-memory implementation of AFUserRepository.

    This implementation is suitable for development and testing only.
    It stores users in memory and uses threading locks for thread-safety.

    WARNING: Data is lost when the process exits. Use a persistent
    implementation for production deployments.

    Attributes:
        _users_by_id: Dictionary mapping user UUIDs to AFUser instances.
        _users_by_github_id: Dictionary mapping GitHub IDs to AFUser instances.
        _lock: Threading lock for thread-safe operations.
    """

    def __init__(self) -> None:
        """Initialize the in-memory user repository."""
        self._users_by_id: dict[UUID, AFUser] = {}
        self._users_by_github_id: dict[int, AFUser] = {}
        self._lock = threading.Lock()
        logger.info("Initialized in-memory user repository (dev-only)")

    async def get_by_id(self, user_id: UUID) -> AFUser | None:
        """Retrieve a user by their UUID.

        Args:
            user_id: The user's UUID.

        Returns:
            The AFUser if found, None otherwise.

        Raises:
            ValueError: If user_id is not a valid UUID.
        """
        if not isinstance(user_id, UUID):
            raise ValueError(f"user_id must be a UUID, got {type(user_id).__name__}")

        with self._lock:
            user = self._users_by_id.get(user_id)

        if user:
            logger.debug("User found by ID", user_id=str(user_id))
        else:
            logger.debug("User not found by ID", user_id=str(user_id))

        return user

    async def get_by_github_id(self, github_user_id: int) -> AFUser | None:
        """Retrieve a user by their GitHub user ID.

        Args:
            github_user_id: The GitHub user ID.

        Returns:
            The AFUser if found, None otherwise.
        """
        with self._lock:
            user = self._users_by_github_id.get(github_user_id)

        if user:
            logger.debug("User found by GitHub ID", github_user_id=github_user_id)
        else:
            logger.debug("User not found by GitHub ID", github_user_id=github_user_id)

        return user

    async def upsert_by_github_id(
        self, github_user_id: int, github_login: str
    ) -> AFUser:
        """Create or update a user by their GitHub ID.

        If a user with the given GitHub ID exists, updates their
        github_login and updated_at fields. Otherwise, creates a
        new user with the provided GitHub identity.

        Args:
            github_user_id: The GitHub user ID.
            github_login: The GitHub username.

        Returns:
            The created or updated AFUser.
        """
        with self._lock:
            existing_user = self._users_by_github_id.get(github_user_id)

            if existing_user:
                # Update existing user
                updated_user = existing_user.model_copy(
                    update={
                        "github_login": github_login,
                        "updated_at": datetime.now(timezone.utc),
                    }
                )
                self._users_by_id[updated_user.id] = updated_user
                self._users_by_github_id[github_user_id] = updated_user
                logger.info(
                    "Updated user by GitHub ID",
                    user_id=str(updated_user.id),
                    github_user_id=github_user_id,
                    github_login=github_login,
                )
                return updated_user
            else:
                # Create new user
                new_user = AFUser(
                    github_user_id=github_user_id,
                    github_login=github_login,
                )
                self._users_by_id[new_user.id] = new_user
                self._users_by_github_id[github_user_id] = new_user
                logger.info(
                    "Created new user by GitHub ID",
                    user_id=str(new_user.id),
                    github_user_id=github_user_id,
                    github_login=github_login,
                )
                return new_user
