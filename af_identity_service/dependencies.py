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
"""Dependency wiring module for the Identity Service.

This module provides lazy instantiation of pluggable dependencies:
- SessionStore: For managing user sessions
- GitHubDriver: For GitHub OAuth interactions

Dependencies are instantiated without performing network I/O, ensuring
fast health checks and fail-fast behavior for configuration issues.
"""

from abc import ABC, abstractmethod
from typing import Any

from af_identity_service.config import Settings
from af_identity_service.logging import get_logger

logger = get_logger(__name__)


class SessionStore(ABC):
    """Abstract base class for session storage.

    Implementations should provide session management without
    requiring network I/O during instantiation.
    """

    @abstractmethod
    async def get(self, session_id: str) -> dict[str, Any] | None:
        """Retrieve a session by ID.

        Args:
            session_id: The unique session identifier.

        Returns:
            The session data if found, None otherwise.
        """
        pass

    @abstractmethod
    async def set(
        self, session_id: str, data: dict[str, Any], expiry_seconds: int | None = None
    ) -> None:
        """Store a session.

        Args:
            session_id: The unique session identifier.
            data: The session data to store.
            expiry_seconds: Optional expiry time in seconds.
        """
        pass

    @abstractmethod
    async def delete(self, session_id: str) -> None:
        """Delete a session.

        Args:
            session_id: The unique session identifier.
        """
        pass

    def health_check(self) -> bool:
        """Check if the session store is healthy.

        Default implementation returns True. Override to add
        connection checks for external stores.

        Returns:
            True if healthy, False otherwise.
        """
        return True


class InMemorySessionStore(SessionStore):
    """In-memory session store implementation.

    This is a placeholder implementation suitable for development
    and single-instance deployments. For production with multiple
    instances, use a distributed store like Redis.
    """

    def __init__(self) -> None:
        """Initialize the in-memory session store."""
        self._sessions: dict[str, dict[str, Any]] = {}
        logger.info("Initialized in-memory session store")

    async def get(self, session_id: str) -> dict[str, Any] | None:
        """Retrieve a session by ID."""
        return self._sessions.get(session_id)

    async def set(
        self, session_id: str, data: dict[str, Any], expiry_seconds: int | None = None
    ) -> None:
        """Store a session."""
        # Note: Expiry is not implemented in the in-memory store
        # A production implementation would use TTL-based eviction
        self._sessions[session_id] = data

    async def delete(self, session_id: str) -> None:
        """Delete a session."""
        self._sessions.pop(session_id, None)


class GitHubDriver(ABC):
    """Abstract base class for GitHub API interactions.

    Implementations should handle OAuth token exchange and
    user information retrieval without performing network I/O
    during instantiation.
    """

    @abstractmethod
    async def exchange_code(self, code: str) -> dict[str, Any]:
        """Exchange an OAuth code for an access token.

        Args:
            code: The OAuth authorization code.

        Returns:
            Token response containing access_token and other metadata.
        """
        pass

    @abstractmethod
    async def get_user(self, access_token: str) -> dict[str, Any]:
        """Get the authenticated user's information.

        Args:
            access_token: The GitHub access token.

        Returns:
            User information from GitHub API.
        """
        pass

    def health_check(self) -> bool:
        """Check if the GitHub driver is healthy.

        Default implementation returns True. Override to add
        connectivity checks if needed.

        Returns:
            True if healthy, False otherwise.
        """
        return True


class PlaceholderGitHubDriver(GitHubDriver):
    """Placeholder GitHub driver implementation.

    This driver does not perform any network I/O and is used
    for bootstrapping and testing. It should be replaced with
    a real implementation that calls the GitHub API.
    """

    def __init__(self, client_id: str, client_secret: str, scopes: list[str]) -> None:
        """Initialize the placeholder GitHub driver.

        Args:
            client_id: GitHub OAuth App client ID.
            client_secret: GitHub OAuth App client secret.
            scopes: List of OAuth scopes to request.
        """
        self._client_id = client_id
        self._client_secret = client_secret
        self._scopes = scopes
        # Note: We don't log secrets, only acknowledge configuration
        logger.info(
            "Initialized placeholder GitHub driver",
            scopes=scopes,
            client_id_length=len(client_id),
        )

    async def exchange_code(self, code: str) -> dict[str, Any]:
        """Placeholder implementation - raises NotImplementedError."""
        raise NotImplementedError(
            "PlaceholderGitHubDriver does not support code exchange. "
            "Replace with a real implementation."
        )

    async def get_user(self, access_token: str) -> dict[str, Any]:
        """Placeholder implementation - raises NotImplementedError."""
        raise NotImplementedError(
            "PlaceholderGitHubDriver does not support user retrieval. "
            "Replace with a real implementation."
        )


class DependencyContainer:
    """Container for managing service dependencies.

    This class lazily instantiates dependencies without performing
    network I/O, ensuring fast startup and health checks.
    """

    def __init__(self, settings: Settings) -> None:
        """Initialize the dependency container.

        Args:
            settings: The service settings.
        """
        self._settings = settings
        self._session_store: SessionStore | None = None
        self._github_driver: GitHubDriver | None = None
        self._initialization_error: Exception | None = None

        # Attempt to initialize dependencies immediately to fail fast
        try:
            self._initialize()
        except Exception as e:
            self._initialization_error = e
            logger.error("Failed to initialize dependencies", error=str(e))

    def _initialize(self) -> None:
        """Initialize all dependencies.

        This method creates instances of all dependencies without
        performing network I/O.
        """
        # Initialize session store
        self._session_store = InMemorySessionStore()

        # Initialize GitHub driver
        self._github_driver = PlaceholderGitHubDriver(
            client_id=self._settings.github_client_id,
            client_secret=self._settings.github_client_secret,
            scopes=self._settings.oauth_scopes_list,
        )

        logger.info("Dependencies initialized successfully")

    @property
    def session_store(self) -> SessionStore:
        """Get the session store instance.

        Returns:
            The session store instance.

        Raises:
            RuntimeError: If initialization failed.
        """
        if self._initialization_error:
            raise RuntimeError(
                f"Dependencies failed to initialize: {self._initialization_error}"
            )
        if self._session_store is None:
            raise RuntimeError("Session store not initialized")
        return self._session_store

    @property
    def github_driver(self) -> GitHubDriver:
        """Get the GitHub driver instance.

        Returns:
            The GitHub driver instance.

        Raises:
            RuntimeError: If initialization failed.
        """
        if self._initialization_error:
            raise RuntimeError(
                f"Dependencies failed to initialize: {self._initialization_error}"
            )
        if self._github_driver is None:
            raise RuntimeError("GitHub driver not initialized")
        return self._github_driver

    def health_check(self) -> dict[str, Any]:
        """Check the health of all dependencies.

        Returns:
            A dictionary with health status for each dependency.
        """
        if self._initialization_error:
            return {
                "healthy": False,
                "error": str(self._initialization_error),
                "session_store": False,
                "github_driver": False,
            }

        session_healthy = (
            self._session_store.health_check() if self._session_store else False
        )
        github_healthy = (
            self._github_driver.health_check() if self._github_driver else False
        )

        return {
            "healthy": session_healthy and github_healthy,
            "session_store": session_healthy,
            "github_driver": github_healthy,
        }


# Global dependency container - initialized when get_dependencies is called
_container: DependencyContainer | None = None


def get_dependencies(settings: Settings) -> DependencyContainer:
    """Get or create the dependency container.

    This function is idempotent and will return the same container
    instance on subsequent calls.

    Args:
        settings: The service settings.

    Returns:
        The dependency container instance.
    """
    global _container
    if _container is None:
        _container = DependencyContainer(settings)
    return _container


def reset_dependencies() -> None:
    """Reset the dependency container.

    This function is primarily used for testing to allow
    re-initialization with different settings.
    """
    global _container
    _container = None
