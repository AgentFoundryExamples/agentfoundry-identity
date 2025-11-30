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
from typing import TYPE_CHECKING, Any

from af_identity_service.config import Settings
from af_identity_service.logging import get_logger

if TYPE_CHECKING:
    from af_identity_service.github.driver import GitHubOAuthDriver
    from af_identity_service.services.github_tokens import GitHubTokenService
    from af_identity_service.services.oauth import OAuthService, StateStore
    from af_identity_service.stores.github_token_store import GitHubTokenStore
    from af_identity_service.stores.session_store import SessionStore as AuthSessionStore
    from af_identity_service.stores.user_store import AFUserRepository

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

    def __init__(self, client_id: str, scopes: list[str]) -> None:
        """Initialize the placeholder GitHub driver.

        Args:
            client_id: GitHub OAuth App client ID.
            scopes: List of OAuth scopes to request.
        """
        self._client_id = client_id
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

    This class lazily instantiates dependencies on first access,
    without performing network I/O, ensuring fast startup and health checks.

    The container respects the IDENTITY_ENVIRONMENT setting:
    - 'dev': Uses in-memory stub implementations (no external dependencies)
    - 'prod': Prepares for real backend implementations (Postgres, Redis)

    Note: Production implementations are not yet instantiated; this container
    provides factory methods and configuration validation for future work.
    """

    def __init__(self, settings: Settings) -> None:
        """Initialize the dependency container.

        Dependencies are NOT created here - they are lazily instantiated
        on first access to ensure fast startup and health checks.

        Args:
            settings: The service settings.
        """
        self._settings = settings
        self._session_store: SessionStore | None = None
        self._github_driver: GitHubDriver | None = None
        self._user_repository: "AFUserRepository | None" = None
        self._token_store: "GitHubTokenStore | None" = None
        self._state_store: "StateStore | None" = None
        self._oauth_service: "OAuthService | None" = None
        self._auth_session_store: "AuthSessionStore | None" = None  # Session-model based store
        self._github_token_service: "GitHubTokenService | None" = None
        self._stub_oauth_driver: "GitHubOAuthDriver | None" = None  # For GitHub token service
        self._initialized = False
        self._initialization_error: Exception | None = None
        logger.info(
            "Initializing dependency container",
            environment=settings.identity_environment,
        )

    @property
    def environment(self) -> str:
        """Get the current environment mode.

        Returns:
            The environment mode ('dev' or 'prod').
        """
        return self._settings.identity_environment

    @property
    def is_prod(self) -> bool:
        """Check if running in production mode.

        Returns:
            True if in production mode, False otherwise.
        """
        return self._settings.is_prod

    @property
    def is_dev(self) -> bool:
        """Check if running in development mode.

        Returns:
            True if in development mode, False otherwise.
        """
        return self._settings.is_dev

    def use_stub_session_store(self) -> bool:
        """Determine whether to use the stub session store.

        In dev mode, always returns True. In prod mode, returns False
        to indicate that a real session store (e.g., Redis) should be used.

        Returns:
            True if stub session store should be used, False otherwise.
        """
        return self.is_dev

    def use_stub_user_repository(self) -> bool:
        """Determine whether to use the stub user repository.

        In dev mode, always returns True. In prod mode, returns False
        to indicate that a real user repository (e.g., Postgres) should be used.

        Returns:
            True if stub user repository should be used, False otherwise.
        """
        return self.is_dev

    def use_stub_token_store(self) -> bool:
        """Determine whether to use the stub token store.

        In dev mode, always returns True. In prod mode, returns False
        to indicate that a real token store (e.g., Postgres) should be used.

        Returns:
            True if stub token store should be used, False otherwise.
        """
        return self.is_dev

    def use_stub_github_driver(self) -> bool:
        """Determine whether to use the stub GitHub OAuth driver.

        In dev mode, always returns True. In prod mode, returns False
        to indicate that a real GitHub OAuth driver should be used.

        Returns:
            True if stub GitHub driver should be used, False otherwise.
        """
        return self.is_dev

    def _create_postgres_engine(self):
        """Create a SQLAlchemy engine for Postgres.

        Creates a connection pool for Postgres using the configured
        credentials. The engine is cached on the container instance.

        Uses SQLAlchemy URL object to safely construct connection string
        without risk of credential exposure in logs or error messages.

        Returns:
            A SQLAlchemy Engine instance.

        Raises:
            ConfigurationError: If Postgres configuration is incomplete.
        """
        from sqlalchemy import create_engine
        from sqlalchemy.engine import URL

        if hasattr(self, "_postgres_engine"):
            return self._postgres_engine

        # Build connection URL using SQLAlchemy URL object to avoid
        # credential exposure through string interpolation
        password = (
            self._settings.postgres_password.get_secret_value()
            if self._settings.postgres_password
            else None
        )

        db_url = URL.create(
            drivername="postgresql+psycopg",
            username=self._settings.postgres_user,
            password=password,
            host=self._settings.postgres_host,
            port=self._settings.postgres_port,
            database=self._settings.postgres_db,
        )

        # Create engine with connection pool settings suitable for Cloud Run
        # - pool_size: Number of connections to keep open
        # - max_overflow: Additional connections allowed above pool_size
        # - pool_timeout: Seconds to wait for a connection from pool
        # - pool_recycle: Seconds before a connection is recycled
        engine = create_engine(
            db_url,
            pool_size=5,
            max_overflow=10,
            pool_timeout=30,
            pool_recycle=1800,  # 30 minutes
        )

        self._postgres_engine = engine
        logger.info(
            "Created Postgres engine",
            host=self._settings.postgres_host,
            port=self._settings.postgres_port,
            db=self._settings.postgres_db,
        )

        return engine

    def _ensure_initialized(self) -> None:
        """Lazily initialize all dependencies on first access.

        This method creates instances of all dependencies without
        performing network I/O. It is called automatically when
        accessing any dependency.

        In dev mode, uses in-memory stub implementations.
        In prod mode, currently uses stubs but logs a warning that
        real implementations are not yet available.
        """
        if self._initialized:
            return

        try:
            # Import here to avoid circular imports
            from af_identity_service.github.driver import StubGitHubOAuthDriver
            from af_identity_service.services.github_tokens import GitHubTokenService
            from af_identity_service.services.oauth import InMemoryStateStore, OAuthService
            from af_identity_service.stores.github_token_store import InMemoryGitHubTokenStore
            from af_identity_service.stores.session_store import (
                InMemorySessionStore as SessionStoreImpl,
            )
            from af_identity_service.stores.user_store import InMemoryUserRepository

            # Log the environment mode
            if self.is_prod:
                logger.info(
                    "Production mode enabled - using Postgres/Redis-backed stores",
                    environment=self.environment,
                )
            else:
                logger.info(
                    "Development mode - using in-memory stub implementations",
                    environment=self.environment,
                )

            # Initialize session store using the stores module implementation
            # This is a Session-model based store used by OAuth and other services
            if self.is_prod and self._settings.redis_host:
                from af_identity_service.stores.redis_session_store import RedisSessionStore

                session_store_impl = RedisSessionStore(
                    host=self._settings.redis_host,
                    port=self._settings.redis_port,
                    db=self._settings.redis_db,
                    tls_enabled=self._settings.redis_tls_enabled,
                )
            else:
                session_store_impl = SessionStoreImpl()
            self._auth_session_store = session_store_impl

            # Initialize the legacy session store (simple key-value) for backward compatibility
            self._session_store = InMemorySessionStore()

            # Initialize GitHub OAuth driver using stub driver for development
            # The stub driver provides fake responses without making real API calls
            # Note: In prod, this would be replaced with a real GitHub OAuth driver
            stub_oauth_driver = StubGitHubOAuthDriver(
                client_id=self._settings.github_client_id,
            )
            self._stub_oauth_driver = stub_oauth_driver

            # Initialize the legacy placeholder driver for backward compatibility
            # with the github_driver property (used by health checks)
            self._github_driver = PlaceholderGitHubDriver(
                client_id=self._settings.github_client_id,
                scopes=self._settings.oauth_scopes_list,
            )

            # Initialize user repository
            # In prod mode with Postgres, use PostgresUserRepository
            if self.is_prod and self._settings.postgres_host:
                from af_identity_service.stores.postgres_user_repository import (
                    PostgresUserRepository,
                )

                engine = self._create_postgres_engine()
                self._user_repository = PostgresUserRepository(engine)
            else:
                self._user_repository = InMemoryUserRepository()

            # Initialize token store
            # In prod mode with Postgres and encryption key, use PostgresGitHubTokenStore
            if (
                self.is_prod
                and self._settings.postgres_host
                and self._settings.github_token_enc_key
            ):
                from af_identity_service.security.crypto import get_token_encryptor
                from af_identity_service.stores.postgres_github_token_store import (
                    PostgresGitHubTokenStore,
                )

                # Get encryptor using the configured key
                encryptor = get_token_encryptor(
                    require_encryption=True,
                    env_var="GITHUB_TOKEN_ENC_KEY",
                )
                # Reuse the same engine for token store
                # (engine is cached by _create_postgres_engine)
                engine = self._create_postgres_engine()
                self._token_store = PostgresGitHubTokenStore(engine, encryptor)
            else:
                self._token_store = InMemoryGitHubTokenStore()

            # Initialize state store for OAuth CSRF protection
            self._state_store = InMemoryStateStore()

            # Initialize OAuth service with the stub OAuth driver
            self._oauth_service = OAuthService(
                github_driver=stub_oauth_driver,
                user_repository=self._user_repository,
                session_store=session_store_impl,
                token_store=self._token_store,
                state_store=self._state_store,
                client_id=self._settings.github_client_id,
                scopes=self._settings.oauth_scopes_list,
                jwt_secret=self._settings.identity_jwt_secret,
                jwt_expiry_seconds=self._settings.jwt_expiry_seconds,
                session_expiry_seconds=self._settings.session_expiry_seconds,
            )

            # Initialize GitHub token service
            self._github_token_service = GitHubTokenService(
                token_store=self._token_store,
                github_driver=stub_oauth_driver,
            )

            self._initialized = True
            logger.info(
                "Dependencies initialized successfully",
                environment=self.environment,
            )
        except Exception as e:
            self._initialization_error = e
            self._initialized = True  # Mark as initialized to avoid retrying
            logger.error("Failed to initialize dependencies", error=str(e))
            # In prod mode, fail fast instead of falling back silently
            if self.is_prod:
                raise

    @property
    def session_store(self) -> SessionStore:
        """Get the session store instance (lazily initialized).

        Returns:
            The session store instance.

        Raises:
            RuntimeError: If initialization failed.
        """
        self._ensure_initialized()
        if self._initialization_error:
            raise RuntimeError(
                f"Dependencies failed to initialize: {self._initialization_error}"
            )
        if self._session_store is None:
            raise RuntimeError("Session store not initialized")
        return self._session_store

    @property
    def github_driver(self) -> GitHubDriver:
        """Get the GitHub driver instance (lazily initialized).

        Returns:
            The GitHub driver instance.

        Raises:
            RuntimeError: If initialization failed.
        """
        self._ensure_initialized()
        if self._initialization_error:
            raise RuntimeError(
                f"Dependencies failed to initialize: {self._initialization_error}"
            )
        if self._github_driver is None:
            raise RuntimeError("GitHub driver not initialized")
        return self._github_driver

    @property
    def oauth_service(self) -> "OAuthService":
        """Get the OAuth service instance (lazily initialized).

        Returns:
            The OAuth service instance.

        Raises:
            RuntimeError: If initialization failed.
        """
        self._ensure_initialized()
        if self._initialization_error:
            raise RuntimeError(
                f"Dependencies failed to initialize: {self._initialization_error}"
            )
        if self._oauth_service is None:
            raise RuntimeError("OAuth service not initialized")
        return self._oauth_service

    @property
    def auth_session_store(self) -> "AuthSessionStore":
        """Get the Session-model based session store (lazily initialized).

        This is the store used for authentication and session management,
        which works with Session model instances.

        Returns:
            The session store instance.

        Raises:
            RuntimeError: If initialization failed.
        """
        self._ensure_initialized()
        if self._initialization_error:
            raise RuntimeError(
                f"Dependencies failed to initialize: {self._initialization_error}"
            )
        if self._auth_session_store is None:
            raise RuntimeError("Auth session store not initialized")
        return self._auth_session_store

    @property
    def user_repository(self) -> "AFUserRepository":
        """Get the user repository instance (lazily initialized).

        Returns:
            The user repository instance.

        Raises:
            RuntimeError: If initialization failed.
        """
        self._ensure_initialized()
        if self._initialization_error:
            raise RuntimeError(
                f"Dependencies failed to initialize: {self._initialization_error}"
            )
        if self._user_repository is None:
            raise RuntimeError("User repository not initialized")
        return self._user_repository

    @property
    def token_store(self) -> "GitHubTokenStore":
        """Get the GitHub token store instance (lazily initialized).

        Returns:
            The GitHub token store instance.

        Raises:
            RuntimeError: If initialization failed.
        """
        self._ensure_initialized()
        if self._initialization_error:
            raise RuntimeError(
                f"Dependencies failed to initialize: {self._initialization_error}"
            )
        if self._token_store is None:
            raise RuntimeError("Token store not initialized")
        return self._token_store

    @property
    def github_token_service(self) -> "GitHubTokenService":
        """Get the GitHub token service instance (lazily initialized).

        Returns:
            The GitHub token service instance.

        Raises:
            RuntimeError: If initialization failed.
        """
        self._ensure_initialized()
        if self._initialization_error:
            raise RuntimeError(
                f"Dependencies failed to initialize: {self._initialization_error}"
            )
        if self._github_token_service is None:
            raise RuntimeError("GitHub token service not initialized")
        return self._github_token_service

    @property
    def settings(self) -> Settings:
        """Get the service settings.

        Returns:
            The Settings instance.
        """
        return self._settings

    def health_check(self) -> dict[str, Any]:
        """Check the health of all dependencies.

        This triggers lazy initialization if not already done.

        Returns:
            A dictionary with health status for each dependency.
        """
        self._ensure_initialized()

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

    async def health_check_backends(
        self, timeout_seconds: float = 2.0
    ) -> dict[str, Any]:
        """Async health check for backend services (Postgres, Redis).

        This method performs lightweight ping checks on backend services
        with a timeout to avoid blocking when services are down.

        Args:
            timeout_seconds: Maximum time to wait for each backend check.

        Returns:
            A dictionary with backend health status:
            {
                "db": "ok" | "degraded" | "unavailable",
                "redis": "ok" | "degraded" | "unavailable",
            }
        """
        import asyncio

        result: dict[str, str] = {}

        # Check Postgres health
        if self.is_prod and self._settings.postgres_host:
            try:
                db_status = await asyncio.wait_for(
                    self._check_postgres_health(),
                    timeout=timeout_seconds,
                )
                result["db"] = db_status
            except asyncio.TimeoutError:
                logger.warning("Postgres health check timed out")
                result["db"] = "degraded"
            except Exception as e:
                logger.warning("Postgres health check failed", error=str(e))
                result["db"] = "unavailable"
        else:
            # In dev mode or when Postgres not configured, mark as in-memory
            result["db"] = "in_memory"

        # Check Redis health
        if self.is_prod and self._settings.redis_host:
            try:
                redis_status = await asyncio.wait_for(
                    self._check_redis_health(),
                    timeout=timeout_seconds,
                )
                result["redis"] = redis_status
            except asyncio.TimeoutError:
                logger.warning("Redis health check timed out")
                result["redis"] = "degraded"
            except Exception as e:
                logger.warning("Redis health check failed", error=str(e))
                result["redis"] = "unavailable"
        else:
            # In dev mode or when Redis not configured, mark as in-memory
            result["redis"] = "in_memory"

        return result

    async def _check_postgres_health(self) -> str:
        """Check Postgres connectivity with a lightweight query.

        Runs the synchronous database check in a separate thread to
        avoid blocking the event loop.

        Returns:
            "ok" if healthy, "degraded" if slow, "unavailable" if unreachable.
        """
        import asyncio

        from sqlalchemy import text

        if not hasattr(self, "_postgres_engine"):
            return "unavailable"

        def db_check() -> str:
            """Synchronous database health check."""
            try:
                with self._postgres_engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                return "ok"
            except Exception:
                # Don't log exception details to avoid information disclosure
                return "unavailable"

        try:
            return await asyncio.to_thread(db_check)
        except Exception:
            logger.debug("Postgres health check thread failed")
            return "unavailable"

    async def _check_redis_health(self) -> str:
        """Check Redis connectivity with a PING command.

        Returns:
            "ok" if healthy, "degraded" if slow, "unavailable" if unreachable.
        """
        from af_identity_service.stores.redis_session_store import RedisSessionStore

        # The RedisSessionStore handles connection internally
        if self._auth_session_store is None:
            return "unavailable"

        # Check if it's a RedisSessionStore using isinstance for proper type checking
        if not isinstance(self._auth_session_store, RedisSessionStore):
            return "in_memory"

        try:
            # Use the public health_check method instead of accessing private methods
            is_healthy = await self._auth_session_store.health_check()
            return "ok" if is_healthy else "unavailable"
        except Exception:
            # Don't log exception details to avoid information disclosure
            logger.debug("Redis health check failed")
            return "unavailable"

    async def close(self) -> None:
        """Close all dependencies that require cleanup.

        This should be called during application shutdown to properly
        release resources like Redis connections.
        """
        from af_identity_service.stores.redis_session_store import RedisSessionStore

        # Close Redis session store if it's a RedisSessionStore
        if self._auth_session_store is not None:
            # Use isinstance for proper type checking
            if isinstance(self._auth_session_store, RedisSessionStore):
                await self._auth_session_store.close()
                logger.info("Closed auth session store")


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


async def close_dependencies() -> None:
    """Close all dependencies that require cleanup.

    This function should be called during application shutdown to properly
    release resources like Redis connections.
    """
    global _container
    if _container is not None:
        await _container.close()


def reset_dependencies() -> None:
    """Reset the dependency container.

    This function is primarily used for testing to allow
    re-initialization with different settings.
    """
    global _container
    _container = None
