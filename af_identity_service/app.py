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
"""FastAPI ASGI application factory for the Identity Service.

This module provides the main FastAPI application with:
- Request ID middleware for correlation
- Structlog context injection
- Health check endpoint
- Lifespan management for proper resource cleanup
- Uvicorn entrypoint
"""

import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from af_identity_service import __service_name__, __version__
from af_identity_service.config import ConfigurationError, Settings, get_settings
from af_identity_service.dependencies import (
    DependencyContainer,
    close_dependencies,
    get_dependencies,
)
from af_identity_service.logging import (
    configure_logging,
    get_logger,
    github_login_ctx,
    github_user_id_ctx,
    request_id_ctx,
    session_id_ctx,
    user_id_ctx,
)


class RequestIDMiddleware:
    """Middleware that generates and attaches request IDs.

    This middleware:
    1. Generates a UUID4 request ID for each incoming request
    2. Sets the request ID in the structlog context for downstream logging
    3. Adds the request ID to the response headers

    Implemented as a pure ASGI middleware to ensure context is preserved
    through exception handling (unlike BaseHTTPMiddleware which resets
    context in finally blocks before exception middleware logs errors).
    """

    def __init__(self, app: Any) -> None:
        """Initialize the middleware.

        Args:
            app: The ASGI application to wrap.
        """
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        """Process the request and attach request ID.

        Args:
            scope: The ASGI connection scope.
            receive: The receive callable.
            send: The send callable.
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Generate unique request ID
        request_id = str(uuid.uuid4())

        # Set context variables for structlog
        request_id_token = request_id_ctx.set(request_id)
        user_id_token = user_id_ctx.set(None)  # Will be set after authentication
        session_id_token = session_id_ctx.set(None)  # Will be set after authentication
        github_user_id_token = github_user_id_ctx.set(None)  # Will be set after authentication
        github_login_token = github_login_ctx.set(None)  # Will be set after authentication

        # Store request_id in scope for route handlers
        scope["state"] = scope.get("state", {})
        scope["state"]["request_id"] = request_id

        async def send_with_request_id(message: dict[str, Any]) -> None:
            """Wrapper to add request ID to response headers."""
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode()))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            # Reset context variables after the entire request/response cycle
            # including any exception handling by downstream middleware
            request_id_ctx.reset(request_id_token)
            user_id_ctx.reset(user_id_token)
            session_id_ctx.reset(session_id_token)
            github_user_id_ctx.reset(github_user_id_token)
            github_login_ctx.reset(github_login_token)


def create_health_router(container: DependencyContainer) -> Any:
    """Create a router with the health check endpoint.

    Args:
        container: The dependency container for health checks.

    Returns:
        A FastAPI APIRouter with the health endpoint.
    """
    from fastapi import APIRouter

    router = APIRouter()
    logger = get_logger(__name__)

    @router.get("/healthz")
    async def health_check() -> JSONResponse:
        """Health check endpoint.

        Returns a JSON response with service health status:
        - 200 OK: All dependencies are healthy or degraded (service is operational)
        - 503 Service Unavailable: Critical dependencies are unhealthy

        Response body:
        {
            "status": "healthy" | "degraded",
            "service": "af-identity-service",
            "version": "0.1.0",
            "backends": {...},  # Backend status (db, redis)
            "dependencies": {...}  # Only included when degraded
        }

        Note: Returns 200 for degraded status to allow load balancers to keep
        the instance in rotation while signaling reduced functionality.
        """
        try:
            # Check dependency health
            dep_health = container.health_check()

            # Check backend health with timeout
            backend_status = await container.health_check_backends(timeout_seconds=2.0)

            # Determine if backends are healthy
            backends_healthy = all(
                status in ("ok", "in_memory")
                for status in backend_status.values()
            )

            if dep_health["healthy"] and backends_healthy:
                logger.debug("Health check passed")
                return JSONResponse(
                    status_code=200,
                    content={
                        "status": "healthy",
                        "service": __service_name__,
                        "version": __version__,
                        "backends": backend_status,
                    },
                )
            else:
                # Return 200 with degraded status to keep instance in load balancer
                # rotation while signaling reduced functionality
                logger.warning(
                    "Health check degraded",
                    dependencies=dep_health,
                    backends=backend_status,
                )
                return JSONResponse(
                    status_code=200,
                    content={
                        "status": "degraded",
                        "service": __service_name__,
                        "version": __version__,
                        "backends": backend_status,
                        "dependencies": {
                            "session_store": dep_health.get("session_store", False),
                            "github_driver": dep_health.get("github_driver", False),
                        },
                    },
                )
        except Exception as e:
            # Critical failure - service cannot respond to health checks properly
            logger.error("Health check failed", error=str(e))
            return JSONResponse(
                status_code=503,
                content={
                    "status": "unhealthy",
                    "service": __service_name__,
                    "version": __version__,
                    "error": "Internal health check error",
                },
            )

    return router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager for the FastAPI application.

    Handles startup and shutdown events, including proper cleanup
    of Redis connections and other resources.

    Args:
        app: The FastAPI application instance.

    Yields:
        None
    """
    # Startup: nothing to do here, dependencies are lazily initialized
    logger = get_logger(__name__)
    logger.info("Application lifespan started")
    yield
    # Shutdown: close all dependencies
    logger.info("Application shutting down, closing dependencies...")
    await close_dependencies()
    logger.info("Application shutdown complete")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    This is the ASGI application factory. It:
    1. Validates configuration (fails fast if invalid)
    2. Configures structured logging
    3. Initializes dependencies
    4. Sets up middleware and lifespan management
    5. Mounts routers

    Args:
        settings: Optional settings instance. If not provided,
                  will be loaded from environment variables.

    Returns:
        The configured FastAPI application.

    Raises:
        ConfigurationError: If required configuration is missing.
    """
    # Load settings if not provided
    if settings is None:
        settings = get_settings()

    # Configure logging first
    configure_logging(settings)
    logger = get_logger(__name__)

    logger.info(
        "Starting Identity Service",
        version=__version__,
        environment=settings.identity_environment,
        log_level=settings.log_level,
        log_format=settings.log_format,
    )

    # Log configuration (with secrets redacted)
    logger.debug(
        "Configuration loaded",
        config=settings.get_redacted_config_dict(),
    )

    # Initialize dependencies (fails fast if misconfigured)
    container = get_dependencies(settings)

    # Verify dependencies initialized correctly
    dep_health = container.health_check()
    if not dep_health["healthy"]:
        logger.error("Dependencies failed to initialize", health=dep_health)
        raise ConfigurationError(
            f"Failed to initialize dependencies: {dep_health.get('error', 'Unknown error')}"
        )

    # Create FastAPI app with lifespan for proper shutdown handling
    app = FastAPI(
        title="Agent Foundry Identity Service",
        description="Authentication and authorization service for Agent Foundry",
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Add request ID middleware
    app.add_middleware(RequestIDMiddleware)

    # Mount health router
    health_router = create_health_router(container)
    app.include_router(health_router)

    # Mount auth GitHub router
    from af_identity_service.routes.auth_github import create_auth_github_router

    auth_github_router = create_auth_github_router(container.oauth_service)
    app.include_router(auth_github_router)

    # Mount token introspection router
    from af_identity_service.routes.token import create_token_router

    token_router = create_token_router(
        jwt_secret=container.settings.identity_jwt_secret,
        session_store=container.auth_session_store,
        user_repository=container.user_repository,
    )
    app.include_router(token_router)

    # Mount session management router
    from af_identity_service.routes.session import create_session_router

    session_router = create_session_router(
        jwt_secret=container.settings.identity_jwt_secret,
        session_store=container.auth_session_store,
        user_repository=container.user_repository,
    )
    app.include_router(session_router)

    # Mount GitHub token distribution router
    from af_identity_service.routes.github_token import create_github_token_router

    github_token_router = create_github_token_router(
        jwt_secret=container.settings.identity_jwt_secret,
        session_store=container.auth_session_store,
        user_repository=container.user_repository,
        github_token_service=container.github_token_service,
    )
    app.include_router(github_token_router)

    # Mount user profile router
    from af_identity_service.routes.me import create_me_router

    me_router = create_me_router(
        jwt_secret=container.settings.identity_jwt_secret,
        session_store=container.auth_session_store,
        user_repository=container.user_repository,
    )
    app.include_router(me_router)

    # Mount admin router (gated by ADMIN_TOOLS_ENABLED)
    from af_identity_service.routes.admin import create_admin_router

    admin_router = create_admin_router(
        jwt_secret=container.settings.identity_jwt_secret,
        session_store=container.auth_session_store,
        user_repository=container.user_repository,
        admin_enabled=container.settings.admin_tools_enabled,
    )
    app.include_router(admin_router)

    logger.info("Identity Service started successfully")

    return app


def main() -> None:
    """Uvicorn entrypoint for running the service.

    This function is called when running `af-identity` from the command line
    or `python -m af_identity_service.app`.
    """
    import uvicorn

    try:
        # Load settings to validate configuration before starting uvicorn
        settings = get_settings()

        uvicorn.run(
            "af_identity_service.app:create_app",
            factory=True,
            host=settings.service_host,
            port=settings.service_port,
            log_level=settings.log_level.lower(),
            reload=False,
        )
    except ConfigurationError as e:
        # Print configuration error and exit
        print(f"Configuration error: {e}")
        raise SystemExit(1) from e


if __name__ == "__main__":
    main()
