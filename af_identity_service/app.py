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
- Uvicorn entrypoint
"""

import uuid
from typing import Any, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from af_identity_service import __service_name__, __version__
from af_identity_service.config import ConfigurationError, Settings, get_settings
from af_identity_service.dependencies import DependencyContainer, get_dependencies
from af_identity_service.logging import (
    configure_logging,
    get_logger,
    request_id_ctx,
    user_id_ctx,
)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware that generates and attaches request IDs.

    This middleware:
    1. Generates a UUID4 request ID for each incoming request
    2. Sets the request ID in the structlog context for downstream logging
    3. Adds the request ID to the response headers
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Any]
    ) -> Response:
        """Process the request and attach request ID.

        Args:
            request: The incoming HTTP request.
            call_next: The next middleware or route handler.

        Returns:
            The HTTP response with request ID header.
        """
        # Generate unique request ID
        request_id = str(uuid.uuid4())

        # Set context variables for structlog
        request_id_token = request_id_ctx.set(request_id)
        user_id_token = user_id_ctx.set(None)  # Will be set after authentication

        try:
            # Store request_id in request state for route handlers
            request.state.request_id = request_id

            # Process the request
            response = await call_next(request)

            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id

            return response
        finally:
            # Reset context variables
            request_id_ctx.reset(request_id_token)
            user_id_ctx.reset(user_id_token)


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
        - 200 OK: All dependencies are healthy
        - 503 Service Unavailable: One or more dependencies are unhealthy

        Response body:
        {
            "status": "healthy" | "degraded",
            "service": "af-identity-service",
            "version": "0.1.0",
            "dependencies": {...}  # Only included when degraded
        }
        """
        try:
            # Check dependency health
            dep_health = container.health_check()

            if dep_health["healthy"]:
                logger.debug("Health check passed")
                return JSONResponse(
                    status_code=200,
                    content={
                        "status": "healthy",
                        "service": __service_name__,
                        "version": __version__,
                    },
                )
            else:
                logger.warning("Health check degraded", dependencies=dep_health)
                return JSONResponse(
                    status_code=503,
                    content={
                        "status": "degraded",
                        "service": __service_name__,
                        "version": __version__,
                        "dependencies": {
                            "session_store": dep_health.get("session_store", False),
                            "github_driver": dep_health.get("github_driver", False),
                        },
                    },
                )
        except Exception as e:
            logger.error("Health check failed", error=str(e))
            return JSONResponse(
                status_code=503,
                content={
                    "status": "degraded",
                    "service": __service_name__,
                    "version": __version__,
                    "error": "Internal health check error",
                },
            )

    return router


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    This is the ASGI application factory. It:
    1. Validates configuration (fails fast if invalid)
    2. Configures structured logging
    3. Initializes dependencies
    4. Sets up middleware
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
        log_level=settings.log_level,
        log_format=settings.log_format,
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

    # Create FastAPI app
    app = FastAPI(
        title="Agent Foundry Identity Service",
        description="Authentication and authorization service for Agent Foundry",
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Add request ID middleware
    app.add_middleware(RequestIDMiddleware)

    # Mount health router
    health_router = create_health_router(container)
    app.include_router(health_router)

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
