# SPDX-License-Identifier: GPL-3.0-only
"""FastAPI application factory with lifespan management and health endpoint."""

from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import FastAPI
from pydantic import ValidationError

from af_identity_service import __service__, __version__
from af_identity_service.config import Settings, get_settings
from af_identity_service.logging import (
    RequestIdMiddleware,
    configure_logging,
    get_logger,
)

# Initialize logger (will be configured in lifespan)
logger = get_logger(__name__)


class DriverFactory:
    """Factory for creating GitHub OAuth driver instances.

    This is a placeholder that simulates driver creation without
    making external calls, for health check verification.
    """

    def __init__(self, client_id: str, client_secret: str) -> None:
        """Initialize the driver factory.

        Args:
            client_id: GitHub OAuth client ID
            client_secret: GitHub OAuth client secret
        """
        self._client_id = client_id
        self._client_secret = client_secret
        self._initialized = True

    @property
    def is_ready(self) -> bool:
        """Check if the driver factory is ready."""
        return self._initialized and bool(self._client_id) and bool(self._client_secret)


class SessionStoreFactory:
    """Factory for creating session store instances.

    This is a placeholder that simulates session store creation
    without making external calls, for health check verification.
    """

    def __init__(self, jwt_secret: str) -> None:
        """Initialize the session store factory.

        Args:
            jwt_secret: Secret key for JWT token operations
        """
        self._jwt_secret = jwt_secret
        self._initialized = True

    @property
    def is_ready(self) -> bool:
        """Check if the session store factory is ready."""
        return self._initialized and bool(self._jwt_secret)


# Global factory instances (set during lifespan)
_driver_factory: DriverFactory | None = None
_session_store_factory: SessionStoreFactory | None = None


def _validate_settings_on_startup() -> Settings:
    """Validate settings on startup and raise clear errors if missing.

    Returns:
        Validated settings object.

    Raises:
        SystemExit: If required settings are missing or invalid.
    """
    try:
        return get_settings()
    except ValidationError as e:
        error_messages = []
        for error in e.errors():
            field = ".".join(str(loc) for loc in error["loc"])
            msg = error["msg"]
            error_messages.append(f"  - {field}: {msg}")

        error_detail = "\n".join(error_messages)
        logger.error(
            "configuration_validation_failed",
            errors=error_messages,
            message="Failed to load required configuration",
        )
        raise SystemExit(
            f"Configuration validation failed:\n{error_detail}\n\n"
            "Please ensure all required environment variables are set. "
            "See .env.example for the complete list."
        ) from e


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager.

    Initializes logging, validates configuration, and creates
    driver/session store factories on startup.
    """
    global _driver_factory, _session_store_factory

    # Configure structured logging
    configure_logging()

    logger.info("application_starting", service=__service__, version=__version__)

    # Validate configuration (will exit if invalid)
    settings = _validate_settings_on_startup()

    # Initialize factories (no external calls)
    _driver_factory = DriverFactory(
        client_id=settings.github_client_id,
        client_secret=settings.github_client_secret,
    )
    _session_store_factory = SessionStoreFactory(jwt_secret=settings.identity_jwt_secret)

    logger.info(
        "factories_initialized",
        driver_ready=_driver_factory.is_ready,
        session_store_ready=_session_store_factory.is_ready,
    )

    yield

    # Cleanup
    logger.info("application_shutdown", service=__service__)
    _driver_factory = None
    _session_store_factory = None


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application instance.
    """
    app = FastAPI(
        title="AF Identity Service",
        description="Agent Foundry Identity Service - Authentication and Authorization",
        version=__version__,
        lifespan=lifespan,
    )

    # Add request ID middleware
    app.add_middleware(RequestIdMiddleware)

    # Register routes
    @app.get("/healthz", tags=["Health"])
    async def healthz() -> dict[str, Any]:
        """Health check endpoint.

        Verifies that driver and session store factories can be created
        and are ready without making external system calls.

        Returns:
            Health status including service name and version.
        """
        driver_ok = _driver_factory is not None and _driver_factory.is_ready
        session_store_ok = (
            _session_store_factory is not None and _session_store_factory.is_ready
        )

        # Determine overall health status
        if driver_ok and session_store_ok:
            status = "healthy"
        else:
            status = "degraded"

        return {
            "status": status,
            "service": __service__,
            "version": __version__,
            "checks": {
                "driver_factory": "ok" if driver_ok else "error",
                "session_store_factory": "ok" if session_store_ok else "error",
            },
        }

    return app


# Create the application instance for uvicorn
app = create_app()
