# SPDX-License-Identifier: GPL-3.0-only
"""Logging configuration with structlog for JSON-friendly Cloud Run compatible logging."""

import uuid
from contextvars import ContextVar
from typing import Any

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from af_identity_service import __service__

# Context variable for request-scoped data
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

# Header name for request ID propagation
REQUEST_ID_HEADER = "X-Request-ID"


def add_service_context(
    logger: Any, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Add service and request_id context to all log events."""
    event_dict["service"] = __service__
    request_id = request_id_var.get()
    if request_id:
        event_dict["request_id"] = request_id
    return event_dict


def configure_logging() -> None:
    """Configure structlog with JSON formatting suitable for Cloud Run.

    This sets up:
    - JSON rendering for all log output
    - Service name injection on all log entries
    - Request ID context propagation
    - Timestamp formatting
    - Exception formatting
    """
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            add_service_context,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a configured structlog logger.

    Args:
        name: Optional logger name. Defaults to module name.

    Returns:
        A bound structlog logger with service context.
    """
    return structlog.get_logger(name)


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Middleware that injects request IDs into the context.

    If an incoming request has an X-Request-ID header, that value is used.
    Otherwise, a new UUID is generated.

    The request ID is:
    - Stored in a context variable for structlog injection
    - Added to the response headers for tracing
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Process request and inject request ID."""
        # Get or generate request ID
        request_id = request.headers.get(REQUEST_ID_HEADER)
        if not request_id:
            request_id = str(uuid.uuid4())

        # Set context variable for logging
        token = request_id_var.set(request_id)

        try:
            response = await call_next(request)
            # Add request ID to response headers
            response.headers[REQUEST_ID_HEADER] = request_id
            return response
        finally:
            # Reset context variable
            request_id_var.reset(token)
